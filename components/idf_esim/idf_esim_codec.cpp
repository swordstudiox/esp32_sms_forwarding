#include "idf_esim_codec.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <limits>
#include <utility>

namespace idf_esim_internal {
namespace {

static std::string trim_ascii_copy(const std::string& value)
{
    size_t begin = 0;
    while (begin < value.size() && isspace(static_cast<unsigned char>(value[begin]))) ++begin;
    size_t end = value.size();
    while (end > begin && isspace(static_cast<unsigned char>(value[end - 1]))) --end;
    return value.substr(begin, end - begin);
}

static bool parse_decimal(const std::string& value, size_t& out)
{
    std::string text = trim_ascii_copy(value);
    if (text.empty()) return false;
    size_t parsed = 0;
    for (char ch : text) {
        if (!isdigit(static_cast<unsigned char>(ch))) return false;
        unsigned digit = static_cast<unsigned>(ch - '0');
        if (parsed > (std::numeric_limits<size_t>::max() - digit) / 10U) return false;
        parsed = parsed * 10U + digit;
    }
    out = parsed;
    return true;
}

static bool parse_tlv_one(const std::vector<uint8_t>& data,
                          size_t end,
                          size_t& pos,
                          Tlv& out,
                          std::string& message,
                          int depth)
{
    // 小响应允许有限嵌套；BPP 后续使用独立增量 parser，不走这里。
    if (depth > 8) {
        message = "TLV 嵌套过深";
        return false;
    }
    TlvSpan span;
    if (!parse_tlv_span(data, end, pos, span, message)) return false;
    out = Tlv();
    out.constructed = (data[span.offset] & 0x20U) != 0U;
    out.tag.assign(data.begin() + span.offset,
                   data.begin() + span.offset + span.tagLength);
    out.value.assign(data.begin() + span.valueOffset,
                     data.begin() + span.valueOffset + span.valueLength);
    if (out.constructed) {
        size_t child_pos = span.valueOffset;
        size_t child_end = span.valueOffset + span.valueLength;
        while (child_pos < child_end) {
            Tlv child;
            if (!parse_tlv_one(data, child_end, child_pos, child, message, depth + 1)) return false;
            out.children.push_back(std::move(child));
        }
    }
    return true;
}

static void append_len(std::vector<uint8_t>& out, size_t len)
{
    if (len < 0x80U) {
        out.push_back(static_cast<uint8_t>(len));
    } else if (len <= 0xFFU) {
        out.push_back(0x81);
        out.push_back(static_cast<uint8_t>(len));
    } else {
        out.push_back(0x82);
        out.push_back(static_cast<uint8_t>((len >> 8U) & 0xFFU));
        out.push_back(static_cast<uint8_t>(len & 0xFFU));
    }
}

static bool find_unique_prefixed_line(const std::string& response,
                                      const char* prefix,
                                      std::string& line)
{
    line.clear();
    bool found = false;
    size_t pos = 0;
    while (pos <= response.size()) {
        size_t end = response.find('\n', pos);
        if (end == std::string::npos) end = response.size();
        std::string row = trim_ascii_copy(response.substr(pos, end - pos));
        if (row.rfind(prefix, 0) == 0) {
            if (found) return false;
            line = std::move(row);
            found = true;
        }
        if (end == response.size()) break;
        pos = end + 1U;
    }
    return found;
}

static bool contains_standalone_error_line(const std::string& response)
{
    size_t pos = 0;
    while (pos <= response.size()) {
        size_t end = response.find('\n', pos);
        if (end == std::string::npos) end = response.size();
        std::string row = trim_ascii_copy(response.substr(pos, end - pos));
        if (row == "ERROR" || row.rfind("+CMS ERROR", 0) == 0 ||
            row.rfind("+CME ERROR", 0) == 0) {
            return true;
        }
        if (end == response.size()) break;
        pos = end + 1U;
    }
    return false;
}

static std::string version_text(const std::vector<uint8_t>& value)
{
    if (value.size() != 3U) return {};
    char buf[24];
    snprintf(buf, sizeof(buf), "%u.%u.%u",
             static_cast<unsigned>(value[0]),
             static_cast<unsigned>(value[1]),
             static_cast<unsigned>(value[2]));
    return std::string(buf);
}

static bool parse_ext_card_resource(const std::vector<uint8_t>& value,
                                    uint32_t& free_non_volatile,
                                    uint32_t& free_volatile,
                                    std::string& message)
{
    std::vector<Tlv> fields;
    if (!parse_tlv_list(value, fields, message)) {
        message = "扩展卡资源格式无效: " + message;
        return false;
    }
    bool non_volatile_found = false;
    bool volatile_found = false;
    for (const Tlv& field : fields) {
        if (field.tag.size() != 1U) continue;
        uint8_t tag = field.tag[0];
        if (tag != 0x82 && tag != 0x83) continue;
        if (field.value.empty() || field.value.size() > 4U) {
            message = "扩展卡资源内存字段长度无效";
            return false;
        }
        uint32_t parsed = 0;
        for (uint8_t byte : field.value) parsed = (parsed << 8U) | byte;
        if (tag == 0x82) {
            if (non_volatile_found) {
                message = "扩展卡资源重复返回非易失内存";
                return false;
            }
            free_non_volatile = parsed;
            non_volatile_found = true;
        } else {
            if (volatile_found) {
                message = "扩展卡资源重复返回易失内存";
                return false;
            }
            free_volatile = parsed;
            volatile_found = true;
        }
    }
    if (!non_volatile_found || !volatile_found) {
        message = "扩展卡资源缺少可用内存字段";
        return false;
    }
    return true;
}

static bool bit_string_value(const std::vector<uint8_t>& value, size_t bit_index, bool& out)
{
    if (value.empty()) return false;
    uint8_t unused = value[0];
    if (unused > 7U) return false;
    size_t bit_count = (value.size() - 1U) * 8U;
    if (unused > bit_count) return false;
    if (unused != 0U && (value.back() & static_cast<uint8_t>((1U << unused) - 1U)) != 0U) return false;
    bit_count -= unused;
    if (bit_index >= bit_count) {
        out = false;
        return true;
    }
    uint8_t byte = value[1U + bit_index / 8U];
    out = (byte & static_cast<uint8_t>(0x80U >> (bit_index % 8U))) != 0;
    return true;
}

}  // namespace

bool tag_is(const Tlv& tlv, const uint8_t* tag, size_t len)
{
    return tlv.tag.size() == len && memcmp(tlv.tag.data(), tag, len) == 0;
}

bool tag_is(const std::vector<uint8_t>& data,
            const TlvSpan& tlv,
            const uint8_t* tag,
            size_t len)
{
    return tag && tlv.tagLength == len && tlv.offset + len <= data.size() &&
           memcmp(data.data() + tlv.offset, tag, len) == 0;
}

bool parse_tlv_span(const std::vector<uint8_t>& data,
                    size_t end,
                    size_t& pos,
                    TlvSpan& out,
                    std::string& message)
{
    if (end > data.size() || pos >= end) {
        message = "TLV 数据为空";
        return false;
    }

    const size_t tag_start = pos;
    const uint8_t first = data[pos++];
    if ((first & 0x1FU) == 0x1FU) {
        bool tag_complete = false;
        while (pos < end) {
            if ((data[pos++] & 0x80U) == 0U) {
                tag_complete = true;
                break;
            }
        }
        if (!tag_complete) {
            message = "TLV tag 不完整";
            return false;
        }
    }
    const size_t tag_length = pos - tag_start;
    if (pos >= end) {
        message = "TLV length 缺失";
        return false;
    }

    const uint8_t len0 = data[pos++];
    size_t length = 0;
    if ((len0 & 0x80U) == 0U) {
        length = len0;
    } else {
        const size_t count = len0 & 0x7FU;
        if (count == 0U || count > 3U || count > end - pos) {
            message = "TLV length 格式不支持";
            return false;
        }
        for (size_t i = 0; i < count; ++i) length = (length << 8U) | data[pos++];
    }
    if (length > end - pos) {
        message = "TLV length 超出响应";
        return false;
    }

    out.offset = tag_start;
    out.tagLength = tag_length;
    out.valueOffset = pos;
    out.valueLength = length;
    pos += length;
    return true;
}

bool parse_tlv_at(const std::vector<uint8_t>& data,
                  size_t end,
                  size_t& pos,
                  Tlv& out,
                  std::string& message)
{
    return parse_tlv_one(data, end, pos, out, message, 0);
}

bool parse_tlv(const std::vector<uint8_t>& data, Tlv& out, std::string& message)
{
    size_t pos = 0;
    if (!parse_tlv_at(data, data.size(), pos, out, message)) return false;
    if (pos != data.size()) {
        message = "TLV 响应含有多余数据";
        return false;
    }
    return true;
}

bool parse_tlv_list(const std::vector<uint8_t>& data, std::vector<Tlv>& out, std::string& message)
{
    out.clear();
    size_t pos = 0;
    while (pos < data.size()) {
        Tlv item;
        if (!parse_tlv_one(data, data.size(), pos, item, message, 0)) return false;
        out.push_back(std::move(item));
    }
    return true;
}

void append_tlv(std::vector<uint8_t>& out,
                const uint8_t* tag,
                size_t tag_len,
                const std::vector<uint8_t>& value)
{
    if (tag_len == 0 || !tag) return;
    out.insert(out.end(), tag, tag + tag_len);
    append_len(out, value.size());
    out.insert(out.end(), value.begin(), value.end());
}

CsimParseResult parse_terminal_capability_csim(const std::string& response,
                                               uint16_t& sw,
                                               std::string& message)
{
    sw = 0;
    std::string line;
    if (!find_unique_prefixed_line(response, "+CSIM:", line)) {
        message = "模组未返回唯一的 +CSIM 数据行";
        return CsimParseResult::malformed;
    }
    size_t colon = line.find(':');
    size_t comma = line.find(',', colon == std::string::npos ? 0 : colon + 1U);
    if (colon == std::string::npos || comma == std::string::npos) {
        message = "+CSIM 响应缺少长度或数据字段";
        return CsimParseResult::malformed;
    }
    size_t declared_length = 0;
    if (!parse_decimal(line.substr(colon + 1U, comma - colon - 1U), declared_length)) {
        message = "+CSIM 响应长度字段无效";
        return CsimParseResult::malformed;
    }
    size_t q1 = line.find('"', comma + 1U);
    if (q1 == std::string::npos || !trim_ascii_copy(line.substr(comma + 1U, q1 - comma - 1U)).empty()) {
        message = "+CSIM 响应数据缺少引号";
        return CsimParseResult::malformed;
    }
    size_t q2 = line.find('"', q1 + 1U);
    if (q2 == std::string::npos || !trim_ascii_copy(line.substr(q2 + 1U)).empty()) {
        message = "+CSIM 响应引号或尾部数据无效";
        return CsimParseResult::malformed;
    }
    std::string hex = line.substr(q1 + 1U, q2 - q1 - 1U);
    if (declared_length != hex.size()) {
        message = "+CSIM 声明长度与 HEX 数据不一致";
        return CsimParseResult::malformed;
    }
    if (hex.size() < 4U || (hex.size() % 2U) != 0) {
        message = "+CSIM 数据不是含状态字的合法 HEX";
        return CsimParseResult::malformed;
    }
    uint8_t sw_bytes[2] = {};
    for (size_t i = 0; i < hex.size(); ++i) {
        int nibble = -1;
        char ch = hex[i];
        if (ch >= '0' && ch <= '9') nibble = ch - '0';
        else if (ch >= 'a' && ch <= 'f') nibble = ch - 'a' + 10;
        else if (ch >= 'A' && ch <= 'F') nibble = ch - 'A' + 10;
        if (nibble < 0) {
            message = "+CSIM 数据不是含状态字的合法 HEX";
            return CsimParseResult::malformed;
        }
        if (i >= hex.size() - 4U) {
            size_t byte_index = (i - (hex.size() - 4U)) / 2U;
            sw_bytes[byte_index] = static_cast<uint8_t>((sw_bytes[byte_index] << 4U) | nibble);
        }
    }
    sw = static_cast<uint16_t>((sw_bytes[0] << 8U) | sw_bytes[1]);
    if (sw != 0x9000) {
        char buf[64];
        snprintf(buf, sizeof(buf), "Terminal Capability 被卡拒绝（SW=%04X）",
                 static_cast<unsigned>(sw));
        message = buf;
        return CsimParseResult::status_error;
    }
    if (contains_standalone_error_line(response)) {
        message = "Terminal Capability 响应同时包含 AT 错误终结码";
        return CsimParseResult::malformed;
    }
    message = "Terminal Capability 已声明";
    return CsimParseResult::success;
}

bool parse_euicc_info1(const std::vector<uint8_t>& data,
                       EuiccInfo1Fields& out,
                       std::string& message)
{
    static constexpr uint8_t TAG_INFO1[] = {0xBF, 0x20};
    static constexpr uint8_t TAG_SVN[] = {0x82};
    static constexpr uint8_t TAG_VERIFY_KEYS[] = {0xA9};
    static constexpr uint8_t TAG_SIGN_KEYS[] = {0xAA};
    out = EuiccInfo1Fields();
    Tlv root;
    if (!parse_tlv(data, root, message)) return false;
    if (!tag_is(root, TAG_INFO1)) {
        message = "EUICCInfo1 响应 tag 不匹配";
        return false;
    }
    const Tlv* svn = first_child(root, TAG_SVN);
    if (!svn || (out.svn = version_text(svn->value)).empty()) {
        message = "EUICCInfo1 缺少合法 SVN";
        return false;
    }
    if (!first_child(root, TAG_VERIFY_KEYS) || !first_child(root, TAG_SIGN_KEYS)) {
        message = "EUICCInfo1 缺少 CI 公钥标识列表";
        return false;
    }
    return true;
}

bool parse_euicc_info2(const std::vector<uint8_t>& data,
                       EuiccInfo2Fields& out,
                       std::string& message)
{
    static constexpr uint8_t TAG_INFO2[] = {0xBF, 0x22};
    static constexpr uint8_t TAG_PROFILE_VERSION[] = {0x81};
    static constexpr uint8_t TAG_SVN[] = {0x82};
    static constexpr uint8_t TAG_FIRMWARE_VERSION[] = {0x83};
    static constexpr uint8_t TAG_EXT_CARD_RESOURCE[] = {0x84};
    static constexpr uint8_t TAG_RSP_CAPABILITY[] = {0x88};

    out = EuiccInfo2Fields();
    Tlv root;
    if (!parse_tlv(data, root, message)) return false;
    if (!tag_is(root, TAG_INFO2)) {
        message = "EUICCInfo2 响应 tag 不匹配";
        return false;
    }
    const Tlv* profile_version = first_child(root, TAG_PROFILE_VERSION);
    const Tlv* svn = first_child(root, TAG_SVN);
    const Tlv* firmware = first_child(root, TAG_FIRMWARE_VERSION);
    const Tlv* ext_resource = first_child(root, TAG_EXT_CARD_RESOURCE);
    const Tlv* rsp_capability = first_child(root, TAG_RSP_CAPABILITY);
    if (!profile_version || (out.profileVersion = version_text(profile_version->value)).empty()) {
        message = "EUICCInfo2 缺少合法 Profile Package 版本";
        return false;
    }
    if (!svn || (out.svn = version_text(svn->value)).empty()) {
        message = "EUICCInfo2 缺少合法 SVN";
        return false;
    }
    if (!firmware || (out.firmwareVersion = version_text(firmware->value)).empty()) {
        message = "EUICCInfo2 缺少合法固件版本";
        return false;
    }
    if (!ext_resource) {
        message = "EUICCInfo2 缺少扩展卡资源";
        return false;
    }
    if (!parse_ext_card_resource(ext_resource->value,
                                 out.freeNonVolatileMemory,
                                 out.freeVolatileMemory,
                                 message)) {
        return false;
    }
    if (!rsp_capability ||
        !bit_string_value(rsp_capability->value, 0, out.additionalProfile) ||
        !bit_string_value(rsp_capability->value, 3, out.testProfileSupport)) {
        message = "EUICCInfo2 缺少合法 RSP capability";
        return false;
    }
    return true;
}

bool parse_euicc_challenge(const std::vector<uint8_t>& data,
                           uint8_t out[16],
                           std::string& message)
{
    static constexpr uint8_t TAG_CHALLENGE_RESPONSE[] = {0xBF, 0x2E};
    static constexpr uint8_t TAG_CHALLENGE[] = {0x80};
    Tlv root;
    if (!parse_tlv(data, root, message)) return false;
    if (!tag_is(root, TAG_CHALLENGE_RESPONSE)) {
        message = "eUICC challenge 响应 tag 不匹配";
        return false;
    }
    const Tlv* challenge = nullptr;
    for (const Tlv& child : root.children) {
        if (tag_is(child, TAG_CHALLENGE)) {
            if (challenge) {
                message = "eUICC challenge 响应重复返回 challenge";
                return false;
            }
            challenge = &child;
        }
    }
    if (!challenge || challenge->value.size() != 16U) {
        message = "eUICC challenge 长度必须为 16 字节";
        return false;
    }
    memcpy(out, challenge->value.data(), 16U);
    return true;
}

}  // namespace idf_esim_internal
