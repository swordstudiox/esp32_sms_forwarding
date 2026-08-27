#include "idf_esim.h"
#include "idf_esim_codec.h"
#include "idf_esim_lpa.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <ctype.h>
#include <memory>
#include <new>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <utility>

#include "esp_err.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "idf_log.h"
#include "idf_modem.h"
#include "idf_util.h"

namespace {

static constexpr const char* ISDR_AID_HEX = "A0000005591010FFFFFFFF8900000100";
// lpac 默认单块 120 字节：240 个 HEX 字符加框架不会超过常见模组的 AT 行长限制。
static constexpr size_t STORE_DATA_MSS = 120;
// 兼容会返回大量短 61xx 分段的 eUICC；同时保留总字节和无进展保护，避免异常卡片
// 让后台任务无限占用 AT 通道。
static constexpr size_t APDU_RESPONSE_DATA_MAX = 32 * 1024;
static constexpr size_t GET_RESPONSE_CHAIN_MAX = 256;
static constexpr size_t GET_RESPONSE_NO_PROGRESS_MAX = 4;

using idf_esim_internal::Tlv;
using idf_esim_internal::append_tlv;
using idf_esim_internal::first_child;
using idf_esim_internal::parse_tlv;
using idf_esim_internal::tag_is;

struct ProfileIdentifier {
    std::vector<uint8_t> tag;
    std::vector<uint8_t> value;
    std::string display;
};

static std::string lower_ascii(std::string value)
{
    for (char& ch : value) ch = static_cast<char>(tolower(static_cast<unsigned char>(ch)));
    return value;
}

static bool equals_relaxed(const std::string& a, const std::string& b)
{
    return lower_ascii(idf_util_trim_copy(a)) == lower_ascii(idf_util_trim_copy(b));
}

static int hex_value(char ch)
{
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    return -1;
}

static bool is_hex_string(const std::string& value)
{
    if (value.empty() || (value.size() % 2) != 0) return false;
    for (char ch : value) {
        if (hex_value(ch) < 0) return false;
    }
    return true;
}

static bool hex_to_bytes(const std::string& hex, std::vector<uint8_t>& out)
{
    if (!is_hex_string(hex)) return false;
    out.clear();
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        out.push_back(static_cast<uint8_t>((hex_value(hex[i]) << 4) | hex_value(hex[i + 1])));
    }
    return true;
}

static std::string bytes_to_hex(const uint8_t* data, size_t len)
{
    static constexpr char kHex[] = "0123456789ABCDEF";
    std::string out;
    out.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        out.push_back(kHex[(data[i] >> 4) & 0x0F]);
        out.push_back(kHex[data[i] & 0x0F]);
    }
    return out;
}

static std::string bytes_to_hex(const std::vector<uint8_t>& data)
{
    return bytes_to_hex(data.data(), data.size());
}

static bool all_digits(const std::string& value)
{
    if (value.empty()) return false;
    for (char ch : value) {
        if (!isdigit(static_cast<unsigned char>(ch))) return false;
    }
    return true;
}

static bool parse_positive_int_token(const std::string& value, int& out)
{
    // all_digits 先拒绝空串/符号/非数字(strtol 本身太宽松)，纯数字串必被整体消费
    std::string text = idf_util_trim_copy(value);
    if (!all_digits(text)) return false;
    long parsed = strtol(text.c_str(), nullptr, 10);
    if (parsed <= 0 || parsed > 999) return false;
    out = static_cast<int>(parsed);
    return true;
}

static std::string compact_digits(const std::string& value)
{
    std::string out;
    out.reserve(value.size());
    for (char ch : value) {
        if (isdigit(static_cast<unsigned char>(ch))) out.push_back(ch);
    }
    return out;
}

static std::string gsm_bcd_decode(const std::vector<uint8_t>& value)
{
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(value.size() * 2);
    for (uint8_t b : value) {
        uint8_t lo = b & 0x0F;
        uint8_t hi = (b >> 4) & 0x0F;
        if (lo != 0x0F) out.push_back(kHex[lo]);
        if (hi != 0x0F) out.push_back(kHex[hi]);
    }
    return out;
}

static bool gsm_bcd_encode(const std::string& digits, std::vector<uint8_t>& out)
{
    if (!all_digits(digits)) return false;
    out.clear();
    out.reserve((digits.size() + 1) / 2);
    for (size_t i = 0; i < digits.size(); i += 2) {
        uint8_t lo = static_cast<uint8_t>(digits[i] - '0');
        uint8_t hi = (i + 1 < digits.size()) ? static_cast<uint8_t>(digits[i + 1] - '0') : 0x0F;
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    // SGP.22 中 ICCID(tag 5A) 固定 10 字节，不足时按 lpac 约定补 0xFF。
    while (out.size() < 10) out.push_back(0xFF);
    return true;
}

static std::string eid_decode(const std::vector<uint8_t>& value)
{
    std::string out;
    out.reserve(value.size() * 2);
    for (uint8_t b : value) {
        uint8_t hi = (b >> 4) & 0x0F;
        uint8_t lo = b & 0x0F;
        if (hi > 9 || lo > 9) return bytes_to_hex(value);
        out.push_back(static_cast<char>('0' + hi));
        out.push_back(static_cast<char>('0' + lo));
    }
    return out;
}

static int tlv_int_value(const Tlv& tlv, int def = 0)
{
    if (tlv.value.empty()) return def;
    // 卡片可控数据：仅取尾部 4 字节，防止超长 TLV 左移出符号位(有符号溢出为 UB)
    uint32_t out = 0;
    size_t start = tlv.value.size() > 4 ? tlv.value.size() - 4 : 0;
    for (size_t i = start; i < tlv.value.size(); ++i) out = (out << 8) | tlv.value[i];
    return static_cast<int>(out);
}

static std::string status_word_text(uint16_t sw)
{
    char buf[96];
    switch (sw) {
        case 0x9000: return "OK";
        case 0x6A82: return "未找到 eUICC 应用或 Profile";
        case 0x6985: return "卡策略拒绝当前操作";
        case 0x6A86: return "APDU 参数不被卡接受";
        case 0x6D00: return "eUICC 不支持该 APDU 指令";
        case 0x6E00: return "APDU 逻辑通道 CLA 不被接受";
        default:
            snprintf(buf, sizeof(buf), "APDU 状态字 %04X", static_cast<unsigned>(sw));
            return buf;
    }
}

static std::string first_line_containing(const std::string& resp, const char* needle)
{
    size_t p = resp.find(needle);
    if (p == std::string::npos) return {};
    size_t start = resp.rfind('\n', p);
    start = (start == std::string::npos) ? 0 : start + 1;
    size_t end = resp.find('\n', p);
    if (end == std::string::npos) end = resp.size();
    std::string line = resp.substr(start, end - start);
    while (!line.empty() && (line.back() == '\r' || line.back() == '\n')) line.pop_back();
    return idf_util_trim_copy(line);
}

static bool parse_quoted_hex_response(const std::string& resp,
                                      const char* prefix,
                                      std::vector<uint8_t>& out,
                                      std::string& message)
{
    std::string line = first_line_containing(resp, prefix);
    if (line.empty()) {
        message = "模组未返回 APDU 数据";
        return false;
    }
    std::string hex;
    size_t q1 = line.find('"');
    size_t q2 = (q1 == std::string::npos) ? std::string::npos : line.find('"', q1 + 1);
    if (q1 != std::string::npos && q2 != std::string::npos && q2 > q1 + 1) {
        hex = line.substr(q1 + 1, q2 - q1 - 1);
    } else {
        size_t comma = line.find(',');
        if (comma != std::string::npos) hex = idf_util_trim_copy(line.substr(comma + 1));
        if (!hex.empty() && hex.front() == '"') hex.erase(0, 1);
        if (!hex.empty() && hex.back() == '"') hex.pop_back();
    }
    if (hex.empty()) {
        message = "模组 APDU 响应格式无法解析";
        return false;
    }
    if (!hex_to_bytes(hex, out)) {
        message = "模组 APDU 响应不是合法 HEX";
        return false;
    }
    return true;
}

static bool parse_ccho_channel(const std::string& resp, int& channel)
{
    std::string line = first_line_containing(resp, "+CCHO:");
    if (!line.empty()) {
        const char* p = strchr(line.c_str(), ':');
        if (!p) return false;
        return parse_positive_int_token(p + 1, channel);
    }

    // 有些模组只返回裸数字；跳过 echo/OK/空行。
    size_t pos = 0;
    while (pos < resp.size()) {
        size_t end = resp.find('\n', pos);
        if (end == std::string::npos) end = resp.size();
        std::string row = idf_util_trim_copy(resp.substr(pos, end - pos));
        if (!row.empty() && row != "OK" && row.rfind("AT+", 0) != 0) {
            if (parse_positive_int_token(row, channel)) return true;
        }
        pos = end + 1;
    }
    return false;
}

static uint8_t class_byte_for_channel(uint8_t cla, int channel)
{
    if (channel < 4) return static_cast<uint8_t>((cla & 0x9C) | channel);
    return static_cast<uint8_t>((cla & 0xB0) | 0x40 | (channel - 4));
}

static uint16_t response_sw(const std::vector<uint8_t>& resp)
{
    if (resp.size() < 2) return 0;
    return static_cast<uint16_t>((resp[resp.size() - 2] << 8) | resp[resp.size() - 1]);
}

static constexpr bool response_sw_ok(uint16_t sw) { return sw == 0x9000 || (sw >> 8) == 0x91; }
static_assert(response_sw_ok(0x9000) && response_sw_ok(0x9108) && !response_sw_ok(0x9300));

static esp_err_t declare_terminal_capability(std::string& message)
{
    static constexpr const char* TERMINAL_CAPABILITY_CMD =
        "AT+CSIM=20,\"80AA000005A903830107\"";
    std::string response;
    // modem 层 API 会把 AT 成功但卡拒绝的 +CSIM 响应作为 ESP_FAIL 返回；
    // 只要存在 +CSIM 数据行，仍交给严格 parser 区分 malformed 与非 9000 SW。
    esp_err_t err = idf_modem_send_at(TERMINAL_CAPABILITY_CMD, 10000, response);
    bool has_csim_line = response.find("+CSIM:") != std::string::npos;
    if (err != ESP_OK && !has_csim_line) {
        message = "Terminal Capability AT 传输失败: ";
        message += esp_err_to_name(err);
        return err;
    }
    uint16_t sw = 0;
    idf_esim_internal::CsimParseResult result =
        idf_esim_internal::parse_terminal_capability_csim(response, sw, message);
    if (result == idf_esim_internal::CsimParseResult::success) return ESP_OK;
    return result == idf_esim_internal::CsimParseResult::status_error ? ESP_ERR_NOT_SUPPORTED : ESP_FAIL;
}

class EsimApduSession {
public:
    explicit EsimApduSession(bool terminal_capability_required = false)
        : m_terminal_capability_required(terminal_capability_required)
    {
    }

    esp_err_t open(std::string& message)
    {
        if (m_open) return ESP_OK;
        if (m_terminal_capability_required) {
            esp_err_t capability_err = declare_terminal_capability(message);
            if (capability_err != ESP_OK) return capability_err;
        }
        std::string cmd = "AT+CCHO=\"";
        cmd += ISDR_AID_HEX;
        cmd += "\"";
        std::string resp;
        esp_err_t err = idf_modem_send_at(cmd, 30000, resp);
        if (err != ESP_OK || !parse_ccho_channel(resp, m_channel)) {
            // 上次会话异常退出可能残留逻辑通道，先清理 1..3 再重试一次。
            for (int ch = 1; ch <= 3; ++ch) {
                char cchc[24];
                snprintf(cchc, sizeof(cchc), "AT+CCHC=%d", ch);
                std::string ignored;
                idf_modem_send_at(cchc, 3000, ignored);
            }
            resp.clear();
            err = idf_modem_send_at(cmd, 30000, resp);
        }
        if (err != ESP_OK || !parse_ccho_channel(resp, m_channel)) {
            message = "打开 eUICC 逻辑通道失败";
            if (err != ESP_OK) {
                message += "（";
                message += esp_err_to_name(err);
                message += "）";
            } else {
                message += "（模组响应格式无效）";
            }
            // 卡内残留主动式会话(如旧固件 REFRESH 遗留)会让 CCHO 一直报错，
            // 只有复位 UICC 能清掉；不把原始 AT 响应透传到 Web/日志。
            message += "；如反复失败请在概览页重启模组";
            return err == ESP_OK ? ESP_FAIL : err;
        }
        if (m_channel <= 0 || m_channel > 19) {
            char buf[96];
            snprintf(buf, sizeof(buf), "模组返回了不支持的逻辑通道 %d", m_channel);
            message = buf;
            // close() 只在 m_open 时生效，这里通道确实已被模组打开，必须直接关掉，
            // 否则超范围通道会一直泄漏到卡上逻辑通道耗尽
            char cchc[24];
            snprintf(cchc, sizeof(cchc), "AT+CCHC=%d", m_channel);
            std::string ignored;
            idf_modem_send_at(cchc, 5000, ignored);
            m_channel = 0;
            return ESP_FAIL;
        }
        m_open = true;
        return ESP_OK;
    }

    void close()
    {
        if (!m_open) return;
        char cmd[32];
        snprintf(cmd, sizeof(cmd), "AT+CCHC=%d", m_channel);
        std::string ignored;
        idf_modem_send_at(cmd, 5000, ignored);
        m_open = false;
        m_channel = 0;
    }

    ~EsimApduSession()
    {
        close();
    }

    esp_err_t transmit_apdu(const std::vector<uint8_t>& apdu,
                            std::vector<uint8_t>& response,
                            std::string& message)
    {
        if (!m_open) {
            message = "eUICC 逻辑通道未打开";
            return ESP_ERR_INVALID_STATE;
        }
        std::string hex = bytes_to_hex(apdu);
        char head[48];
        snprintf(head, sizeof(head), "AT+CGLA=%d,%u,\"", m_channel, static_cast<unsigned>(hex.size()));
        std::string cmd = head;
        cmd += hex;
        cmd += "\"";
        std::string resp;
        esp_err_t err = idf_modem_send_at(cmd, 30000, resp);
        if (err != ESP_OK) {
            message = "APDU AT 传输失败: ";
            message += esp_err_to_name(err);
            return err;
        }
        if (!parse_quoted_hex_response(resp, "+CGLA:", response, message)) return ESP_FAIL;
        if (response.size() < 2) {
            message = "APDU 响应过短";
            return ESP_FAIL;
        }
        return ESP_OK;
    }

    esp_err_t exchange_store_data(const std::vector<uint8_t>& payload,
                                  std::vector<uint8_t>& response_data,
                                  std::string& message)
    {
        if (payload.empty()) {
            message = "APDU payload 为空";
            return ESP_ERR_INVALID_ARG;
        }
        response_data.clear();
        size_t offset = 0;
        uint16_t block_number = 0;
        while (offset < payload.size()) {
            size_t n = std::min(STORE_DATA_MSS, payload.size() - offset);
            bool last = (offset + n == payload.size());
            if (block_number > 0xFFU) {
                message = "STORE DATA segment 过大";
                return ESP_ERR_INVALID_SIZE;
            }
            esp_err_t err = exchange_store_data_block(
                payload.data() + offset, n, last, static_cast<uint8_t>(block_number),
                response_data, message);
            if (err != ESP_OK) return err;
            offset += n;
            ++block_number;
        }
        return ESP_OK;
    }

    esp_err_t exchange_store_data_block(const uint8_t* data,
                                        size_t length,
                                        bool last,
                                        uint8_t block_number,
                                        std::vector<uint8_t>& response_data,
                                        std::string& message)
    {
        if (!data || length == 0 || length > STORE_DATA_MSS) {
            message = "STORE DATA block 大小无效";
            response_data.clear();
            return ESP_ERR_INVALID_ARG;
        }
        std::vector<uint8_t> apdu;
        apdu.reserve(5 + length);
        apdu.push_back(class_byte_for_channel(0x80, m_channel));
        apdu.push_back(0xE2);
        apdu.push_back(last ? 0x91 : 0x11);
        apdu.push_back(block_number);
        apdu.push_back(static_cast<uint8_t>(length));
        apdu.insert(apdu.end(), data, data + length);

        std::vector<uint8_t> resp;
        esp_err_t err = transmit_apdu(apdu, resp, message);
        if (err != ESP_OK) {
            response_data.clear();
            return err;
        }
        response_data.clear();
        return collect_response(resp, response_data, message);
    }

private:
    esp_err_t collect_response(const std::vector<uint8_t>& first,
                               std::vector<uint8_t>& out,
                               std::string& message)
    {
        std::vector<uint8_t> resp = first;
        size_t get_response_count = 0;
        size_t no_progress_count = 0;
        while (true) {
            uint16_t sw = response_sw(resp);
            if (sw == 0) {
                message = "APDU 响应过短";
                return ESP_FAIL;
            }
            size_t data_len = resp.size() - 2;
            if (out.size() + data_len > APDU_RESPONSE_DATA_MAX) {
                char buf[96];
                snprintf(buf, sizeof(buf), "APDU 响应过大(%u/%u字节)",
                         static_cast<unsigned>(out.size() + data_len),
                         static_cast<unsigned>(APDU_RESPONSE_DATA_MAX));
                message = buf;
                return ESP_ERR_NO_MEM;
            }
            size_t previous_out_size = out.size();
            out.insert(out.end(), resp.begin(), resp.end() - 2);
            // 91xx 表示命令已成功且模组将执行 SIM REFRESH；SW2 是主动命令长度，不是错误码。
            if (response_sw_ok(sw)) return ESP_OK;
            if ((sw >> 8) != 0x61) {
                message = status_word_text(sw);
                return ESP_FAIL;
            }
            if (out.size() == previous_out_size) {
                if (++no_progress_count > GET_RESPONSE_NO_PROGRESS_MAX) {
                    message = "APDU 分段响应无进展";
                    return ESP_FAIL;
                }
            } else {
                no_progress_count = 0;
            }
            if (++get_response_count > GET_RESPONSE_CHAIN_MAX) {
                char buf[96];
                snprintf(buf, sizeof(buf), "APDU 分段响应过多(%u段/%u字节)",
                         static_cast<unsigned>(get_response_count),
                         static_cast<unsigned>(out.size()));
                message = buf;
                return ESP_FAIL;
            }

            uint8_t le = static_cast<uint8_t>(sw & 0xFF);
            std::vector<uint8_t> get_resp = {
                class_byte_for_channel(0x80, m_channel), 0xC0, 0x00, 0x00, le
            };
            esp_err_t err = transmit_apdu(get_resp, resp, message);
            if (err != ESP_OK) return err;
        }
    }

    int m_channel = 0;
    bool m_open = false;
    bool m_terminal_capability_required = false;
};

class EsimOperationGuard {
public:
    EsimOperationGuard() { idf_modem_begin_esim_operation(); }
    ~EsimOperationGuard() { idf_modem_end_esim_operation(); }
};

static esp_err_t invoke_es10_raw(const std::vector<uint8_t>& request,
                                 bool terminal_capability_required,
                                 std::vector<uint8_t>& response,
                                 std::string& message)
{
    EsimOperationGuard guard;
    EsimApduSession session(terminal_capability_required);
    esp_err_t err = session.open(message);
    if (err != ESP_OK) return err;
    return session.exchange_store_data(request, response, message);
}

static esp_err_t invoke_es10c(const std::vector<uint8_t>& request,
                              Tlv& response,
                              std::string& message)
{
    std::vector<uint8_t> raw;
    esp_err_t err = invoke_es10_raw(request, false, raw, message);
    if (err != ESP_OK) return err;
    if (!parse_tlv(raw, response, message)) return ESP_FAIL;
    return ESP_OK;
}

static std::vector<uint8_t> make_empty_request(uint8_t tag_low)
{
    return {0xBF, tag_low, 0x00};
}

static std::vector<uint8_t> make_get_eid_request()
{
    std::vector<uint8_t> body = {0x5C, 0x01, 0x5A};
    std::vector<uint8_t> out;
    static constexpr uint8_t req_tag[] = {0xBF, 0x3E};
    append_tlv(out, req_tag, body);
    return out;
}

static std::vector<uint8_t> make_profile_list_request(bool with_tags)
{
    std::vector<uint8_t> body;
    if (with_tags) {
        // 仅请求 UI 需要的字段，避免 Profile 图标等大字段撑高堆峰值。
        std::vector<uint8_t> tags = {0x5A, 0x4F, 0x9F, 0x70, 0x90, 0x91, 0x92, 0x95};
        static constexpr uint8_t tag_list_tag[] = {0x5C};
        append_tlv(body, tag_list_tag, tags);
    }
    std::vector<uint8_t> out;
    static constexpr uint8_t req_tag[] = {0xBF, 0x2D};
    append_tlv(out, req_tag, body);
    return out;
}

static std::string profile_state_text(int state)
{
    switch (state) {
        case 0: return "disabled";
        case 1: return "enabled";
        default: return "unknown";
    }
}

static std::string profile_class_text(int klass)
{
    switch (klass) {
        case 0: return "test";
        case 1: return "provisioning";
        case 2: return "operational";
        default: return "unknown";
    }
}

static void parse_profile_info(const Tlv& tlv, IdfEsimProfile& out)
{
    static constexpr uint8_t TAG_ICCID[] = {0x5A};
    static constexpr uint8_t TAG_ISDP[] = {0x4F};
    static constexpr uint8_t TAG_STATE[] = {0x9F, 0x70};
    static constexpr uint8_t TAG_NICK[] = {0x90};
    static constexpr uint8_t TAG_SPN[] = {0x91};
    static constexpr uint8_t TAG_NAME[] = {0x92};
    static constexpr uint8_t TAG_CLASS[] = {0x95};

    if (const Tlv* v = first_child(tlv, TAG_ICCID)) out.iccid = gsm_bcd_decode(v->value);
    if (const Tlv* v = first_child(tlv, TAG_ISDP)) out.isdpAid = bytes_to_hex(v->value);
    if (const Tlv* v = first_child(tlv, TAG_STATE)) out.state = profile_state_text(tlv_int_value(*v, -1));
    if (const Tlv* v = first_child(tlv, TAG_NICK)) out.nickname.assign(v->value.begin(), v->value.end());
    if (const Tlv* v = first_child(tlv, TAG_SPN)) out.serviceProvider.assign(v->value.begin(), v->value.end());
    if (const Tlv* v = first_child(tlv, TAG_NAME)) out.profileName.assign(v->value.begin(), v->value.end());
    if (const Tlv* v = first_child(tlv, TAG_CLASS)) out.profileClass = profile_class_text(tlv_int_value(*v, 1));
    if (out.state.empty()) out.state = "disabled";
    if (out.profileClass.empty()) out.profileClass = "provisioning";
}

static bool parse_profile_list_response(const Tlv& response,
                                        std::vector<IdfEsimProfile>& profiles,
                                        std::string& message)
{
    static constexpr uint8_t TAG_LIST[] = {0xBF, 0x2D};
    static constexpr uint8_t TAG_ERROR[] = {0x81};
    static constexpr uint8_t TAG_CONTAINER[] = {0xA0};
    static constexpr uint8_t TAG_PROFILE_E3[] = {0xE3};
    static constexpr uint8_t TAG_PROFILE_BF25[] = {0xBF, 0x25};

    if (!tag_is(response, TAG_LIST)) {
        message = "Profile 列表响应 tag 不匹配";
        return false;
    }
    if (const Tlv* err = first_child(response, TAG_ERROR)) {
        int code = tlv_int_value(*err, 127);
        message = (code == 1) ? "eUICC 拒绝 Profile 列表查询参数" : "eUICC 返回 Profile 列表未知错误";
        return false;
    }
    const Tlv* container = first_child(response, TAG_CONTAINER);
    const std::vector<Tlv>& rows = container ? container->children : response.children;
    profiles.clear();
    for (const Tlv& row : rows) {
        if (!tag_is(row, TAG_PROFILE_E3) && !tag_is(row, TAG_PROFILE_BF25)) continue;
        IdfEsimProfile p;
        parse_profile_info(row, p);
        if (!p.iccid.empty() || !p.isdpAid.empty()) profiles.push_back(std::move(p));
    }
    return true;
}

// EID 是单张 eUICC 的固定标识，读到一次后缓存：省掉每次列表前的一整个 APDU 会话。
// 调用方由蜂窝任务互斥锁串行化，无并发写。但可插拔 eUICC 热插拔换卡后 EID 会变，
// 模组的卡身份钩子只置原子脏标记(可能在模组任务上下文触发)，真正清缓存在
// 下次 read_eid(蜂窝任务上下文)执行，与读取方天然串行，无竞争。
static std::string s_eid_cache;
static std::atomic<bool> s_eid_cache_stale{false};

static void on_sim_identity_changed()
{
    s_eid_cache_stale.store(true, std::memory_order_relaxed);
}

static esp_err_t read_eid(std::string& eid, std::string& message)
{
    static constexpr uint8_t TAG_EID_RESP[] = {0xBF, 0x3E};
    static constexpr uint8_t TAG_EID[] = {0x5A};

    if (s_eid_cache_stale.exchange(false, std::memory_order_relaxed)) s_eid_cache.clear();
    if (!s_eid_cache.empty()) {
        eid = s_eid_cache;
        message = "EID(缓存)";
        return ESP_OK;
    }

    Tlv response;
    esp_err_t err = invoke_es10c(make_get_eid_request(), response, message);
    if (err != ESP_OK) return err;
    if (!tag_is(response, TAG_EID_RESP)) {
        message = "EID 响应 tag 不匹配";
        return ESP_FAIL;
    }
    const Tlv* eid_tlv = first_child(response, TAG_EID);
    if (!eid_tlv || eid_tlv->value.empty()) {
        message = "eUICC 未返回 EID";
        return ESP_FAIL;
    }
    eid = eid_decode(eid_tlv->value);
    s_eid_cache = eid;
    message = "EID 读取成功";
    return ESP_OK;
}

static esp_err_t read_profiles(std::vector<IdfEsimProfile>& profiles, std::string& message)
{
    Tlv response;
    esp_err_t err = invoke_es10c(make_profile_list_request(true), response, message);
    if (err == ESP_OK && parse_profile_list_response(response, profiles, message)) {
        char buf[64];
        snprintf(buf, sizeof(buf), "已读取 %u 个 eSIM Profile", static_cast<unsigned>(profiles.size()));
        message = buf;
        return ESP_OK;
    }

    // 部分卡对 tag-list 参数较挑剔，退回 BF2D00 再试一次。
    std::string first_error = message;
    response = Tlv();
    err = invoke_es10c(make_profile_list_request(false), response, message);
    if (err == ESP_OK && parse_profile_list_response(response, profiles, message)) {
        char buf[96];
        snprintf(buf, sizeof(buf), "已读取 %u 个 eSIM Profile（兼容模式）", static_cast<unsigned>(profiles.size()));
        message = buf;
        return ESP_OK;
    }
    if (!first_error.empty()) message = first_error + "；兼容查询仍失败: " + message;
    return err == ESP_OK ? ESP_FAIL : err;
}

static bool make_direct_identifier(const std::string& raw,
                                   bool require_iccid,
                                   ProfileIdentifier& out,
                                   std::string& message)
{
    std::string value = idf_util_trim_copy(raw);
    std::string digits = compact_digits(value);
    if (digits.size() >= 18 && digits.size() <= 22 && digits.size() == value.size()) {
        std::vector<uint8_t> bcd;
        if (!gsm_bcd_encode(digits, bcd)) {
            message = "ICCID 格式无效";
            return false;
        }
        out.tag = {0x5A};
        out.value = std::move(bcd);
        out.display = digits;
        return true;
    }
    if (!require_iccid && value.size() >= 10 && value.size() <= 64 && is_hex_string(value)) {
        std::vector<uint8_t> aid;
        if (hex_to_bytes(value, aid)) {
            out.tag = {0x4F};
            out.value = std::move(aid);
            out.display = value;
            return true;
        }
    }
    return false;
}

static bool profile_matches(const IdfEsimProfile& p, const std::string& id)
{
    std::string v = idf_util_trim_copy(id);
    return (!p.iccid.empty() && equals_relaxed(p.iccid, v)) ||
           (!p.isdpAid.empty() && equals_relaxed(p.isdpAid, v)) ||
           (!p.nickname.empty() && equals_relaxed(p.nickname, v)) ||
           (!p.profileName.empty() && equals_relaxed(p.profileName, v)) ||
           (!p.serviceProvider.empty() && equals_relaxed(p.serviceProvider, v));
}

static bool identifier_from_profile(const IdfEsimProfile& profile,
                                    ProfileIdentifier& out,
                                    std::string& message)
{
    if (profile.iccid.empty()) {
        message = "目标 Profile 没有 ICCID，暂不能执行该操作";
        return false;
    }
    return make_direct_identifier(profile.iccid, true, out, message);
}

static esp_err_t resolve_identifier(const std::string& raw,
                                    bool require_iccid,
                                    ProfileIdentifier& out,
                                    std::string& message)
{
    if (raw.empty()) {
        message = "Profile 标识为空";
        return ESP_ERR_INVALID_ARG;
    }
    if (make_direct_identifier(raw, require_iccid, out, message)) return ESP_OK;

    std::vector<IdfEsimProfile> profiles;
    std::string list_msg;
    esp_err_t err = read_profiles(profiles, list_msg);
    if (err != ESP_OK) {
        message = "无法解析别名/Profile 名称：" + list_msg;
        return err;
    }
    const IdfEsimProfile* hit = nullptr;
    int matched = 0;
    for (const IdfEsimProfile& profile : profiles) {
        if (!profile_matches(profile, raw)) continue;
        ++matched;
        if (!hit) hit = &profile;
    }
    if (matched > 1) {
        // 昵称/运营商名可能重复(如两张同一运营商的卡)。启停尤其是删除都不可逆，
        // 绝不能"默默选第一个"，必须让用户改用唯一的完整 ICCID
        char buf[96];
        snprintf(buf, sizeof(buf), "该标识匹配到 %d 个 Profile，请改用完整 ICCID 指定", matched);
        message = buf;
        return ESP_ERR_INVALID_ARG;
    }
    if (hit) return identifier_from_profile(*hit, out, message) ? ESP_OK : ESP_FAIL;
    message = "未找到匹配的 eSIM Profile: " + idf_esim_mask_profile_id(raw);
    return ESP_ERR_NOT_FOUND;
}

static std::vector<uint8_t> make_profile_operation_request(const ProfileIdentifier& identifier,
                                                           bool enable)
{
    std::vector<uint8_t> id_tlv;
    append_tlv(id_tlv, identifier.tag.data(), identifier.tag.size(), identifier.value);

    std::vector<uint8_t> body;
    static constexpr uint8_t TAG_A0[] = {0xA0};
    append_tlv(body, TAG_A0, id_tlv);
    // refreshFlag 显式编码为 FALSE(0x00)：REFRESH 主动式命令在 ML307R 上不会被取走
    // 执行，遗留的主动式会话会让后续 CCHO/ES10c 轮番报 catBusy/CME ERROR 4(issue #17)。
    // SGP.22 允许无 refreshFlag 模式，由 LPA(本固件)在成功后自行复位 UICC。
    std::vector<uint8_t> refresh_value = {0x00};
    static constexpr uint8_t TAG_REFRESH[] = {0x81};
    append_tlv(body, TAG_REFRESH, refresh_value);

    std::vector<uint8_t> out;
    const uint8_t tag_enable[] = {0xBF, 0x31};
    const uint8_t tag_disable[] = {0xBF, 0x32};
    if (enable) append_tlv(out, tag_enable, body);
    else append_tlv(out, tag_disable, body);
    return out;
}

static const char* operation_result_text(bool enable, int result)
{
    switch (result) {
        case 0: return "OK";
        case 1: return "ICCID/AID 不存在";
        case 2: return enable ? "Profile 不是禁用状态" : "Profile 不是启用状态";
        case 3: return "Profile 策略禁止该操作";
        case 4: return "卡拒绝重复启用当前 Profile";
        case 5: return "卡工具包忙，请稍后重试";
        case 127: return "eUICC 未定义错误";
        default: return "未知结果码";
    }
}

static const char* delete_result_text(int result)
{
    switch (result) {
        case 0: return "OK";
        case 1: return "ICCID/AID 不存在";
        case 2: return "Profile 不是禁用状态";
        case 3: return "Profile 策略禁止删除";
        case 5: return "卡工具包忙，请稍后重试";
        case 127: return "eUICC 未定义错误";
        default: return "未知结果码";
    }
}

static esp_err_t profile_operation_once(const ProfileIdentifier& identifier,
                                        bool enable,
                                        int& result_code,
                                        std::string& message)
{
    result_code = -1;
    Tlv response;
    esp_err_t err = invoke_es10c(make_profile_operation_request(identifier, enable), response, message);
    if (err != ESP_OK) return err;

    const uint8_t expected_enable[] = {0xBF, 0x31};
    const uint8_t expected_disable[] = {0xBF, 0x32};
    if ((enable && !tag_is(response, expected_enable)) || (!enable && !tag_is(response, expected_disable))) {
        message = "Profile 操作响应 tag 不匹配";
        return ESP_FAIL;
    }
    static constexpr uint8_t TAG_RESULT[] = {0x80};
    const Tlv* result = first_child(response, TAG_RESULT);
    if (!result) {
        message = "Profile 操作响应缺少结果码";
        return ESP_FAIL;
    }
    result_code = tlv_int_value(*result, 127);
    if (result_code != 0) {
        message = operation_result_text(enable, result_code);
        return ESP_FAIL;
    }
    return ESP_OK;
}

// 等待模组重启(软/硬)完成：重启请求受理时 phase 立即变 powering，重启后完成短信/注册
// 配置才进入 registering，此时 SIM 已就绪，可重新打开逻辑通道。
static bool wait_modem_reset_done(uint32_t timeout_ms)
{
    for (uint32_t waited = 0; waited < timeout_ms; waited += 1000) {
        vTaskDelay(pdMS_TO_TICKS(1000));
        IdfModemStatus st = idf_modem_get_status();
        if (st.atReady && st.phase != "powering" && st.phase != "at_ready") return true;
    }
    return false;
}

static esp_err_t profile_operation(const std::string& raw, bool enable, std::string& message)
{
    ProfileIdentifier identifier;
    esp_err_t err = resolve_identifier(raw, false, identifier, message);
    if (err != ESP_OK) return err;

    int code = -1;
    err = profile_operation_once(identifier, enable, code, message);
    if (err != ESP_OK && code == 5) {
        // catBusy：卡内残留主动式会话(多为旧固件 refreshFlag 遗留；模组不断电时
        // 可跨 ESP 重启甚至 OTA 升级存活)。硬重启(断电)彻底清掉卡内会话后重试一次，
        // 免得用户反复点击都停在"卡工具包忙"
        idf_logf("eSIM 操作遇到 catBusy，硬重启模组复位 UICC 后重试");
        idf_modem_request_reset(true);
        if (!wait_modem_reset_done(90000)) {
            message += "；模组重启超时，请稍后重试";
            return ESP_FAIL;
        }
        err = profile_operation_once(identifier, enable, code, message);
    }
    if (err != ESP_OK) return err;
    // 启停结果已写入 eUICC，但当前 UICC 会话仍运行旧 Profile：必须复位 UICC(模组
    // 软重启)才真正生效。这一步就是 issue #17 里用户手动"重启+断电"的自动化。
    idf_modem_request_reset(false);
    message = enable ? "eSIM Profile 已启用，模组重启附着新卡中"
                     : "eSIM Profile 已禁用，模组重启生效中";
    return ESP_OK;
}

static std::vector<uint8_t> make_delete_profile_request(const ProfileIdentifier& identifier)
{
    std::vector<uint8_t> id_tlv;
    append_tlv(id_tlv, identifier.tag.data(), identifier.tag.size(), identifier.value);

    std::vector<uint8_t> out;
    static constexpr uint8_t tag_delete[] = {0xBF, 0x33};
    append_tlv(out, tag_delete, id_tlv);
    return out;
}

static esp_err_t delete_profile(const std::string& raw, std::string& message)
{
    ProfileIdentifier identifier;
    esp_err_t err = resolve_identifier(raw, false, identifier, message);
    if (err != ESP_OK) return err;

    Tlv response;
    err = invoke_es10c(make_delete_profile_request(identifier), response, message);
    if (err != ESP_OK) return err;

    static constexpr uint8_t TAG_RESP[] = {0xBF, 0x33};
    static constexpr uint8_t TAG_RESULT[] = {0x80};
    if (!tag_is(response, TAG_RESP)) {
        message = "Profile 删除响应 tag 不匹配";
        return ESP_FAIL;
    }
    const Tlv* result = first_child(response, TAG_RESULT);
    if (!result) {
        message = "Profile 删除响应缺少结果码";
        return ESP_FAIL;
    }
    int code = tlv_int_value(*result, 127);
    if (code != 0) {
        message = delete_result_text(code);
        return ESP_FAIL;
    }
    message = "eSIM Profile 已删除";
    return ESP_OK;
}

static std::vector<uint8_t> make_set_nickname_request(const ProfileIdentifier& identifier,
                                                      const std::string& nickname)
{
    std::vector<uint8_t> body;
    append_tlv(body, identifier.tag.data(), identifier.tag.size(), identifier.value);
    std::vector<uint8_t> nick(nickname.begin(), nickname.end());
    static constexpr uint8_t TAG_NICK[] = {0x90};
    append_tlv(body, TAG_NICK, nick);

    std::vector<uint8_t> out;
    static constexpr uint8_t TAG_REQ[] = {0xBF, 0x29};
    append_tlv(out, TAG_REQ, body);
    return out;
}

static esp_err_t set_profile_nickname(const std::string& raw,
                                      const std::string& nickname,
                                      std::string& message)
{
    std::string nick = idf_util_trim_copy(nickname);
    if (nick.size() > 64) {
        message = "昵称最长 64 字节";
        return ESP_ERR_INVALID_ARG;
    }

    ProfileIdentifier identifier;
    esp_err_t err = resolve_identifier(raw, true, identifier, message);
    if (err != ESP_OK) return err;

    Tlv response;
    err = invoke_es10c(make_set_nickname_request(identifier, nick), response, message);
    if (err != ESP_OK) return err;

    static constexpr uint8_t TAG_RESP[] = {0xBF, 0x29};
    static constexpr uint8_t TAG_RESULT[] = {0x80};
    if (!tag_is(response, TAG_RESP)) {
        message = "昵称设置响应 tag 不匹配";
        return ESP_FAIL;
    }
    const Tlv* result = first_child(response, TAG_RESULT);
    if (!result) {
        message = "昵称设置响应缺少结果码";
        return ESP_FAIL;
    }
    int code = tlv_int_value(*result, 127);
    if (code == 0) {
        message = "eSIM Profile 昵称已更新";
        return ESP_OK;
    }
    message = (code == 1) ? "ICCID 不存在" : "eUICC 设置昵称失败";
    return ESP_FAIL;
}

// 下载 preflight 只验证 BF20/BF22，并把 BF20 原始对象留给当前认证任务；
// 解析出的能力字段不离开本次卡侧会话，也不进入 Web 或长期 RAM 状态。
static esp_err_t read_lpa_preflight(EsimApduSession& session,
                                    std::vector<uint8_t>* raw_info1,
                                    std::string& message)
{
    std::vector<uint8_t> raw;
    idf_esim_internal::EuiccInfo1Fields info1;
    esp_err_t err = session.exchange_store_data(make_empty_request(0x20), raw, message);
    if (err != ESP_OK) return err;
    if (!idf_esim_internal::parse_euicc_info1(raw, info1, message)) return ESP_FAIL;
    if (raw_info1) *raw_info1 = std::move(raw);

    raw.clear();
    idf_esim_internal::EuiccInfo2Fields info2;
    err = session.exchange_store_data(make_empty_request(0x22), raw, message);
    if (err != ESP_OK) return err;
    if (!idf_esim_internal::parse_euicc_info2(raw, info2, message)) return ESP_FAIL;
    idf_logf("eSIM 下载前置检查: profileVersion=%s svn=%s firmware=%s freeNv=%u freeRam=%u additionalProfile=%d testProfile=%d",
             info2.profileVersion.c_str(),
             info2.svn.c_str(),
             info2.firmwareVersion.c_str(),
             static_cast<unsigned>(info2.freeNonVolatileMemory),
             static_cast<unsigned>(info2.freeVolatileMemory),
             info2.additionalProfile ? 1 : 0,
             info2.testProfileSupport ? 1 : 0);
    return ESP_OK;
}

static esp_err_t read_lpa_auth_material(std::vector<uint8_t>& euicc_info1,
                                        std::array<uint8_t, 16>& challenge,
                                        std::string& message)
{
    euicc_info1.clear();
    challenge.fill(0);
    EsimOperationGuard guard;
    EsimApduSession session(true);
    esp_err_t err = session.open(message);
    if (err != ESP_OK) return err;

    err = read_lpa_preflight(session, &euicc_info1, message);
    if (err != ESP_OK) return err;

    std::vector<uint8_t> raw;
    err = session.exchange_store_data(make_empty_request(0x2E), raw, message);
    if (err != ESP_OK) return err;
    if (!idf_esim_internal::parse_euicc_challenge(raw, challenge.data(), message)) return ESP_FAIL;
    message = "eUICC LPA 认证材料已准备";
    return ESP_OK;
}

struct IdfEsimLpaBppSessionImpl {
    std::unique_ptr<EsimOperationGuard> guard;
    std::unique_ptr<EsimApduSession> session;
};

}  // namespace

void idf_esim_init(void)
{
    // 必须定义在匿名命名空间之外，否则是内部链接，app_main 链接不到
    idf_modem_set_sim_identity_hook(on_sim_identity_changed);
}

esp_err_t idf_esim_get_eid(std::string& eid, std::string& message)
{
    return read_eid(eid, message);
}

esp_err_t idf_esim_lpa_get_auth_material(std::vector<uint8_t>& euicc_info1,
                                         std::array<uint8_t, 16>& challenge,
                                         std::string& safe_message)
{
    return read_lpa_auth_material(euicc_info1, challenge, safe_message);
}

esp_err_t idf_esim_lpa_authenticate_server(const std::vector<uint8_t>& request,
                                           std::vector<uint8_t>& response,
                                           std::string& safe_message)
{
    if (request.empty() || request.size() > 16U * 1024U) {
        safe_message = "AuthenticateServer 数据对象大小无效";
        response.clear();
        return ESP_ERR_INVALID_SIZE;
    }
    static constexpr uint8_t TAG_AUTHENTICATE_SERVER[] = {0xBF, 0x38};
    Tlv request_tlv;
    if (!parse_tlv(request, request_tlv, safe_message) ||
        !tag_is(request_tlv, TAG_AUTHENTICATE_SERVER)) {
        safe_message = "AuthenticateServer 数据对象 tag 无效";
        response.clear();
        return ESP_ERR_INVALID_ARG;
    }
    return invoke_es10_raw(request, true, response, safe_message);
}

esp_err_t idf_esim_lpa_prepare_download(const std::vector<uint8_t>& request,
                                        std::vector<uint8_t>& response,
                                        std::string& safe_message)
{
    if (request.empty() || request.size() > 16U * 1024U) {
        safe_message = "PrepareDownload 数据对象大小无效";
        response.clear();
        return ESP_ERR_INVALID_SIZE;
    }
    static constexpr uint8_t TAG_PREPARE_DOWNLOAD[] = {0xBF, 0x21};
    Tlv request_tlv;
    if (!parse_tlv(request, request_tlv, safe_message) ||
        !tag_is(request_tlv, TAG_PREPARE_DOWNLOAD)) {
        safe_message = "PrepareDownload 数据对象 tag 无效";
        response.clear();
        return ESP_ERR_INVALID_ARG;
    }
    return invoke_es10_raw(request, true, response, safe_message);
}

esp_err_t idf_esim_lpa_retrieve_notifications(
    std::vector<uint8_t>& encoded_response,
    size_t& list_offset,
    size_t& list_length,
    std::string& safe_message)
{
    encoded_response.clear();
    list_offset = 0;
    list_length = 0;
    static constexpr uint8_t TAG_RETRIEVE_NOTIFICATIONS[] = {0xBF, 0x2B};
    static constexpr uint8_t TAG_NOTIFICATION_LIST[] = {0xA0};
    static constexpr uint8_t TAG_RESULT_ERROR[] = {0x81};
    // searchCriteria 在 SGP.22 中为 OPTIONAL。直接省略可同时覆盖全部标准通知，
    // 也兼容拒绝 operation/sequence 筛选、但支持无条件检索的 eUICC。
    std::vector<uint8_t> request = {0xBF, 0x2B, 0x00};

    esp_err_t err = invoke_es10_raw(request, true, encoded_response, safe_message);
    if (err != ESP_OK) return err;

    size_t pos = 0;
    idf_esim_internal::TlvSpan root;
    if (!idf_esim_internal::parse_tlv_span(
            encoded_response, encoded_response.size(), pos, root, safe_message) ||
        pos != encoded_response.size() ||
        !idf_esim_internal::tag_is(encoded_response, root, TAG_RETRIEVE_NOTIFICATIONS)) {
        encoded_response.clear();
        safe_message = "RetrieveNotificationsList 响应 tag 无效";
        return ESP_ERR_INVALID_RESPONSE;
    }

    pos = root.valueOffset;
    const size_t root_end = root.valueOffset + root.valueLength;
    idf_esim_internal::TlvSpan choice;
    if (!idf_esim_internal::parse_tlv_span(
            encoded_response, root_end, pos, choice, safe_message) || pos != root_end) {
        encoded_response.clear();
        safe_message = "RetrieveNotificationsList 响应 choice 无效";
        return ESP_ERR_INVALID_RESPONSE;
    }

    if (idf_esim_internal::tag_is(encoded_response, choice, TAG_RESULT_ERROR)) {
        if (choice.valueLength == 1U && encoded_response[choice.valueOffset] == 127U) {
            safe_message = "eUICC 无法检索待发送通知";
        } else {
            safe_message = "RetrieveNotificationsList 错误结果无效";
        }
        encoded_response.clear();
        return ESP_ERR_INVALID_RESPONSE;
    }
    if (!idf_esim_internal::tag_is(encoded_response, choice, TAG_NOTIFICATION_LIST)) {
        encoded_response.clear();
        safe_message = "RetrieveNotificationsList 成功结果无效";
        return ESP_ERR_INVALID_RESPONSE;
    }
    list_offset = choice.valueOffset;
    list_length = choice.valueLength;
    return ESP_OK;
}

esp_err_t idf_esim_lpa_remove_notification(uint32_t sequence_number,
                                            std::string& safe_message)
{
    std::vector<uint8_t> integer;
    uint32_t value = sequence_number;
    do {
        integer.push_back(static_cast<uint8_t>(value & 0xFFU));
        value >>= 8U;
    } while (value != 0U);
    std::reverse(integer.begin(), integer.end());
    if ((integer.front() & 0x80U) != 0U) integer.insert(integer.begin(), 0U);

    static constexpr uint8_t TAG_REMOVE_NOTIFICATION[] = {0xBF, 0x30};
    static constexpr uint8_t TAG_SEQUENCE_NUMBER[] = {0x80};
    std::vector<uint8_t> body;
    append_tlv(body, TAG_SEQUENCE_NUMBER, integer);
    std::vector<uint8_t> request;
    append_tlv(request, TAG_REMOVE_NOTIFICATION, body);
    std::vector<uint8_t> response;
    esp_err_t err = invoke_es10_raw(request, true, response, safe_message);
    if (err != ESP_OK) return err;

    // SW=9000 只表示 APDU 传输成功，还必须检查 BF30 的业务状态。
    static constexpr uint8_t TAG_STATUS[] = {0x80};
    Tlv root;
    if (!parse_tlv(response, root, safe_message) ||
        !tag_is(root, TAG_REMOVE_NOTIFICATION) ||
        root.children.size() != 1U ||
        !tag_is(root.children.front(), TAG_STATUS) ||
        root.children.front().value.size() != 1U) {
        safe_message = "RemoveNotificationFromList 响应无效";
        return ESP_ERR_INVALID_RESPONSE;
    }

    switch (root.children.front().value[0]) {
        case 0x00:
            return ESP_OK;
        case 0x01:
            // 服务器已确认通知，卡侧目标状态已满足；重复清理应保持幂等成功。
            idf_log_line("eSIM 待处理通知已不在卡侧列表中");
            return ESP_OK;
        case 0x7F:
            safe_message = "eUICC 删除待处理通知失败";
            return ESP_FAIL;
        default:
            safe_message = "RemoveNotificationFromList 返回未知状态";
            return ESP_ERR_INVALID_RESPONSE;
    }
}

IdfEsimLpaBppSession::IdfEsimLpaBppSession() : impl_(nullptr) {}

IdfEsimLpaBppSession::~IdfEsimLpaBppSession()
{
    close();
}

esp_err_t IdfEsimLpaBppSession::begin_segment(std::string& safe_message)
{
    if (impl_) return ESP_OK;
    auto* impl = new (std::nothrow) IdfEsimLpaBppSessionImpl();
    if (!impl) {
        safe_message = "BPP segment 会话内存不足";
        return ESP_ERR_NO_MEM;
    }
    impl->guard.reset(new (std::nothrow) EsimOperationGuard());
    impl->session.reset(new (std::nothrow) EsimApduSession(true));
    if (!impl->guard || !impl->session) {
        impl->session.reset();
        impl->guard.reset();
        delete impl;
        safe_message = "BPP segment 会话内存不足";
        return ESP_ERR_NO_MEM;
    }
    esp_err_t err = impl->session->open(safe_message);
    if (err != ESP_OK) {
        impl->session.reset();
        impl->guard.reset();
        delete impl;
        return err;
    }
    impl_ = impl;
    return ESP_OK;
}

esp_err_t IdfEsimLpaBppSession::write_block(const uint8_t* data,
                                            size_t length,
                                            bool last,
                                            uint8_t block_number,
                                            std::vector<uint8_t>& response,
                                            std::string& safe_message)
{
    auto* impl = static_cast<IdfEsimLpaBppSessionImpl*>(impl_);
    if (!impl || !impl->session) {
        safe_message = "BPP segment 会话未打开";
        response.clear();
        return ESP_ERR_INVALID_STATE;
    }
    return impl->session->exchange_store_data_block(data, length, last, block_number,
                                                    response, safe_message);
}

void IdfEsimLpaBppSession::close()
{
    auto* impl = static_cast<IdfEsimLpaBppSessionImpl*>(impl_);
    if (!impl) return;
    if (impl->session) impl->session->close();
    impl->session.reset();
    impl->guard.reset();
    delete impl;
    impl_ = nullptr;
}

esp_err_t idf_esim_list_profiles(std::vector<IdfEsimProfile>& profiles,
                                 std::string& eid,
                                 std::string& message)
{
    std::string eid_msg;
    esp_err_t eid_err = read_eid(eid, eid_msg);
    esp_err_t list_err = read_profiles(profiles, message);
    if (list_err == ESP_OK) {
        if (eid_err != ESP_OK) {
            message += "；EID 读取失败: " + eid_msg;
        }
        return ESP_OK;
    }
    if (eid_err == ESP_OK) {
        message = "EID 已读取，但 Profile 列表失败: " + message;
    }
    return list_err;
}

esp_err_t idf_esim_enable_profile(const std::string& identifier, std::string& message)
{
    return profile_operation(identifier, true, message);
}

esp_err_t idf_esim_disable_profile(const std::string& identifier, std::string& message)
{
    return profile_operation(identifier, false, message);
}

esp_err_t idf_esim_delete_profile(const std::string& identifier,
                                  std::string& message)
{
    return delete_profile(identifier, message);
}

esp_err_t idf_esim_set_nickname(const std::string& identifier,
                                const std::string& nickname,
                                std::string& message)
{
    return set_profile_nickname(identifier, nickname, message);
}

esp_err_t idf_esim_switch_profile(const std::string& identifier, std::string& message)
{
    std::vector<IdfEsimProfile> profiles;
    std::string list_msg;
    esp_err_t err = read_profiles(profiles, list_msg);
    if (err != ESP_OK) {
        message = "切换前无法读取 Profile 列表: " + list_msg;
        return err;
    }
    for (const IdfEsimProfile& profile : profiles) {
        if (!profile_matches(profile, identifier)) continue;
        if (profile.state == "enabled") {
            std::string display_id = profile.iccid.empty() ? profile.isdpAid : profile.iccid;
            if (display_id.empty()) display_id = identifier;
            message = "目标 eSIM Profile 已经启用: " + idf_esim_mask_profile_id(display_id);
            return ESP_OK;
        }
        // 列表条目可能缺 ICCID(5A tag)，退回 ISD-P AID 启用
        const std::string& enable_id = profile.iccid.empty() ? profile.isdpAid : profile.iccid;
        if (enable_id.empty()) break;  // 两者都没有则走下面的直接标识兜底
        err = idf_esim_enable_profile(enable_id, message);
        if (err == ESP_OK) {
            message = "已切换到 eSIM Profile: " + idf_esim_mask_profile_id(enable_id) +
                      "，模组重启附着新卡中";
        }
        return err;
    }

    // 用户填 ICCID/AID 时，列表里没有读到可匹配字段也尝试直接启用一次。
    ProfileIdentifier direct;
    std::string direct_msg;
    if (make_direct_identifier(identifier, false, direct, direct_msg)) {
        err = idf_esim_enable_profile(identifier, message);
        if (err == ESP_OK) {
            message = "已按输入标识尝试启用 eSIM Profile: " + idf_esim_mask_profile_id(identifier) +
                      "，模组重启附着新卡中";
        }
        return err;
    }

    message = "未找到目标 eSIM Profile: " + idf_esim_mask_profile_id(identifier);
    return ESP_ERR_NOT_FOUND;
}

bool idf_esim_profile_matches(const IdfEsimProfile& profile, const std::string& identifier)
{
    return profile_matches(profile, identifier);
}

std::string idf_esim_mask_profile_id(const std::string& identifier)
{
    std::string value = idf_util_trim_copy(identifier);
    if (value.size() <= 8) return value;
    // 中文别名按字节切会产生非法 UTF-8，污染 JSON/推送；别名非敏感，原样返回
    for (char ch : value) {
        if (static_cast<unsigned char>(ch) >= 0x80) return value;
    }
    return value.substr(0, 4) + "****" + value.substr(value.size() - 4);
}
