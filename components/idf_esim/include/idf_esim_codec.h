#pragma once

#include <stddef.h>
#include <stdint.h>

#include <string>
#include <vector>

namespace idf_esim_internal {

struct Tlv {
    std::vector<uint8_t> tag;
    std::vector<uint8_t> value;
    std::vector<Tlv> children;
    bool constructed = false;
};

// 指向原始缓冲区中的一个完整 TLV，不复制 value；用于通知列表等较大响应。
struct TlvSpan {
    size_t offset = 0;
    size_t tagLength = 0;
    size_t valueOffset = 0;
    size_t valueLength = 0;

    size_t encoded_length() const { return valueOffset + valueLength - offset; }
};

bool tag_is(const Tlv& tlv, const uint8_t* tag, size_t len);

bool tag_is(const std::vector<uint8_t>& data,
            const TlvSpan& tlv,
            const uint8_t* tag,
            size_t len);

template <size_t N>
bool tag_is(const Tlv& tlv, const uint8_t (&tag)[N])
{
    return tag_is(tlv, tag, N);
}

template <size_t N>
bool tag_is(const std::vector<uint8_t>& data,
            const TlvSpan& tlv,
            const uint8_t (&tag)[N])
{
    return tag_is(data, tlv, tag, N);
}

template <size_t N>
const Tlv* first_child(const Tlv& tlv, const uint8_t (&tag)[N])
{
    for (const Tlv& child : tlv.children) {
        if (tag_is(child, tag)) return &child;
    }
    return nullptr;
}

bool parse_tlv(const std::vector<uint8_t>& data, Tlv& out, std::string& message);
bool parse_tlv_at(const std::vector<uint8_t>& data,
                  size_t end,
                  size_t& pos,
                  Tlv& out,
                  std::string& message);
bool parse_tlv_list(const std::vector<uint8_t>& data, std::vector<Tlv>& out, std::string& message);
bool parse_tlv_span(const std::vector<uint8_t>& data,
                    size_t end,
                    size_t& pos,
                    TlvSpan& out,
                    std::string& message);
void append_tlv(std::vector<uint8_t>& out,
                const uint8_t* tag,
                size_t tag_len,
                const std::vector<uint8_t>& value);

template <size_t N>
void append_tlv(std::vector<uint8_t>& out,
                const uint8_t (&tag)[N],
                const std::vector<uint8_t>& value)
{
    append_tlv(out, tag, N, value);
}

enum class CsimParseResult {
    success,
    malformed,
    status_error,
};

CsimParseResult parse_terminal_capability_csim(const std::string& response,
                                               uint16_t& sw,
                                               std::string& message);

struct EuiccInfo1Fields {
    std::string svn;
};

struct EuiccInfo2Fields {
    std::string profileVersion;
    std::string svn;
    std::string firmwareVersion;
    uint32_t freeNonVolatileMemory = 0;
    uint32_t freeVolatileMemory = 0;
    bool additionalProfile = false;
    bool testProfileSupport = false;
};

bool parse_euicc_info1(const std::vector<uint8_t>& data,
                       EuiccInfo1Fields& out,
                       std::string& message);
bool parse_euicc_info2(const std::vector<uint8_t>& data,
                       EuiccInfo2Fields& out,
                       std::string& message);
bool parse_euicc_challenge(const std::vector<uint8_t>& data,
                           uint8_t out[16],
                           std::string& message);

}  // namespace idf_esim_internal
