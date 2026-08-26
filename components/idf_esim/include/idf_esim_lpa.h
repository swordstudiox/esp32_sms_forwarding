#pragma once

#include <array>
#include <stddef.h>
#include <stdint.h>
#include <string>
#include <vector>

#include "esp_err.h"

// 读取正式下载认证所需的 BF20 原始对象和 BF2E challenge；同时执行 BF22 能力/空间前置检查。
esp_err_t idf_esim_lpa_get_auth_material(std::vector<uint8_t>& euicc_info1,
                                         std::array<uint8_t, 16>& challenge,
                                         std::string& safe_message);

// 发送受控的 ES10b.AuthenticateServer BF38 数据对象，不暴露任意 raw APDU。
esp_err_t idf_esim_lpa_authenticate_server(const std::vector<uint8_t>& request,
                                           std::vector<uint8_t>& response,
                                           std::string& safe_message);

// 发送受控的 ES10b.PrepareDownload BF21 数据对象。
esp_err_t idf_esim_lpa_prepare_download(const std::vector<uint8_t>& request,
                                        std::vector<uint8_t>& response,
                                        std::string& safe_message);

// 无筛选检索 eUICC 中全部待发送通知（BF2B）。原始响应只保留一份，并返回
// A0 列表的 value 范围；调用方按需扫描每条通知，避免递归 TLV 树和 payload 副本。
esp_err_t idf_esim_lpa_retrieve_notifications(
    std::vector<uint8_t>& encoded_response,
    size_t& list_offset,
    size_t& list_length,
    std::string& safe_message);

esp_err_t idf_esim_lpa_remove_notification(uint32_t sequence_number,
                                           std::string& safe_message);

// 在一个 BPP segment 内按模组允许的 transport block 写入；每个 segment
// 重新打开最短的 eUICC 会话，避免 HTTPS 等待期间长期占用 AT 通道。
class IdfEsimLpaBppSession {
public:
    IdfEsimLpaBppSession();
    IdfEsimLpaBppSession(const IdfEsimLpaBppSession&) = delete;
    IdfEsimLpaBppSession& operator=(const IdfEsimLpaBppSession&) = delete;
    ~IdfEsimLpaBppSession();

    esp_err_t begin_segment(std::string& safe_message);
    esp_err_t write_block(const uint8_t* data,
                          size_t length,
                          bool last,
                          uint8_t block_number,
                          std::vector<uint8_t>& response,
                          std::string& safe_message);
    void close();

private:
    void* impl_;
};
