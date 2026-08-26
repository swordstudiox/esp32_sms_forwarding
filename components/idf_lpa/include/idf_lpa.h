#pragma once

#include <stddef.h>

#include <string>

#include "esp_err.h"

// 保存输入校验和当前认证任务所需的短期字段，不进入持久化存储。
struct LpaActivationCode {
    std::string smdpHost;
    std::string matchingId;

    LpaActivationCode() = default;
    LpaActivationCode(const LpaActivationCode&) = delete;
    LpaActivationCode& operator=(const LpaActivationCode&) = delete;
    LpaActivationCode(LpaActivationCode&& other) noexcept;
    LpaActivationCode& operator=(LpaActivationCode&& other) noexcept;

    void clear_sensitive();
    ~LpaActivationCode();
};

// 解析 SGP.22 Activation Code v1 的受控输入形式：LPA:1$... 或 1$...。
// 失败消息只描述字段类别和边界，不回显输入内容。
bool idf_lpa_parse_activation_code(const std::string& input,
                                   LpaActivationCode& out,
                                   std::string& message);

// 仅返回可用于 UI 预览的脱敏 Matching ID。
std::string idf_lpa_mask_matching_id(const std::string& matching_id);

// 对短期敏感字符串做显式清零并释放容量。
void idf_lpa_clear_sensitive(std::string& value);

struct LpaAuthenticationResult {
    // true 表示服务器要求 Confirmation Code；Gate 3 不会因此继续写卡。
    bool confirmationCodeRequired = false;
};

// 执行 SGP.22 v2.7 的 InitiateAuthentication、AuthenticateServer、AuthenticateClient。
// 成功只表示服务器认证链完成，不表示 Profile 已下载或写入 eUICC。
// 认证对象、transactionId 和证书均只在函数生命周期内存在于 RAM。
esp_err_t idf_lpa_run_authentication(const LpaActivationCode& activation_code,
                                     LpaAuthenticationResult& result,
                                     std::string& safe_message);

// 完成后台下载链。回调只用于把阶段和 Confirmation Code
// 接回现有 idf_web job，不在 HTTP handler 中执行协议。
struct LpaDownloadObserver {
    void* context = nullptr;
    // 本次 install-start 是否仅兼容缺失 X-Admin-Protocol 响应头。
    bool allow_missing_admin_protocol = false;
    void (*set_phase)(void* context, const char* phase, const char* message) = nullptr;
    esp_err_t (*wait_confirmation_code)(void* context,
                                        std::string& code,
                                        std::string& safe_message) = nullptr;
};

struct LpaDownloadStats {
    size_t bppEncodedBytes = 0;
    size_t bppDecodedBytes = 0;
    size_t freeHeapAtStart = 0;
    size_t freeHeapAtEnd = 0;
    size_t minimumFreeHeap = 0;
    size_t largestFreeBlock = 0;
};

// 成功表示 Profile 已通过 LoadBoundProfilePackage、HandleNotification 和
// RemoveNotificationFromList；不表示已自动启用。所有敏感字段只在本次调用中存在。
esp_err_t idf_lpa_run_profile_download(const LpaActivationCode& activation_code,
                                       const LpaDownloadObserver& observer,
                                       LpaDownloadStats& stats,
                                       std::string& safe_message);
