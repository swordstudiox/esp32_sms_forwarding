#pragma once

#include <string>
#include <vector>

#include "esp_err.h"

struct IdfEsimProfile {
    std::string iccid;
    std::string isdpAid;
    std::string state;
    std::string nickname;
    std::string serviceProvider;
    std::string profileName;
    std::string profileClass;
};

// 注册模组"卡身份变化"钩子：SIM 热插拔/换卡后失效 EID 缓存。app_main 启动时调用一次
void idf_esim_init(void);
esp_err_t idf_esim_get_eid(std::string& eid, std::string& message);
esp_err_t idf_esim_list_profiles(std::vector<IdfEsimProfile>& profiles,
                                 std::string& eid,
                                 std::string& message);
// 启停/切换一律走 SGP.22 无 refreshFlag 模式，成功后自动请求模组软重启复位 UICC，
// 新 Profile 在模组重启附着后生效(issue #17)。调用方无需再做任何刷新动作。
esp_err_t idf_esim_enable_profile(const std::string& identifier, std::string& message);
esp_err_t idf_esim_disable_profile(const std::string& identifier, std::string& message);
esp_err_t idf_esim_delete_profile(const std::string& identifier,
                                  std::string& message);
esp_err_t idf_esim_set_nickname(const std::string& identifier,
                                const std::string& nickname,
                                std::string& message);
esp_err_t idf_esim_switch_profile(const std::string& identifier, std::string& message);
std::string idf_esim_mask_profile_id(const std::string& identifier);
// 判断一个 Profile 是否匹配用户输入的标识（ICCID/ISD-P AID/昵称/名称/运营商名，忽略大小写）
bool idf_esim_profile_matches(const IdfEsimProfile& profile, const std::string& identifier);
