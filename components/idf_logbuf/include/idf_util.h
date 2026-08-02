#pragma once

#include <stdint.h>

#include <string>

// 通用小工具集合：原先各组件各自复制一份，统一收拢到 idf_logbuf(几乎所有组件都已依赖)。

// 将 value 按 JSON 字符串规则转义后追加到 out(反斜杠/引号/换行/制表符，其余控制字符转 \u00xx)
void idf_util_json_escape_append(std::string& out, const std::string& value);

// 去掉首尾空白(isspace 语义)并返回副本，原串不变
std::string idf_util_trim_copy(const std::string& value);

// epoch 秒 → "YYYY-MM-DD HH:MM:SS" 本地时间；时间未同步(epoch 过小)返回空串
std::string idf_util_format_epoch_local(uint32_t epoch, int tz_offset_min);
