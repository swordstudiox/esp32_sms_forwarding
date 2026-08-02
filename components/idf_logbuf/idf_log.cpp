#include "idf_log.h"
#include "idf_util.h"

#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <array>
#include <atomic>

#include "esp_attr.h"
#include "esp_system.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "nvs.h"
#include "nvs_flash.h"

static constexpr size_t LOG_RING_SIZE = 120;
static constexpr size_t LOG_LINE_MAX = 192;

static SemaphoreHandle_t s_log_mutex = nullptr;
static std::array<std::string, LOG_RING_SIZE> s_lines;
static uint32_t s_seq = 0;
// s_seq 的无锁镜像：锁竞争超时的降级路径也能返回真实序号。
// 返回 seq=0 会被网页当成"设备重启过"，触发清屏+全量重放
static std::atomic<uint32_t> s_seq_mirror{0};
static size_t s_count = 0;
static size_t s_next = 0;

// ---- 上次运行日志(重启前镜像) ----
// 日志同时写入一块 .noinit RAM 字节环。软件复位/看门狗复位/panic 都不会清
// 这块内存，开机时把上一次会话的日志取出来，崩溃前的最后动作就能看到。
// 掉电(上电复位)会丢 RAM，所以异常复位时再把它写进 smsdata NVS 分区兜底。
static constexpr size_t PREV_RING_SIZE = 8192;
static constexpr uint32_t PREV_MAGIC = 0x4C4F4752;  // 'LOGR'

struct NoinitLogRing {
    uint32_t magic;
    uint32_t head;   // 下一个写入位置
    uint32_t used;   // 有效字节数(<= PREV_RING_SIZE)
    uint32_t check;  // 简单一致性校验，防止上电后的随机内容被当成日志
    char buf[PREV_RING_SIZE];
};

static __NOINIT_ATTR NoinitLogRing s_prev_ring;
static bool s_prev_ring_ready = false;   // 捕获完成前不写入，避免污染上一会话内容
static std::string s_prev_log;           // 开机时提取出的上次日志(含头部说明)
static bool s_prev_deferred_save = false;
static bool s_prev_deferred_started = false;
static bool s_prev_flash_load_tried = false;

// smsdata 为 640KB 独立 NVS 分区(短信留存也在用)，写入频率仅为每次异常复位一次
static constexpr const char* PREV_NVS_PART = "smsdata";
static constexpr const char* PREV_NVS_NS = "prevlog";
static constexpr const char* PREV_NVS_KEY = "log";

static uint32_t prev_ring_checksum()
{
    return PREV_MAGIC ^ s_prev_ring.head ^ (s_prev_ring.used << 8) ^ 0xA5A5A5A5u;
}

static bool prev_ring_valid()
{
    return s_prev_ring.magic == PREV_MAGIC &&
           s_prev_ring.head < PREV_RING_SIZE &&
           s_prev_ring.used <= PREV_RING_SIZE &&
           s_prev_ring.check == prev_ring_checksum();
}

static void prev_ring_reset()
{
    s_prev_ring.magic = PREV_MAGIC;
    s_prev_ring.head = 0;
    s_prev_ring.used = 0;
    s_prev_ring.check = prev_ring_checksum();
}

// 追加到 noinit 环。先写数据再更新元信息：崩溃打断时元信息仍描述旧内容，
// 最多丢这一行，不会让整个环失效
static void prev_ring_append(const char* data, size_t len)
{
    if (!s_prev_ring_ready || len == 0) return;
    if (len > PREV_RING_SIZE) {
        data += len - PREV_RING_SIZE;
        len = PREV_RING_SIZE;
    }
    size_t head = s_prev_ring.head;
    size_t first = PREV_RING_SIZE - head;
    if (first > len) first = len;
    memcpy(s_prev_ring.buf + head, data, first);
    if (len > first) memcpy(s_prev_ring.buf, data + first, len - first);
    s_prev_ring.head = (head + len) % PREV_RING_SIZE;
    s_prev_ring.used += len;
    if (s_prev_ring.used > PREV_RING_SIZE) s_prev_ring.used = PREV_RING_SIZE;
    s_prev_ring.check = prev_ring_checksum();
}

static const char* reset_reason_text(esp_reset_reason_t reason)
{
    switch (reason) {
        case ESP_RST_POWERON: return "上电复位";
        case ESP_RST_EXT: return "外部复位";
        case ESP_RST_SW: return "软件重启";
        case ESP_RST_PANIC: return "程序崩溃(panic)";
        case ESP_RST_INT_WDT: return "中断看门狗";
        case ESP_RST_TASK_WDT: return "任务看门狗";
        case ESP_RST_WDT: return "其他看门狗";
        case ESP_RST_DEEPSLEEP: return "深度睡眠唤醒";
        case ESP_RST_BROWNOUT: return "欠压复位";
        case ESP_RST_SDIO: return "SDIO 复位";
        case ESP_RST_USB: return "USB/串口复位";
        case ESP_RST_JTAG: return "JTAG 复位";
        case ESP_RST_EFUSE: return "eFuse 错误复位";
        case ESP_RST_PWR_GLITCH: return "电源毛刺复位";
        case ESP_RST_CPU_LOCKUP: return "CPU 锁死复位";
        default: return "未知";
    }
}

static bool reset_reason_abnormal(esp_reset_reason_t reason)
{
    switch (reason) {
        case ESP_RST_PANIC:
        case ESP_RST_INT_WDT:
        case ESP_RST_TASK_WDT:
        case ESP_RST_WDT:
        case ESP_RST_BROWNOUT:
        case ESP_RST_PWR_GLITCH:
        case ESP_RST_CPU_LOCKUP:
            return true;
        default:
            return false;
    }
}

static esp_err_t prev_log_prepare_nvs()
{
    esp_err_t err = nvs_flash_init_partition(PREV_NVS_PART);
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        // smsdata 是短信留存分区，不能在日志模块里擅自擦除；交给收件箱初始化流程处理
        return err;
    }
    if (err == ESP_ERR_INVALID_STATE) return ESP_OK;
    return err;
}

// 从 NVS 读上一次异常复位存下的日志(设备掉过电、RAM 镜像已丢时的兜底)
static bool prev_log_load_from_nvs(std::string& out)
{
    if (prev_log_prepare_nvs() != ESP_OK) return false;
    nvs_handle_t handle = 0;
    if (nvs_open_from_partition(PREV_NVS_PART, PREV_NVS_NS, NVS_READONLY, &handle) != ESP_OK) {
        return false;
    }
    size_t len = 0;
    bool ok = false;
    if (nvs_get_blob(handle, PREV_NVS_KEY, nullptr, &len) == ESP_OK && len > 0 && len <= PREV_RING_SIZE + 1024) {
        out.resize(len);
        ok = nvs_get_blob(handle, PREV_NVS_KEY, &out[0], &len) == ESP_OK;
        if (!ok) out.clear();
    }
    nvs_close(handle);
    return ok;
}

static void prev_log_save_to_nvs(const std::string& text)
{
    if (text.empty() || prev_log_prepare_nvs() != ESP_OK) return;
    nvs_handle_t handle = 0;
    if (nvs_open_from_partition(PREV_NVS_PART, PREV_NVS_NS, NVS_READWRITE, &handle) != ESP_OK) {
        return;
    }
    if (nvs_set_blob(handle, PREV_NVS_KEY, text.data(), text.size()) == ESP_OK) {
        nvs_commit(handle);
    }
    nvs_close(handle);
}

static void prev_log_set(std::string text)
{
    if (!s_log_mutex) {
        s_prev_log = std::move(text);
        return;
    }
    if (xSemaphoreTake(s_log_mutex, pdMS_TO_TICKS(500)) != pdTRUE) return;
    s_prev_log = std::move(text);
    xSemaphoreGive(s_log_mutex);
}

static std::string prev_log_get()
{
    if (!s_log_mutex || xSemaphoreTake(s_log_mutex, pdMS_TO_TICKS(500)) != pdTRUE) return std::string();
    std::string out = s_prev_log;
    xSemaphoreGive(s_log_mutex);
    return out;
}

static void prev_log_deferred_task(void*)
{
    // 启动路径只做 RAM 捕获；异常复位后的 Flash 保存延后，避免卡在开机早期。
    vTaskDelay(pdMS_TO_TICKS(15000));

    if (s_prev_deferred_save) {
        std::string snapshot = prev_log_get();
        if (!snapshot.empty()) {
            prev_log_save_to_nvs(snapshot);
            idf_log_line("上次运行日志已后台保存到 Flash");
        }
    }

    vTaskDelete(nullptr);
}

static void prev_log_start_deferred_save()
{
    s_prev_deferred_save = true;
    if (s_prev_deferred_started) return;
    s_prev_deferred_started = true;
    BaseType_t ok = xTaskCreate(prev_log_deferred_task, "prev_log_save", 6144, nullptr, 1, nullptr);
    if (ok != pdPASS) {
        s_prev_deferred_started = false;
        idf_log_line("上次运行日志后台任务启动失败");
    }
}

// 开机时执行一次：把上一会话留在 noinit 环里的日志取出来，异常复位再落盘
static void prev_log_capture()
{
    esp_reset_reason_t reason = esp_reset_reason();
    bool abnormal = reset_reason_abnormal(reason);

    std::string body;
    bool from_ram = prev_ring_valid() && s_prev_ring.used > 0;
    if (from_ram) {
        size_t used = s_prev_ring.used;
        size_t start = (s_prev_ring.head + PREV_RING_SIZE - used) % PREV_RING_SIZE;
        body.reserve(used);
        for (size_t i = 0; i < used; ++i) {
            char ch = s_prev_ring.buf[(start + i) % PREV_RING_SIZE];
            // 极小概率崩在环写入中途，个别字节可能是半行残留；替换控制字符保证可读
            if (ch != '\n' && static_cast<unsigned char>(ch) < 0x20) ch = ' ';
            body += ch;
        }
        // 环满时最旧一行通常被截半，去掉第一个换行前的残段
        if (used == PREV_RING_SIZE) {
            size_t nl = body.find('\n');
            if (nl != std::string::npos) body.erase(0, nl + 1);
        }
    }
    prev_ring_reset();
    s_prev_ring_ready = true;

    if (from_ram) {
        std::string text = "===== 上次运行日志 =====\n";
        text += "本次复位原因: ";
        text += reset_reason_text(reason);
        char num[16];
        snprintf(num, sizeof(num), " (%d)\n", static_cast<int>(reason));
        text += num;
        if (abnormal) {
            text += "异常复位日志将在启动完成后后台保存到 Flash；完整崩溃转储可在日志页下载。\n";
        }
        text += "------------------------\n";
        text += body;
        prev_log_set(std::move(text));
        // 只有异常复位才写 Flash，且必须放到后台：启动期 Flash/NVS 操作可能引发看门狗连环重启
        if (abnormal) prev_log_start_deferred_save();
    }

    idf_logf("本次启动复位原因: %s (%d)%s", reset_reason_text(reason), static_cast<int>(reason),
             prev_log_get().empty() ? "" : "，上次日志已保留(日志页可查看)");
}

static void ensure_init()
{
    if (!s_log_mutex) s_log_mutex = xSemaphoreCreateMutex();
}

void idf_log_init(void)
{
    ensure_init();
    static bool s_captured = false;
    if (!s_captured) {
        s_captured = true;
        prev_log_capture();
    }
}

void idf_log_line(const char* line)
{
    ensure_init();
    if (!s_log_mutex || !line) return;

    std::string item(line);
    if (item.size() > LOG_LINE_MAX) {
        size_t end = LOG_LINE_MAX - 3;
        // 退到 UTF-8 字符边界：日志多为中文(3 字节/字)，硬截会产生乱码
        while (end > 0 && (static_cast<unsigned char>(item[end]) & 0xC0) == 0x80) --end;
        item.resize(end);
        item += "...";
    }

    if (xSemaphoreTake(s_log_mutex, pdMS_TO_TICKS(500)) != pdTRUE) return;
    prev_ring_append(item.data(), item.size());
    prev_ring_append("\n", 1);
    s_lines[s_next] = std::move(item);
    s_next = (s_next + 1) % LOG_RING_SIZE;
    if (s_count < LOG_RING_SIZE) ++s_count;
    ++s_seq;
    s_seq_mirror.store(s_seq, std::memory_order_relaxed);
    xSemaphoreGive(s_log_mutex);
}

void idf_logf(const char* fmt, ...)
{
    char buf[LOG_LINE_MAX + 1];
    va_list ap;
    va_start(ap, fmt);
    int ret = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (ret > static_cast<int>(LOG_LINE_MAX)) {
        // vsnprintf 截断可能落在多字节字符中间；退到 UTF-8 边界，避免输出乱码
        size_t end = LOG_LINE_MAX;
        size_t p = end;
        while (p > 0 && (static_cast<unsigned char>(buf[p - 1]) & 0xC0) == 0x80) --p;
        if (p > 0) {
            unsigned char lead = static_cast<unsigned char>(buf[p - 1]);
            size_t need = (lead >= 0xF0) ? 4 : (lead >= 0xE0) ? 3 : (lead >= 0xC0) ? 2 : 1;
            if (need > 1 && p - 1 + need > end) end = p - 1;  // 末字符不完整，整个去掉
        }
        buf[end] = '\0';
    }
    idf_log_line(buf);
}

std::string idf_log_json_since(uint32_t since)
{
    ensure_init();
    std::string out;
    out.reserve(2048);

    if (!s_log_mutex || xSemaphoreTake(s_log_mutex, pdMS_TO_TICKS(500)) != pdTRUE) {
        // 返回最近已知序号而非 0：seq 回退会被网页误判为设备重启，清屏重放
        char fallback[48];
        snprintf(fallback, sizeof(fallback), "{\"seq\":%" PRIu32 ",\"lines\":[]}",
                 s_seq_mirror.load(std::memory_order_relaxed));
        return fallback;
    }

    uint32_t seq = s_seq;
    size_t count = s_count;
    size_t start = (s_next + LOG_RING_SIZE - count) % LOG_RING_SIZE;
    uint32_t oldest = seq >= count ? seq - static_cast<uint32_t>(count) + 1 : 1;
    // 客户端游标比当前序号还大 = 设备已重启、序号从头计。从 0 重放，
    // 否则网页要等新日志追上旧游标才恢复显示
    if (since > seq) since = 0;

    char head[48];
    snprintf(head, sizeof(head), "{\"seq\":%" PRIu32 ",\"lines\":[", seq);
    out += head;
    bool first = true;
    for (size_t i = 0; i < count; ++i) {
        uint32_t line_seq = oldest + static_cast<uint32_t>(i);
        if (line_seq <= since) continue;
        if (!first) out += ",";
        first = false;
        out += "\"";
        idf_util_json_escape_append(out, s_lines[(start + i) % LOG_RING_SIZE]);
        out += "\"";
    }
    out += "]}";
    xSemaphoreGive(s_log_mutex);
    return out;
}

std::string idf_log_text_dump(void)
{
    ensure_init();
    std::string out;
    out.reserve(4096);
    if (!s_log_mutex || xSemaphoreTake(s_log_mutex, pdMS_TO_TICKS(500)) != pdTRUE) return out;

    size_t count = s_count;
    size_t start = (s_next + LOG_RING_SIZE - count) % LOG_RING_SIZE;
    for (size_t i = 0; i < count; ++i) {
        out += s_lines[(start + i) % LOG_RING_SIZE];
        out += "\r\n";
    }
    xSemaphoreGive(s_log_mutex);
    return out;
}

bool idf_log_has_prev(void)
{
    return !prev_log_get().empty();
}

std::string idf_log_prev_dump(void)
{
    std::string out = prev_log_get();
    if (!out.empty() || s_prev_flash_load_tried) return out;

    s_prev_flash_load_tried = true;
    std::string saved;
    if (prev_log_load_from_nvs(saved) && !saved.empty()) {
        out = "(本次启动未读取 Flash；以下是在用户请求时读取的最近一次异常复位日志)\n";
        out += saved;
        prev_log_set(out);
    }
    return out;
}
