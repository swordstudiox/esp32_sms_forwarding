#include "idf_inbox.h"

#include <stdio.h>
#include <time.h>

#include <array>
#include <algorithm>
#include <vector>

#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "idf_util.h"
#include "nvs.h"
#include "nvs_flash.h"

static const char* TAG = "idf_inbox";

// 收件箱只是网页速览缓存，完整内容已转发到推送/邮件。
// 50×1024B 的旧配额最坏 ~73KB 堆，会挤掉 TLS 握手所需的 ~40KB 连续内存。
static constexpr size_t INBOX_MAX = 50;
static constexpr size_t SENT_MAX = 10;
static constexpr size_t BODY_MAX = 320;

// 短信本地留存：独立 NVS 分区(partitions_ota_1m6.csv 里的 smsdata，640KB)。
// 每条短信存成一个 key(m<id>/t<id>)：新增写一条、转发完改一条、淘汰/删除擦一条，
// 从不整块重写；NVS 自带磨损均衡+掉电原子，本量级(≤60 条小 blob)对 flash 寿命无感。
static constexpr const char* SMS_NVS_PART = "smsdata";
static constexpr const char* NS_INBOX = "inbox";
static constexpr const char* NS_SENT = "sent";
static constexpr uint8_t BLOB_VERSION = 1;

struct InboxSlot : IdfInboxEntry {
    bool deleted = false;
};

static SemaphoreHandle_t s_mutex = nullptr;
static std::array<InboxSlot, INBOX_MAX> s_inbox;
static std::array<IdfSentEntry, SENT_MAX> s_sent;
static size_t s_inbox_head = 0;
static size_t s_inbox_filled = 0;
static uint32_t s_inbox_seq = 0;
static size_t s_sent_head = 0;
static size_t s_sent_filled = 0;
static uint32_t s_sent_seq = 0;

static bool s_nvs_ready = false;
static nvs_handle_t s_inbox_nvs = 0;
static nvs_handle_t s_sent_nvs = 0;

static void ensure_init()
{
    if (!s_mutex) s_mutex = xSemaphoreCreateMutex();
}

// ---- 持久化：序列化/反序列化 + NVS 读写(全部在持锁上下文内调用) ----
static void blob_put_u8(std::string& b, uint8_t v) { b.push_back(static_cast<char>(v)); }
static void blob_put_u16(std::string& b, uint16_t v) { b.push_back(static_cast<char>(v & 0xff)); b.push_back(static_cast<char>(v >> 8)); }
static void blob_put_u32(std::string& b, uint32_t v)
{
    for (int i = 0; i < 4; ++i) b.push_back(static_cast<char>((v >> (i * 8)) & 0xff));
}
static void blob_put_str(std::string& b, const std::string& s, bool u16len)
{
    size_t n = u16len ? std::min<size_t>(s.size(), 0xffff) : std::min<size_t>(s.size(), 0xff);
    if (u16len) blob_put_u16(b, static_cast<uint16_t>(n)); else blob_put_u8(b, static_cast<uint8_t>(n));
    b.append(s.data(), n);
}

struct BlobReader {
    const uint8_t* p; size_t n; size_t i = 0; bool ok = true;
    uint8_t u8() { if (i + 1 > n) { ok = false; return 0; } return p[i++]; }
    uint16_t u16() { uint16_t a = u8(); uint16_t b = u8(); return static_cast<uint16_t>(a | (b << 8)); }
    uint32_t u32() { uint32_t v = 0; for (int k = 0; k < 4; ++k) v |= static_cast<uint32_t>(u8()) << (k * 8); return v; }
    std::string str(bool u16len) {
        size_t len = u16len ? u16() : u8();
        if (!ok || i + len > n) { ok = false; return {}; }
        std::string s(reinterpret_cast<const char*>(p + i), len); i += len; return s;
    }
};

static void inbox_key(char* buf, size_t sz, uint32_t id) { snprintf(buf, sz, "m%u", static_cast<unsigned>(id)); }
static void sent_key(char* buf, size_t sz, uint32_t id) { snprintf(buf, sz, "t%u", static_cast<unsigned>(id)); }

static void persist_inbox_entry(const InboxSlot& e)
{
    if (!s_nvs_ready) return;
    std::string blob;
    blob.reserve(16 + e.sender.size() + e.ts.size() + e.text.size());
    blob_put_u8(blob, BLOB_VERSION);
    blob_put_u8(blob, e.forwarded ? 1 : 0);
    blob_put_u32(blob, e.id);
    blob_put_u32(blob, e.recvEpoch);
    blob_put_str(blob, e.sender, false);
    blob_put_str(blob, e.ts, false);
    blob_put_str(blob, e.text, true);
    char key[16];
    inbox_key(key, sizeof(key), e.id);
    if (nvs_set_blob(s_inbox_nvs, key, blob.data(), blob.size()) == ESP_OK) {
        nvs_commit(s_inbox_nvs);
    }
}

static void erase_inbox_entry(uint32_t id)
{
    if (!s_nvs_ready || id == 0) return;
    char key[16];
    inbox_key(key, sizeof(key), id);
    if (nvs_erase_key(s_inbox_nvs, key) == ESP_OK) nvs_commit(s_inbox_nvs);
}

static void persist_sent_entry(const IdfSentEntry& e)
{
    if (!s_nvs_ready) return;
    std::string blob;
    blob.reserve(12 + e.target.size() + e.text.size());
    blob_put_u8(blob, BLOB_VERSION);
    blob_put_u8(blob, e.ok ? 1 : 0);
    blob_put_u32(blob, e.id);
    blob_put_u32(blob, e.sentEpoch);
    blob_put_str(blob, e.target, false);
    blob_put_str(blob, e.text, true);
    char key[16];
    sent_key(key, sizeof(key), e.id);
    if (nvs_set_blob(s_sent_nvs, key, blob.data(), blob.size()) == ESP_OK) {
        nvs_commit(s_sent_nvs);
    }
}

static void erase_sent_entry(uint32_t id)
{
    if (!s_nvs_ready || id == 0) return;
    char key[16];
    sent_key(key, sizeof(key), id);
    if (nvs_erase_key(s_sent_nvs, key) == ESP_OK) nvs_commit(s_sent_nvs);
}

// 遍历命名空间下所有 blob，逐个 get 出原始字节，回调解析(返回是否有效)。
// 超上限的最旧项擦除交给调用方；解析失败/超长的坏 blob 在此就地回收——
// 它们不在正常淘汰路径上，不清理会永久占用 smsdata 分区空间。
template <typename Parse>
static void for_each_blob(const char* ns, nvs_handle_t handle, Parse parse)
{
    std::vector<std::string> bad_keys;
    nvs_iterator_t it = nullptr;
    esp_err_t err = nvs_entry_find(SMS_NVS_PART, ns, NVS_TYPE_BLOB, &it);
    while (err == ESP_OK && it) {
        nvs_entry_info_t info;
        nvs_entry_info(it, &info);
        size_t len = 0;
        bool valid = false;
        if (nvs_get_blob(handle, info.key, nullptr, &len) == ESP_OK && len > 0 && len < 2048) {
            std::vector<uint8_t> buf(len);
            if (nvs_get_blob(handle, info.key, buf.data(), &len) == ESP_OK) {
                valid = parse(buf.data(), len);
            }
        }
        if (!valid) bad_keys.push_back(info.key);
        err = nvs_entry_next(&it);
    }
    if (it) nvs_release_iterator(it);
    if (!bad_keys.empty()) {
        for (const auto& k : bad_keys) nvs_erase_key(handle, k.c_str());
        nvs_commit(handle);
    }
}

static void load_inbox_from_flash()
{
    std::vector<IdfInboxEntry> items;
    for_each_blob(NS_INBOX, s_inbox_nvs, [&](const uint8_t* p, size_t n) -> bool {
        BlobReader r{p, n};
        uint8_t ver = r.u8();
        bool forwarded = r.u8() != 0;
        IdfInboxEntry e;
        e.id = r.u32();
        e.recvEpoch = r.u32();
        e.sender = r.str(false);
        e.ts = r.str(false);
        e.text = r.str(true);
        e.forwarded = forwarded;
        if (ver != BLOB_VERSION || !r.ok || e.id == 0) return false;
        items.push_back(std::move(e));
        return true;
    });
    std::sort(items.begin(), items.end(),
              [](const IdfInboxEntry& a, const IdfInboxEntry& b) { return a.id < b.id; });
    // 超出上限的最旧项(可能来自更大留存的旧固件)从 flash 抹掉，保持 NVS 与 RAM 一致
    while (items.size() > INBOX_MAX) {
        erase_inbox_entry(items.front().id);
        items.erase(items.begin());
    }
    // 按 id 升序(旧→新)填物理槽 0..n-1，head=n%MAX，与环形迭代语义一致
    for (size_t i = 0; i < items.size(); ++i) {
        static_cast<IdfInboxEntry&>(s_inbox[i]) = items[i];
        s_inbox[i].deleted = false;
        if (items[i].id > s_inbox_seq) s_inbox_seq = items[i].id;
    }
    s_inbox_filled = items.size();
    s_inbox_head = s_inbox_filled % INBOX_MAX;
}

static void load_sent_from_flash()
{
    std::vector<IdfSentEntry> items;
    for_each_blob(NS_SENT, s_sent_nvs, [&](const uint8_t* p, size_t n) -> bool {
        BlobReader r{p, n};
        uint8_t ver = r.u8();
        bool ok = r.u8() != 0;
        IdfSentEntry e;
        e.id = r.u32();
        e.sentEpoch = r.u32();
        e.target = r.str(false);
        e.text = r.str(true);
        e.ok = ok;
        if (ver != BLOB_VERSION || !r.ok || e.id == 0) return false;
        items.push_back(std::move(e));
        return true;
    });
    std::sort(items.begin(), items.end(),
              [](const IdfSentEntry& a, const IdfSentEntry& b) { return a.id < b.id; });
    while (items.size() > SENT_MAX) {
        erase_sent_entry(items.front().id);
        items.erase(items.begin());
    }
    for (size_t i = 0; i < items.size(); ++i) {
        s_sent[i] = items[i];
        if (items[i].id > s_sent_seq) s_sent_seq = items[i].id;
    }
    s_sent_filled = items.size();
    s_sent_head = s_sent_filled % SENT_MAX;
}

static void load_from_flash()
{
    load_inbox_from_flash();
    load_sent_from_flash();
    if (s_inbox_filled || s_sent_filled) {
        ESP_LOGI(TAG, "从 flash 恢复短信: 收件箱 %u 条, 发件箱 %u 条",
                 static_cast<unsigned>(s_inbox_filled), static_cast<unsigned>(s_sent_filled));
    }
}

static void init_persistence()
{
    esp_err_t err = nvs_flash_init_partition(SMS_NVS_PART);
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        nvs_flash_erase_partition(SMS_NVS_PART);
        err = nvs_flash_init_partition(SMS_NVS_PART);
    }
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "smsdata 分区初始化失败(%s)，短信留存降级为纯内存", esp_err_to_name(err));
        return;
    }
    esp_err_t inbox_err = nvs_open_from_partition(SMS_NVS_PART, NS_INBOX, NVS_READWRITE, &s_inbox_nvs);
    esp_err_t sent_err = inbox_err == ESP_OK
        ? nvs_open_from_partition(SMS_NVS_PART, NS_SENT, NVS_READWRITE, &s_sent_nvs)
        : inbox_err;
    if (inbox_err != ESP_OK || sent_err != ESP_OK) {
        if (inbox_err == ESP_OK) {
            nvs_close(s_inbox_nvs);
            s_inbox_nvs = 0;
        }
        if (sent_err == ESP_OK) {
            nvs_close(s_sent_nvs);
            s_sent_nvs = 0;
        }
        ESP_LOGW(TAG, "smsdata 命名空间打开失败，短信留存降级为纯内存");
        return;
    }
    s_nvs_ready = true;
    load_from_flash();
}

static std::string truncate_body(const char* text)
{
    std::string out = text ? text : "";
    if (out.size() > BODY_MAX) {
        size_t end = BODY_MAX;
        // 退到 UTF-8 字符边界，避免截出半个汉字变成乱码
        while (end > 0 && (static_cast<unsigned char>(out[end]) & 0xC0) == 0x80) --end;
        out.resize(end);
        out += "...";
    }
    return out;
}

static void json_prop(std::string& out, const char* key, const std::string& value)
{
    out += "\"";
    out += key;
    out += "\":\"";
    idf_util_json_escape_append(out, value);
    out += "\"";
}

void idf_inbox_init(void)
{
    ensure_init();
    if (s_mutex && xSemaphoreTake(s_mutex, pdMS_TO_TICKS(1000)) == pdTRUE) {
        init_persistence();
        xSemaphoreGive(s_mutex);
    }
}

uint32_t idf_inbox_add(const char* sender, const char* text, const char* ts)
{
    ensure_init();
    // 收到短信后入库不能因为网页正在读/flash 正在提交而放弃；SMS 任务本来就是串行处理。
    if (!s_mutex || xSemaphoreTake(s_mutex, portMAX_DELAY) != pdTRUE) return 0;

    InboxSlot& e = s_inbox[s_inbox_head];
    // 环满时该物理槽即将覆盖最旧短信：先把它的 flash key 擦掉，保持 NVS 只存活动条目
    uint32_t evict_id = (s_inbox_filled == INBOX_MAX && !e.deleted) ? e.id : 0;
    e.id = ++s_inbox_seq;
    e.recvEpoch = static_cast<uint32_t>(time(nullptr));
    e.sender = sender ? sender : "";
    e.ts = ts ? ts : "";
    e.text = truncate_body(text);
    e.forwarded = false;
    e.deleted = false;

    s_inbox_head = (s_inbox_head + 1) % INBOX_MAX;
    if (s_inbox_filled < INBOX_MAX) ++s_inbox_filled;
    uint32_t id = e.id;
    if (evict_id) erase_inbox_entry(evict_id);
    persist_inbox_entry(e);
    xSemaphoreGive(s_mutex);
    return id;
}

void idf_inbox_set_forwarded(uint32_t id, bool forwarded)
{
    if (id == 0) return;
    ensure_init();
    if (!s_mutex || xSemaphoreTake(s_mutex, portMAX_DELAY) != pdTRUE) return;
    for (size_t i = 0; i < s_inbox_filled; ++i) {
        if (s_inbox[i].id == id && !s_inbox[i].deleted) {
            if (s_inbox[i].forwarded != forwarded) {
                s_inbox[i].forwarded = forwarded;
                persist_inbox_entry(s_inbox[i]);  // 更新落盘的转发标记(重启后仍显示"已处理")
            }
            break;
        }
    }
    xSemaphoreGive(s_mutex);
}

void idf_inbox_mark_forwarded(uint32_t id)
{
    idf_inbox_set_forwarded(id, true);
}

size_t idf_inbox_count(void)
{
    // 读侧(本函数及以下各读取/JSON 接口)一律阻塞等锁：写侧最长持锁到两次
    // nvs_commit 结束(数百 ms 级)。带超时的版本在该窗口内会把收件箱误报成"空"
    ensure_init();
    if (!s_mutex || xSemaphoreTake(s_mutex, portMAX_DELAY) != pdTRUE) return 0;
    size_t count = 0;
    for (size_t i = 0; i < s_inbox_filled; ++i) {
        if (!s_inbox[i].deleted) ++count;
    }
    xSemaphoreGive(s_mutex);
    return count;
}

bool idf_inbox_get_by_id(uint32_t id, IdfInboxEntry& out)
{
    if (id == 0) return false;
    ensure_init();
    if (!s_mutex || xSemaphoreTake(s_mutex, portMAX_DELAY) != pdTRUE) return false;
    bool ok = false;
    for (size_t i = 0; i < s_inbox_filled; ++i) {
        if (s_inbox[i].id == id && !s_inbox[i].deleted) {
            out.id = s_inbox[i].id;
            out.recvEpoch = s_inbox[i].recvEpoch;
            out.sender = s_inbox[i].sender;
            out.ts = s_inbox[i].ts;
            out.text = s_inbox[i].text;
            out.forwarded = s_inbox[i].forwarded;
            ok = true;
            break;
        }
    }
    xSemaphoreGive(s_mutex);
    return ok;
}

bool idf_inbox_delete(uint32_t id)
{
    if (id == 0) return false;
    ensure_init();
    if (!s_mutex || xSemaphoreTake(s_mutex, portMAX_DELAY) != pdTRUE) return false;
    bool ok = false;
    for (size_t i = 0; i < s_inbox_filled; ++i) {
        if (s_inbox[i].id == id && !s_inbox[i].deleted) {
            s_inbox[i].deleted = true;
            s_inbox[i].sender.clear();
            s_inbox[i].ts.clear();
            s_inbox[i].text.clear();
            erase_inbox_entry(id);  // 同步从 flash 抹掉
            ok = true;
            break;
        }
    }
    xSemaphoreGive(s_mutex);
    return ok;
}

void idf_sent_add(const char* target, const char* text, bool ok)
{
    ensure_init();
    if (!s_mutex || xSemaphoreTake(s_mutex, portMAX_DELAY) != pdTRUE) return;

    IdfSentEntry& e = s_sent[s_sent_head];
    uint32_t evict_id = (s_sent_filled == SENT_MAX && e.id != 0) ? e.id : 0;
    e.id = ++s_sent_seq;
    e.sentEpoch = static_cast<uint32_t>(time(nullptr));
    e.target = target ? target : "";
    e.text = truncate_body(text);
    e.ok = ok;

    s_sent_head = (s_sent_head + 1) % SENT_MAX;
    if (s_sent_filled < SENT_MAX) ++s_sent_filled;
    if (evict_id) erase_sent_entry(evict_id);
    persist_sent_entry(e);
    xSemaphoreGive(s_mutex);
}

std::string idf_inbox_json(bool sent_box, int limit)
{
    // 单次持锁直接遍历环形缓冲：避免"取数量、再逐条取"期间新短信入库导致的
    // 条目错位/重复，也把 51 次锁往返 + O(n²) 扫描降为一次 O(n)
    ensure_init();
    if (limit < 0) limit = 0;

    std::string out;
    out += "[";
    if (!s_mutex || xSemaphoreTake(s_mutex, portMAX_DELAY) != pdTRUE) {
        out += "]";
        return out;
    }

    size_t emitted = 0;
    char buf[80];
    if (sent_box) {
        out.reserve(64 + std::min<size_t>(s_sent_filled, limit ? limit : s_sent_filled) * 160);
        for (size_t k = 0; k < s_sent_filled; ++k) {
            if (limit > 0 && emitted >= static_cast<size_t>(limit)) break;
            size_t idx = (s_sent_head + SENT_MAX - 1 - k) % SENT_MAX;
            const IdfSentEntry& e = s_sent[idx];
            if (emitted) out += ",";
            snprintf(buf, sizeof(buf), "{\"id\":%u,\"sent\":%u,",
                     static_cast<unsigned>(e.id), static_cast<unsigned>(e.sentEpoch));
            out += buf;
            json_prop(out, "target", e.target); out += ",";
            json_prop(out, "text", e.text); out += ",";
            out += "\"ok\":";
            out += e.ok ? "true" : "false";
            out += "}";
            ++emitted;
        }
    } else {
        out.reserve(64 + std::min<size_t>(s_inbox_filled, limit ? limit : s_inbox_filled) * 200);
        for (size_t k = 0; k < s_inbox_filled; ++k) {
            if (limit > 0 && emitted >= static_cast<size_t>(limit)) break;
            size_t idx = (s_inbox_head + INBOX_MAX - 1 - k) % INBOX_MAX;
            const InboxSlot& e = s_inbox[idx];
            if (e.deleted) continue;
            if (emitted) out += ",";
            snprintf(buf, sizeof(buf), "{\"id\":%u,\"recv\":%u,",
                     static_cast<unsigned>(e.id), static_cast<unsigned>(e.recvEpoch));
            out += buf;
            json_prop(out, "sender", e.sender); out += ",";
            json_prop(out, "ts", e.ts); out += ",";
            json_prop(out, "text", e.text); out += ",";
            out += "\"fwd\":";
            out += e.forwarded ? "true" : "false";
            out += "}";
            ++emitted;
        }
    }
    xSemaphoreGive(s_mutex);
    out += "]";
    return out;
}
