#pragma once

#include <stdint.h>

enum class IdfHeartbeatEnqueueResult : uint8_t {
    queued,
    busy,
    no_target,
};

// 心跳调度只负责入队：网络发送及其重试仍由推送/邮件 worker 负责。
// NVS 与内存队列无法组成事务，因此采用 at-most-once：先持久化当日 claim，
// 再入队；入队失败只在 RAM 中按分钟重试，避免反复 claim/回滚磨损 NVS。
class IdfDailyHeartbeat {
public:
    explicit IdfDailyHeartbeat(int64_t last_claimed_day) : last_claimed_day_(last_claimed_day) {}

    template <typename Enqueue, typename Persist>
    bool poll(bool enabled, int scheduled_hour, uint32_t now, int tz_offset_min,
              uint64_t uptime_ms, Enqueue enqueue, Persist persist)
    {
        if (!enabled || now < 1700000000U || scheduled_hour < 0 || scheduled_hour > 23) return false;

        const int64_t local = static_cast<int64_t>(now) + static_cast<int64_t>(tz_offset_min) * 60LL;
        const int64_t day = local / 86400LL;
        const int hour = static_cast<int>((local / 3600LL) % 24LL);
        // 到点后当天持续补发，避免晚校时或短时队列繁忙错过整个小时。
        const bool retrying_claimed_day = pending_enqueue_day_ == day;
        if (!retrying_claimed_day && (hour < scheduled_hour || day <= last_claimed_day_)) return false;
        if (attempted_ && uptime_ms - last_attempt_ms_ < 60000ULL) return false;

        attempted_ = true;
        last_attempt_ms_ = uptime_ms;
        if (!retrying_claimed_day) {
            // 外部通知必须先 claim；否则入队成功后掉电、或 NVS 提交失败再重启，
            // 会在同一天重复入队。claim 失败时不产生任何外部副作用。
            if (!persist(day)) return false;
            last_claimed_day_ = day;
            pending_enqueue_day_ = day;
        }

        const IdfHeartbeatEnqueueResult result = enqueue();
        if (result == IdfHeartbeatEnqueueResult::busy) return false;
        pending_enqueue_day_ = -1;
        if (result == IdfHeartbeatEnqueueResult::no_target) return false;
        return true;
    }

private:
    int64_t last_claimed_day_;
    int64_t pending_enqueue_day_ = -1;
    uint64_t last_attempt_ms_ = 0;
    bool attempted_ = false;
};
