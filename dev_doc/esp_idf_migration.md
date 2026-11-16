# ESP-IDF 迁移状态

迁移已完成：固件现在只保留原生 ESP-IDF 工程，不再保留 Arduino fallback sketch。

## 工程边界

- 固件入口：`CMakeLists.txt`、`main/`、`components/`。
- Web UI 源文件：`code/web_src/`。
- 生成的 gzip Web 资源：`code/web_assets.h`、`code/web_assets.cpp`，由 `components/web_assets` 作为 IDF component 链接。
- 构建输出：只写入 `build/`。
- 本机验证基线：ESP-IDF 5.5.4；CI 另用 ESP-IDF 6.0.2 做兼容性检查。
- 本机推荐入口：`powershell -ExecutionPolicy Bypass -File tools\idf.ps1 build`；脚本默认加载 `E:\Espressif\esp-idf-v5.5.4`，并把 ccache 放在仓库 `build/` 内。
- 烧录入口：`powershell -ExecutionPolicy Bypass -File tools\idf.ps1 flash -Port COM5`。
- `build/idf6` 和 `build/sdkconfig.idf6` 是历史兼容路径名，不表示本机安装了 ESP-IDF 6。
- SDK 补丁统一由 `tools/apply_idf_patches.py` 严格预检；`patches/esp-idf/` 下的交叉签名证书内存补丁仅在 IDF 6 对应功能存在时应用，本机 IDF 5.5.4 正常跳过。

## 当前实现

- `idf_wifi`：STA、失败兜底 SoftAP、captive DNS、轻量 mDNS、SNTP 三服务器、运行中 BOOT 长按配网、重连看门狗。
- `idf_modem`：UART1 单 owner、AT 串行化、模组上电/重启恢复、注册/信号/身份采样、蜂窝 MHTTP、USSD、短信发送 AT 通道。
- `idf_sms`：PDU 收发、`+CMTI`/`+CMT`/`CMGL` 双路径接收、长短信合并、去重、黑名单、管理员命令、收件箱入库、转发入队。
- `idf_push`：HTTP/HTTPS 推送、SMTP over TLS/STARTTLS、转发规则、重试队列、失败冷却、测试推送、Server酱等 10 类通道。
- `idf_web`：Web UI/API、Basic Auth、状态 JSON、日志、短信收发、WiFi 配网、AT 终端、OTA、保号/每日心跳/定时重启调度。
- `idf_config`：NVS 配置读写，保留旧 key 兼容与默认值迁移。

## 验证

```powershell
python tools\build_web_assets.py --check
powershell -ExecutionPolicy Bypass -File tools\idf.ps1 build
```

设备侧仍需按场景人工验证：短信收发、长短信合并、推送/邮件实际投递、OTA 上传、WiFi 配网 SoftAP、BOOT 长按配网、保号 MHTTP/USSD、弱信号/无 SIM/漫游场景。
