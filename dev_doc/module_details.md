# 模块说明

## main

`main/app_main.cpp` 初始化 NVS、日志、配置、WiFi、推送 worker、HTTP server、模组任务和短信任务。单个服务启动失败应写日志并尽量继续启动其它服务。

## components/idf_config

负责 `IdfConfig` 的 NVS 读写、表单保存、导入导出、恢复出厂、Web Auth 校验和 keepalive 基准日更新。配置访问使用互斥保护和快照，避免 Web 保存与后台 worker 并发撕裂。

## components/idf_wifi

负责 STA 连接、配网 SoftAP、DNS captive portal、轻量 mDNS、SNTP 三服务器、WiFi 扫描、配置保存重启、断线重连和 BOOT 长按强制配网。

## components/idf_modem

负责 UART1、AT 命令互斥、模组上电/硬重启/软重启、网络注册、信号与身份采样、PDP/MHTTP、USSD、网页发短信底层发送。其它模块不得直接访问 UART。

## components/idf_sms

负责短信接收与发送队列：PDU 解码/编码、`+CMT`/`+CMTI`/`CMGL` 双路径、长短信合并、缺失分段标记、哈希去重、黑名单、管理员命令、收件箱入库和转发入队。

## components/idf_push

负责转发规则、推送队列、邮件队列、失败重试、通道冷却、测试推送和 10 类推送渠道。慢速 HTTP/HTTPS/SMTP 只在 worker 中执行。

## components/idf_web

负责 `esp_http_server` 路由、Basic Auth、静态 Web UI、状态 JSON、配置保存、日志、收件箱 API、OTA、诊断、AT 终端、保号任务和 scheduler。

## components/idf_logbuf / idf_inbox

`idf_logbuf` 提供 120 行环形日志与 `/log?since=` 增量读取。`idf_inbox` 提供最近短信/已发送短信的环形缓存和 JSON 输出。

## components/web_assets

链接 `code/web_assets.cpp` 中的 gzip 静态资源。编辑 `code/web_src/` 后必须运行：

```powershell
python tools\build_web_assets.py
python tools\build_web_assets.py --check
```
