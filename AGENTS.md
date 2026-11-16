# AGENTS.md

This file provides guidance to Codex (Codex.ai/code) when working with code in this repository.

## What This Is

ESP32-C3 firmware for a low-cost SMS forwarder. A 4G/LTE modem (ML307R-DC) receives SMS over UART/AT; the ESP32-C3 decodes PDU, then forwards the message over WiFi to email (SMTP) and up to 5 simultaneous push channels, and serves a web UI for config/diagnostics.

The firmware is now native **ESP-IDF only**. The former Arduino fallback sketch has been removed. Keep inline docs/comments in Chinese when editing source files.

## Build / Flash / Monitor

Local ESP-IDF helper:

```powershell
powershell -ExecutionPolicy Bypass -File tools\idf.ps1 build
powershell -ExecutionPolicy Bypass -File tools\idf.ps1 flash -Port COM5
powershell -ExecutionPolicy Bypass -File tools\idf.ps1 monitor -Port COM5
```

The helper defaults to the locally installed ESP-IDF 5.5.4 at `E:\Espressif\esp-idf-v5.5.4`, applies the applicable repository-managed SDK patches under `patches/`, keeps ccache inside `build/`, uses Ninja parallelism, and writes generated files to `build/idf6` with configuration at `build/sdkconfig.idf6`. The `idf6` directory name is retained for compatibility with existing scripts and artifacts; it does not mean the local SDK is IDF 6.

Primary local and real-device validation baseline: **ESP-IDF v5.5.4**. The source also retains the upstream ESP-IDF 6.0.2 / Mbed TLS 4 compatibility adaptations, and CI uses the fixed `espressif/idf:v6.0.2` image as a compatibility gate. Do not assume that ESP-IDF 6.0.2 is installed on the local Windows machine. If a different SDK location is used, pass `-IdfPath` / `-IdfToolsPath` explicitly or set the matching environment variables.

`tools/apply_idf_patches.py` always checks the shared Mbed TLS policy patch. The ESP-IDF 6 cross-signed certificate bundle leak patch is feature-gated and must be skipped on IDF 5.x; do not force IDF 6-only patch context onto the local 5.5.4 SDK.

For direct `idf.py` use, load the intended SDK and apply the repository patch first:

```bash
. /path/to/esp-idf-v5.5.4/export.sh
python tools/apply_idf_patches.py --idf-path "$IDF_PATH"
```

Before committing Web UI changes, run:

```powershell
python tools\build_web_assets.py
python tools\build_web_assets.py --check
```

CI builds the ESP-IDF firmware via `.github/workflows/build.yml`.

## Architecture

Project entrypoints:

- `CMakeLists.txt`, `main/`, and `components/` are the ESP-IDF firmware.
- `components/idf_modem` owns UART1 and all modem AT traffic.
- `components/idf_sms` handles PDU SMS receive/send, SIM storage polling, multipart merge, dedup, blacklist/admin commands, and enqueueing forwards.
- `components/idf_push` owns HTTP/HTTPS push, SMTP, forward queues, retry queues, test push, and forward-rule evaluation.
- `components/idf_web` owns `esp_http_server`, all Web/API routes, scheduler, keep-alive jobs, OTA upload, diagnostics, and status JSON.
- `components/idf_wifi` owns STA/SoftAP provisioning, captive DNS, lightweight mDNS, SNTP, reconnect watchdog, and BOOT long-press provisioning.
- `components/idf_config` persists config in NVS namespace `sms_config`; old NVS keys remain additive/compatible.
- `components/web_assets` links generated gzip Web assets from `code/web_assets.cpp`; editable sources live in `code/web_src/`.

Slow work must stay off request handlers where possible: use existing worker queues for push/email/modem/keep-alive work so SMS receive and Web refresh stay responsive.

## Web UI Assets

Editable UI files live in `code/web_src/`:

- `index.html`
- `app.css`
- `app.js`
- `panels/*.html`

Generated assets are `code/web_assets.h` and `code/web_assets.cpp`. Do not hand-edit generated assets; run `python tools/build_web_assets.py` after editing `web_src`.

New page placeholder flow: add `%TOKEN%` in a panel, render it in `code/web_src/app.js`, expose any dynamic value from `/config.json`, then regenerate assets.

## Extension Conventions

- **New push channel**: add type handling in `components/idf_push/idf_push.cpp`, add validation, then add the Web UI option and hint in `code/web_src/app.js`. `IDF_MAX_PUSH_CHANNELS` is 5.
- **New config field**: add to `IdfConfig`, load/save it in `components/idf_config/idf_config.cpp`, expose/parse it in Web config handlers, and keep the key additive with a default.
- **New HTTP route**: add a handler in `components/idf_web/idf_web.cpp`, register it in `idf_web_start()`, and prefer bounded/streaming responses over large one-shot strings.
- **Logging**: use `idf_log_line()` / `idf_logf()` for Web-visible logs. Logs are mirrored into the 120-entry ring buffer.
- **Privacy**: SMS body and phone numbers should remain masked in normal logs; full content belongs only behind explicit verbose/debug builds.
- **Modem order matters**: handshake, disable/enable data per config via `CGACT`, configure storage/CNMI/PDU mode, then wait for CEREG. PDU mode is required for Chinese SMS.
- **Receive robustness**: keep both URC receive and periodic `AT+CMGL` storage polling. Dedup makes the dual path safe.
