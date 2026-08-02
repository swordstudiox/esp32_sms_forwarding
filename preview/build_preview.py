#!/usr/bin/env python3
"""从 code/web_src 组装本地 Web UI 预览页。

预览页只注入 mock 数据，用于 README 截图和本地看样式；不影响固件。
"""

from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "code" / "web_src"
OUT = ROOT / "preview" / "index.html"
PANELS = ["overview", "sim", "inbox", "settings", "push", "keepalive", "diagnose", "atterm", "log"]


def read(path: Path) -> str:
    text = path.read_text(encoding="utf-8").replace("{{ASSET_HASH}}", "preview")
    return (
        text.replace("+447700900123", "+44 7700 900123")
        .replace("+447700900456", "+44 7700 900456")
        .replace("860000000000000", "860000••••••0000")
        .replace("89440000000000000000", "8944••••••••••0000")
        .replace("234100000000000", "23410••••••••000")
    )


index = read(SRC / "index.html")
css = read(SRC / "app.css")
js = read(SRC / "app.js")
panels = {name: read(SRC / "panels" / f"{name}.html") for name in PANELS}

mock_config = {
    "assetHash": "preview",
    "uptimeText": "3天 04:18:22",
    "webUser": "admin",
    "webPass": "demo-password",
    "smtpServer": "smtp.example.com",
    "smtpPort": 465,
    "smtpUser": "sms-demo@example.com",
    "smtpPass": "demo-auth-code",
    "smtpSendTo": "owner@example.com",
    "adminPhone": "+44 7700 900123",
    "numberBlackList": "+44 7700 900999\nAD-SENDER",
    "forwardRules": "kw\t验证码\t1,email\t1\nfrom\t^(giffgaff|AUTH)$\t1\t1\nkw\t广告\tdrop\t1",
    "emailEnabled": True,
    "pushEnabled": True,
    "emailConfigured": True,
    "modemReady": True,
    "pushEnabledCount": 2,
    "inboxMax": 120,
    "ntpServer": "ntp.aliyun.com",
    "tzOffsetMin": 480,
    "rebootEnabled": True,
    "rebootHour": 4,
    "hbEnabled": True,
    "hbHour": 9,
    "dataEnabled": False,
    "apn": "giffgaff.com",
    "phoneNumber": "+44 7700 900123",
    "operatorPlmn": "",
    "pushChannels": [
        {
            "enabled": True,
            "type": 2,
            "name": "Bark 自建",
            "url": "https://bark-demo.example.com",
            "key1": "demo-device-key",
            "key2": "group=SMS&level=timeSensitive&sound=bell&copy={message}",
            "customBody": "",
        },
        {
            "enabled": False,
            "type": 6,
            "name": "Server酱 备用",
            "url": "",
            "key1": "SCT-DEMO-SENDKEY",
            "key2": "",
            "customBody": "",
        },
        {
            "enabled": True,
            "type": 1,
            "name": "内部 Webhook",
            "url": "https://notify.example.com/sms",
            "key1": "",
            "key2": "",
            "customBody": "",
        },
        {"enabled": False, "type": 1, "name": "通道4", "url": "", "key1": "", "key2": "", "customBody": ""},
        {"enabled": False, "type": 1, "name": "通道5", "url": "", "key1": "", "key2": "", "customBody": ""},
    ],
}

mock_status = {
    "version": "1.0.4-preview",
    "modemReady": True,
    "modemPhase": "ready",
    "wifiConnected": True,
    "apMode": False,
    "ssid": "Demo-WiFi",
    "rssi": -58,
    "csq": 24,
    "ber": 99,
    "signalFresh": True,
    "identityFresh": True,
    "rsrp": -91,
    "rsrq": -9,
    "sinr": 18,
    "pci": 217,
    "plmn": "23410",
    "tac": "7A21",
    "tz": 480,
    "nowEpoch": 1783056563,
    "operator": "giffgaff",
    "imei": "860000••••••1234",
    "iccid": "8944••••••••••0000",
    "imsi": "23410••••••••123",
    "apnSim": "giffgaff.com",
    "mfr": "MeiG",
    "model": "ML307R",
    "fwver": "ML307R-demo",
    "phone": "+44 7700 900123",
    "dataEnabled": False,
    "apn": "giffgaff.com",
    "cellIp": "",
    "inboxCount": 12,
    "ip": "192.168.1.50",
    "gw": "192.168.1.1",
    "mask": "255.255.255.0",
    "dns": "192.168.1.1",
    "mac": "AA:BB:CC:DD:EE:FF",
    "bssid": "11:22:33:44:55:66",
    "chan": 6,
    "freeHeap": 212000,
    "minFreeHeap": 176000,
    "maxAllocHeap": 108000,
    "uptime": 274702,
    "queueDepth": 0,
    "fwdQueueDepth": 0,
    "outSmsQueueDepth": 0,
    "emailQueueDepth": 0,
    "slowBusy": False,
    "emailEnabled": True,
    "emailConfigured": True,
    "pushEnabled": True,
    "pushEnabledCount": 2,
    "adminPhone": "+44 7700 900123",
    "smsTotal": 86,
    "lastSmsEpoch": 1783056400,
    "resetReason": 1,
    "configValid": True,
    "timeSynced": True,
    "chipTemp": 42.5,
}

mock_messages = [
    {
        "id": 86,
        "recv": 1783056400,
        "sender": "AUTH",
        "ts": "2026-07-03 14:46:40",
        "text": "Your AI service verification code is 482913. It expires in 5 minutes.",
        "fwd": True,
    },
    {
        "id": 85,
        "recv": 1783052100,
        "sender": "giffgaff",
        "ts": "2026-07-03 13:35:00",
        "text": "Your giffgaff SIM is active. Keep it topped up or use it periodically.",
        "fwd": True,
    },
    {
        "id": 84,
        "recv": 1783049900,
        "sender": "+44 7700 900456",
        "ts": "2026-07-03 12:58:20",
        "text": "测试短信：Bark、邮件和 Webhook 都应收到这条转发。",
        "fwd": True,
    },
]

mock_sent = [
    {"id": 3, "sent": 1783040000, "target": "43430", "text": "BAL", "ok": True},
    {"id": 2, "sent": 1783030000, "target": "+44 7700 900456", "text": "设备测试短信", "ok": True},
]

mock_log = [
    "配置已加载: wifi=Demo-WiFi, webUser=admin",
    "ESP-IDF 迁移版启动: 1.0.4-preview",
    "Web 资源 hash=preview shell=1595 css=4249 js=16968",
    "mDNS 已启动: http://sms.local",
    "连接 WiFi: Demo-WiFi",
    "WiFi 已连接，IP=192.168.1.50",
    "NTP 时间同步已启动：首选=ntp.aliyun.com，备用=ntp.ntsc.ac.cn,pool.ntp.org",
    "推送后台 worker 已启动",
    "HTTP 服务器已启动",
    "NTP 时间同步成功，本地时间=2026-07-03 14:49:23 UTC+8",
    "模组 AT 已就绪",
    "模组信号 CSQ=24/31 BER=未知",
    "短信接收(PDU/存储通知)已配置",
    "发送到推送通道: Bark 自建",
    "[Bark 自建] HTTP 响应码: 200",
]

stub = f"""<script>
/* PREVIEW ONLY — mock fetch，不包含真实号码、密钥、邮箱或设备标识。 */
(function(){{
  var panels = {json.dumps(panels, ensure_ascii=False)};
  var config = {json.dumps(mock_config, ensure_ascii=False)};
  var status = {json.dumps(mock_status, ensure_ascii=False)};
  var messages = {json.dumps(mock_messages, ensure_ascii=False)};
  var sent = {json.dumps(mock_sent, ensure_ascii=False)};
  var logs = {json.dumps(mock_log, ensure_ascii=False)};
  function resp(obj, text) {{ return Promise.resolve({{
    ok: true,
    status: 200,
    json: function() {{ return Promise.resolve(obj); }},
    text: function() {{ return Promise.resolve(text != null ? text : JSON.stringify(obj)); }}
  }}); }}
  window.fetch = function(url) {{
    url = String(url || '');
    if (url.indexOf('/config.json') >= 0) return resp(config);
    if (url.indexOf('/ui?') >= 0) {{
      var m = url.match(/[?&]panel=([^&]+)/);
      var name = m ? decodeURIComponent(m[1]) : 'overview';
      return resp({{}}, panels[name] || panels.overview);
    }}
    if (url.indexOf('/status') >= 0) return resp(status);
    if (url.indexOf('/messages') >= 0 && url.indexOf('box=sent') >= 0) return resp(sent);
    if (url.indexOf('/messages') >= 0) {{
      var limited = url.indexOf('limit=1') >= 0 ? messages.slice(0, 1) : messages;
      return resp(limited);
    }}
    if (url.indexOf('/log') >= 0) {{
      var m = url.match(/[?&]since=(\\d+)/);
      var since = m ? parseInt(m[1], 10) : 0;
      return resp({{seq: logs.length, lines: since > 0 ? [] : logs}});
    }}
    if (url.indexOf('/keepalive') >= 0) return resp({{
      enabled: true, intervalDays: 175, action: 1, target: '',
      url: 'http://gg.incrafttime.top/api/payload?size=64342',
      lastTime: 1777680000, daysLeft: 113, timeValid: true,
      queued: false, running: false, done: true, success: true,
      message: '预览模式：保号状态正常'
    }});
    if (url.indexOf('/wifiscan') >= 0) return resp([
      {{ssid:'Demo-WiFi', rssi:-48, enc:1}},
      {{ssid:'Lab-5G', rssi:-67, enc:1}},
      {{ssid:'Guest', rssi:-72, enc:0}}
    ]);
    if (url.indexOf('/testpush') >= 0) return resp({{success:true, queued:false, running:false, done:true, success:true, message:'预览模式：测试推送成功'}});
    if (url.indexOf('/ping') >= 0) return resp({{success:true, queued:false, running:false, done:true, message:'预览模式：蜂窝 payload 下载成功，已关闭 PDP'}});
    if (url.indexOf('/modem') >= 0 || url.indexOf('/flight') >= 0 || url.indexOf('/ussd') >= 0 || url.indexOf('/at?') >= 0) {{
      return resp({{success:true, message:'预览模式：示例响应'}});
    }}
    return resp({{success:true, message:'预览模式：示例响应'}});
  }};
}})();
</script>"""

index = index.replace('<link rel="stylesheet" href="/assets/app.css?v=preview">', "<style>\n" + css + "\n</style>")
index = index.replace('<script src="/assets/app.js?v=preview" defer></script>', stub + "\n<script>\n" + js + "\n</script>")

OUT.parent.mkdir(parents=True, exist_ok=True)
open(OUT, "w", encoding="utf-8", newline="").write(index)
print(f"generated {OUT}")
