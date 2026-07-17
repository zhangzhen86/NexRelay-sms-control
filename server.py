#!/usr/bin/env python3
import hashlib
import json
import os
import secrets
import select
import termios
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

BASE = Path(__file__).resolve().parent
DATA = Path(os.environ.get("IG830_DATA_DIR", BASE))
DATA.mkdir(parents=True, exist_ok=True)
CONFIG_FILE = DATA / "config.json"
LOG_FILE = DATA / "events.log"
STATE_FILE = DATA / "state.json"
LOCK = threading.RLock()
MODEM_LOCK = threading.Lock()
RUNTIME = {"last_poll": None, "last_error": "", "forwarded": 0}

DEFAULTS = {
    "enabled": False,
    "serial_port": "/dev/ttyUSB2",
    "poll_interval": 10,
    "webhook_url": "",
    "http_method": "POST",
    "auth_header": "Authorization",
    "auth_value": "",
    "sender_allow": "",
    "sender_block": "",
    "keyword_include": "",
    "keyword_exclude": "",
    "delete_after_forward": False,
    "forward_existing": False,
}


def utcnow():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def load_config():
    with LOCK:
        if CONFIG_FILE.exists():
            raw = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
        else:
            raw = {}
        changed = False
        for key, value in DEFAULTS.items():
            if key not in raw:
                raw[key] = value
                changed = True
        if "admin_token_hash" not in raw:
            token = secrets.token_urlsafe(24)
            raw["admin_token_hash"] = hashlib.sha256(token.encode()).hexdigest()
            (DATA / "admin-token.txt").write_text(token + "\n", encoding="utf-8")
            os.chmod(DATA / "admin-token.txt", 0o600)
            changed = True
        if changed:
            save_config(raw)
        return raw


def save_config(cfg):
    with LOCK:
        tmp = CONFIG_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(cfg, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        os.chmod(tmp, 0o600)
        tmp.replace(CONFIG_FILE)


def public_config(cfg):
    result = {k: cfg.get(k, v) for k, v in DEFAULTS.items()}
    result["auth_value_set"] = bool(cfg.get("auth_value"))
    result["auth_value"] = ""
    return result


def log_event(kind, message, **extra):
    item = {"time": utcnow(), "kind": kind, "message": message, **extra}
    with LOCK:
        with LOG_FILE.open("a", encoding="utf-8") as f:
            f.write(json.dumps(item, ensure_ascii=False) + "\n")


def recent_logs(limit=100):
    if not LOG_FILE.exists():
        return []
    lines = LOG_FILE.read_text(encoding="utf-8", errors="replace").splitlines()[-limit:]
    out = []
    for line in lines:
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    return list(reversed(out))


def csv_values(value):
    return [x.strip().lower() for x in str(value or "").split(",") if x.strip()]


def should_forward(sender, message, cfg):
    s, m = sender.lower(), message.lower()
    allow, block = csv_values(cfg.get("sender_allow")), csv_values(cfg.get("sender_block"))
    include, exclude = csv_values(cfg.get("keyword_include")), csv_values(cfg.get("keyword_exclude"))
    if allow and not any(x in s for x in allow):
        return False
    if any(x in s for x in block):
        return False
    if include and not any(x in m for x in include):
        return False
    if any(x in m for x in exclude):
        return False
    return True


class Modem:
    def __init__(self, port):
        self.fd = os.open(port, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
        attrs = termios.tcgetattr(self.fd)
        attrs[0] = 0
        attrs[1] = 0
        attrs[2] = termios.CS8 | termios.CREAD | termios.CLOCAL
        attrs[3] = 0
        attrs[4] = termios.B115200
        attrs[5] = termios.B115200
        termios.tcsetattr(self.fd, termios.TCSANOW, attrs)
        termios.tcflush(self.fd, termios.TCIOFLUSH)

    def close(self):
        os.close(self.fd)

    def command(self, command, timeout=4):
        termios.tcflush(self.fd, termios.TCIFLUSH)
        os.write(self.fd, (command + "\r").encode())
        end, data = time.monotonic() + timeout, bytearray()
        while time.monotonic() < end:
            ready, _, _ = select.select([self.fd], [], [], min(0.25, end - time.monotonic()))
            if ready:
                chunk = os.read(self.fd, 8192)
                if chunk:
                    data.extend(chunk)
                    text = data.decode("utf-8", "replace")
                    if "\r\nOK\r\n" in text or "\r\nERROR\r\n" in text or "+CME ERROR:" in text:
                        return text
        raise TimeoutError(f"AT command timeout: {command}")


def parse_cmgl(raw):
    lines = [x.strip() for x in raw.replace("\r", "").split("\n") if x.strip()]
    out, current = [], None
    for line in lines:
        if line.startswith("+CMGL:"):
            if current:
                out.append(current)
            parts = line.split(",")
            try:
                index = int(parts[0].split(":", 1)[1].strip())
            except (IndexError, ValueError):
                current = None
                continue
            quoted = [part.strip().strip('"') for part in parts[1:]]
            current = {"index": index, "sender": quoted[1] if len(quoted) > 1 else "", "received_at": ",".join(quoted[3:5]) if len(quoted) > 3 else "", "message": ""}
        elif current and line not in ("OK", "ERROR") and not line.startswith("AT+"):
            current["message"] += ("\n" if current["message"] else "") + line
    if current:
        out.append(current)
    return out


def deliver_sms(cfg, sms):
    url = cfg.get("webhook_url", "").strip()
    if not url.startswith(("http://", "https://")):
        raise ValueError("Webhook URL 未配置")
    payload = json.dumps({"event": "sms.received", "device": "IG830", "sender": sms["sender"], "message": sms["message"], "received_at": sms["received_at"], "modem_index": sms["index"]}, ensure_ascii=False).encode()
    headers = {"Content-Type": "application/json", "User-Agent": "IG830-SMS-Control/1.0"}
    if cfg.get("auth_header") and cfg.get("auth_value"):
        headers[cfg["auth_header"]] = cfg["auth_value"]
    req = urllib.request.Request(url, data=payload, headers=headers, method=cfg.get("http_method", "POST"))
    with urllib.request.urlopen(req, timeout=15) as res:
        if not 200 <= res.status < 300:
            raise RuntimeError(f"Webhook HTTP {res.status}")


def poll_once():
    cfg = load_config()
    if not cfg.get("enabled"):
        return
    state = json.loads(STATE_FILE.read_text()) if STATE_FILE.exists() else {"seen": []}
    seen = set(state.get("seen", []))
    with MODEM_LOCK:
        modem = Modem(cfg["serial_port"])
        try:
            modem.command("ATE0")
            if "+CPIN: READY" not in modem.command("AT+CPIN?"):
                raise RuntimeError("SIM 未就绪")
            if "OK" not in modem.command("AT+CMGF=1"):
                raise RuntimeError("模块不支持短信文本模式")
            raw = modem.command('AT+CMGL="ALL"', timeout=8)
            messages = parse_cmgl(raw)
            for sms in messages:
                key = hashlib.sha256(f"{sms['index']}|{sms['sender']}|{sms['received_at']}|{sms['message']}".encode()).hexdigest()
                if key in seen:
                    continue
                if not cfg.get("forward_existing") and not state.get("initialized"):
                    seen.add(key)
                    continue
                if should_forward(sms["sender"], sms["message"], cfg):
                    deliver_sms(cfg, sms)
                    RUNTIME["forwarded"] += 1
                    log_event("sms", "短信转发成功", sender=sms["sender"], index=sms["index"])
                    if cfg.get("delete_after_forward"):
                        modem.command(f"AT+CMGD={sms['index']}")
                else:
                    log_event("filter", "短信被规则忽略", sender=sms["sender"], index=sms["index"])
                seen.add(key)
            state = {"initialized": True, "seen": list(seen)[-2000:]}
            STATE_FILE.write_text(json.dumps(state), encoding="utf-8")
            os.chmod(STATE_FILE, 0o600)
        finally:
            modem.close()


def worker():
    while True:
        cfg = load_config()
        try:
            poll_once()
            RUNTIME["last_error"] = ""
        except Exception as e:
            RUNTIME["last_error"] = str(e)
            log_event("error", "短信轮询失败", error=str(e))
        RUNTIME["last_poll"] = utcnow()
        time.sleep(max(3, int(cfg.get("poll_interval", 10))))


def device_status():
    cfg = load_config()
    port = cfg.get("serial_port", "/dev/ttyUSB2")
    exists = Path(port).exists()
    return {
        "usb_present": Path("/sys/bus/usb/devices").exists() and any(
            "2ca3" in p.read_text(errors="ignore").lower()
            for p in Path("/sys/bus/usb/devices").glob("*/idVendor")
        ),
        "serial_port": port,
        "serial_present": exists,
        "service_time": utcnow(),
        "note": "串口已就绪" if exists else "未找到串口，请检查 UTM USB 直通和驱动绑定",
        "runtime": dict(RUNTIME),
    }


def test_webhook(cfg):
    url = cfg.get("webhook_url", "").strip()
    if not url.startswith(("http://", "https://")):
        raise ValueError("Webhook URL 必须以 http:// 或 https:// 开头")
    payload = json.dumps({
        "event": "test",
        "device": "IG830",
        "sender": "+8613800000000",
        "message": "这是一条 IG830 短信转发测试消息",
        "received_at": utcnow(),
    }, ensure_ascii=False).encode()
    headers = {"Content-Type": "application/json", "User-Agent": "IG830-SMS-Control/1.0"}
    if cfg.get("auth_header") and cfg.get("auth_value"):
        headers[cfg["auth_header"]] = cfg["auth_value"]
    req = urllib.request.Request(url, data=payload, headers=headers, method=cfg.get("http_method", "POST"))
    with urllib.request.urlopen(req, timeout=10) as res:
        return {"status": res.status, "body": res.read(500).decode("utf-8", "replace")}


HTML = r'''<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>IG830 短信转发控制台</title>
<style>
:root{color-scheme:dark;--bg:#071018;--panel:#101d28;--line:#263a49;--text:#e9f3f8;--muted:#91a7b5;--accent:#38d39f;--warn:#ffca58;--bad:#ff6b6b}*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 10% 0,#123348 0,transparent 38%),var(--bg);color:var(--text);font:15px/1.5 system-ui,-apple-system,sans-serif}.wrap{max-width:1050px;margin:auto;padding:28px}.top{display:flex;justify-content:space-between;align-items:center;gap:16px;margin-bottom:22px}h1{font-size:25px;margin:0}.sub{color:var(--muted);margin-top:5px}.pill{border:1px solid var(--line);border-radius:999px;padding:7px 12px;color:var(--muted)}.grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}.card{background:color-mix(in srgb,var(--panel) 94%,transparent);border:1px solid var(--line);border-radius:15px;padding:19px;box-shadow:0 18px 45px #0004}.wide{grid-column:1/-1}h2{font-size:16px;margin:0 0 15px}.row{display:grid;grid-template-columns:1fr 1fr;gap:12px}.field{margin:10px 0}label{display:block;color:var(--muted);font-size:13px;margin-bottom:5px}input,select{width:100%;padding:10px 11px;border:1px solid var(--line);border-radius:9px;background:#07131c;color:var(--text);outline:none}input:focus,select:focus{border-color:var(--accent)}.check{display:flex;align-items:center;gap:9px;margin:11px 0}.check input{width:auto}.actions{display:flex;flex-wrap:wrap;gap:10px;margin-top:17px}button{border:0;border-radius:9px;padding:10px 15px;background:var(--accent);color:#042017;font-weight:700;cursor:pointer}button.secondary{background:#213443;color:var(--text)}button:disabled{opacity:.55;cursor:wait}.status{display:grid;grid-template-columns:repeat(3,1fr);gap:10px}.metric{background:#09151e;border:1px solid var(--line);padding:13px;border-radius:10px}.metric b{display:block;margin-top:4px}.ok{color:var(--accent)}.bad{color:var(--bad)}#toast{position:fixed;right:22px;bottom:22px;max-width:420px;background:#132531;border:1px solid var(--line);padding:12px 15px;border-radius:10px;display:none}.log{max-height:260px;overflow:auto}.entry{border-bottom:1px solid var(--line);padding:9px 0}.entry small{color:var(--muted)}.login{max-width:440px;margin:15vh auto}.hidden{display:none!important}@media(max-width:750px){.grid,.row{grid-template-columns:1fr}.wide{grid-column:auto}.status{grid-template-columns:1fr}.wrap{padding:16px}}
</style></head><body>
<section id="login" class="login card"><h1>IG830 控制台</h1><p class="sub">请输入部署时生成的管理令牌。</p><div class="field"><label>管理令牌</label><input id="token" type="password" autocomplete="current-password"></div><button onclick="login()">进入控制台</button></section>
<main id="app" class="wrap hidden"><div class="top"><div><h1>IG830 短信转发控制台</h1><div class="sub">本地、自托管、配置由你掌控</div></div><span id="enabledPill" class="pill">读取中</span></div>
<div class="grid"><section class="card wide"><h2>设备状态</h2><div class="status"><div class="metric">USB 设备<b id="usb">—</b></div><div class="metric">短信串口<b id="serial">—</b></div><div class="metric">更新时间<b id="stime">—</b></div></div><p id="note" class="sub"></p><div class="actions"><button class="secondary" onclick="refreshAll()">刷新状态</button></div></section>
<section class="card"><h2>转发目标</h2><div class="check"><input id="enabled" type="checkbox"><label for="enabled">启用短信转发</label></div><div class="field"><label>Webhook URL</label><input id="webhook_url" placeholder="https://your-app.example/sms"></div><div class="row"><div class="field"><label>请求方法</label><select id="http_method"><option>POST</option><option>PUT</option></select></div><div class="field"><label>轮询间隔（秒）</label><input id="poll_interval" type="number" min="3" max="3600"></div></div><div class="field"><label>鉴权 Header</label><input id="auth_header" placeholder="Authorization"></div><div class="field"><label>鉴权值（留空表示保持原值）</label><input id="auth_value" type="password" placeholder="Bearer ..."></div><div class="field"><label>短信串口</label><input id="serial_port"></div></section>
<section class="card"><h2>筛选与处理</h2><div class="field"><label>允许的发送方（逗号分隔，留空为全部）</label><input id="sender_allow"></div><div class="field"><label>屏蔽的发送方（逗号分隔）</label><input id="sender_block"></div><div class="field"><label>正文必须包含的关键词（逗号分隔）</label><input id="keyword_include"></div><div class="field"><label>正文排除关键词（逗号分隔）</label><input id="keyword_exclude"></div><div class="check"><input id="forward_existing" type="checkbox"><label for="forward_existing">首次启用时转发现有短信</label></div><div class="check"><input id="delete_after_forward" type="checkbox"><label for="delete_after_forward">转发成功后删除模块内短信</label></div></section>
<section class="card wide"><h2>保存与测试</h2><p class="sub">测试 Webhook 会向你填写的地址发送一条模拟消息，不包含真实短信。</p><div class="actions"><button onclick="save()">保存配置</button><button class="secondary" onclick="testHook()">发送测试消息</button><button class="secondary" onclick="logout()">退出</button></div></section>
<section class="card wide"><h2>最近事件</h2><div id="logs" class="log"><div class="sub">暂无记录</div></div></section></div></main><div id="toast"></div>
<script>
const fields=['enabled','serial_port','poll_interval','webhook_url','http_method','auth_header','auth_value','sender_allow','sender_block','keyword_include','keyword_exclude','delete_after_forward','forward_existing'];
let tok=localStorage.getItem('ig830Token')||''; const $=id=>document.getElementById(id);
function msg(s,bad=false){let t=$('toast');t.textContent=s;t.style.display='block';t.style.borderColor=bad?'var(--bad)':'var(--accent)';setTimeout(()=>t.style.display='none',4500)}
async function api(path,opt={}){opt.headers={...(opt.headers||{}),'X-Admin-Token':tok};let r=await fetch(path,opt);let j=await r.json().catch(()=>({error:'响应格式错误'}));if(!r.ok)throw Error(j.error||('HTTP '+r.status));return j}
async function login(){tok=$('token').value.trim();try{await api('/api/config');localStorage.setItem('ig830Token',tok);$('login').classList.add('hidden');$('app').classList.remove('hidden');refreshAll()}catch(e){msg('令牌错误：'+e.message,true)}}
function logout(){localStorage.removeItem('ig830Token');location.reload()}
function fill(c){for(let k of fields){let e=$(k);if(!e)continue;if(e.type==='checkbox')e.checked=!!c[k];else if(k!=='auth_value')e.value=c[k]??''}$('enabledPill').textContent=c.enabled?'转发已启用':'转发已停用';$('enabledPill').className='pill '+(c.enabled?'ok':'')}
async function refreshAll(){try{let [c,s,l]=await Promise.all([api('/api/config'),api('/api/status'),api('/api/logs')]);fill(c);$('usb').textContent=s.usb_present?'已识别':'未识别';$('usb').className=s.usb_present?'ok':'bad';$('serial').textContent=s.serial_present?s.serial_port:'不可用';$('serial').className=s.serial_present?'ok':'bad';$('stime').textContent=new Date(s.service_time).toLocaleString();$('note').textContent=s.note;$('logs').innerHTML=l.length?l.map(x=>`<div class="entry"><b>${esc(x.kind)}</b> ${esc(x.message)}<br><small>${esc(x.time)}</small></div>`).join(''):'<div class="sub">暂无记录</div>'}catch(e){if(e.message.includes('401'))logout();else msg(e.message,true)}}
function collect(){let c={};for(let k of fields){let e=$(k);c[k]=e.type==='checkbox'?e.checked:e.value}c.poll_interval=Number(c.poll_interval);return c}
async function save(){try{let c=await api('/api/config',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify(collect())});fill(c);msg('配置已保存')}catch(e){msg(e.message,true)}}
async function testHook(){if(!confirm('将向配置的 Webhook 地址发送一条模拟短信，继续吗？'))return;try{let r=await api('/api/test-webhook',{method:'POST'});msg('测试成功，HTTP '+r.status)}catch(e){msg('测试失败：'+e.message,true)}}
function esc(s){return String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
if(tok){$('login').classList.add('hidden');$('app').classList.remove('hidden');refreshAll()}
</script></body></html>'''


class Handler(BaseHTTPRequestHandler):
    server_version = "IG830Control/1.0"

    def log_message(self, fmt, *args):
        pass

    def send_json(self, obj, status=200):
        data = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def read_json(self):
        size = int(self.headers.get("Content-Length", "0"))
        return json.loads(self.rfile.read(size) or b"{}")

    def authorized(self):
        cfg = load_config()
        supplied = self.headers.get("X-Admin-Token", "")
        actual = hashlib.sha256(supplied.encode()).hexdigest()
        return secrets.compare_digest(actual, cfg["admin_token_hash"])

    def require_auth(self):
        if self.authorized():
            return True
        self.send_json({"error": "未授权"}, 401)
        return False

    def do_GET(self):
        if self.path == "/":
            data = HTML.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)
            return
        if not self.require_auth():
            return
        if self.path == "/api/config":
            self.send_json(public_config(load_config()))
        elif self.path == "/api/status":
            self.send_json(device_status())
        elif self.path == "/api/logs":
            self.send_json(recent_logs())
        else:
            self.send_json({"error": "未找到"}, 404)

    def do_PUT(self):
        if not self.require_auth():
            return
        if self.path != "/api/config":
            return self.send_json({"error": "未找到"}, 404)
        try:
            incoming = self.read_json()
            cfg = load_config()
            for key, default in DEFAULTS.items():
                if key in incoming:
                    if key == "auth_value" and incoming[key] == "":
                        continue
                    cfg[key] = incoming[key]
            cfg["poll_interval"] = max(3, min(3600, int(cfg["poll_interval"])))
            if cfg["http_method"] not in ("POST", "PUT"):
                raise ValueError("请求方法仅支持 POST 或 PUT")
            save_config(cfg)
            log_event("config", "转发配置已更新", enabled=bool(cfg["enabled"]))
            self.send_json(public_config(cfg))
        except (ValueError, TypeError, json.JSONDecodeError) as e:
            self.send_json({"error": str(e)}, 400)

    def do_POST(self):
        if not self.require_auth():
            return
        if self.path != "/api/test-webhook":
            return self.send_json({"error": "未找到"}, 404)
        try:
            result = test_webhook(load_config())
            log_event("webhook", "测试消息发送成功", status=result["status"])
            self.send_json(result)
        except Exception as e:
            log_event("error", "Webhook 测试失败", error=str(e))
            self.send_json({"error": str(e)}, 502)


if __name__ == "__main__":
    load_config()
    log_event("service", "IG830 控制台已启动")
    threading.Thread(target=worker, name="sms-worker", daemon=True).start()
    ThreadingHTTPServer(("0.0.0.0", 8765), Handler).serve_forever()
