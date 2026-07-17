#!/usr/bin/env python3
import csv
import hashlib
import hmac
import io
import json
import os
import re
import secrets
import select
import smtplib
import ssl
import sys
import termios
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from storage import Storage

APP_VERSION = "1.9.0-local"
CONFIG_SCHEMA_VERSION = 4
BASE = Path(__file__).resolve().parent
DATA = Path(os.environ.get("IG830_DATA_DIR", BASE))
DATA.mkdir(parents=True, exist_ok=True)
CONFIG_FILE = DATA / "config.json"
LOG_FILE = DATA / "events.log"
STATE_FILE = DATA / "state.json"
USB_BACKUP_FILE = DATA / "usbcfg-backup.json"
DB = Storage(DATA / "ig830.db")
LOCK = threading.RLock()
MODEM_LOCK = threading.Lock()
OUTBOUND_SMS_COOLDOWN = 30
LAST_OUTBOUND_SMS_AT = 0.0
DEVICE_ONLINE_STATE = None
LAST_POLL_ERROR = ""
RUNTIME = {
    "last_poll": None, "last_error": "", "forwarded": 0,
    "sim_ready": False, "signal_rssi": None, "signal_dbm": None,
    "signal_level": 0, "operator": "", "registered": False,
    "registration": "未知",
    "phone_number": "",
    "channel_errors": {}, "channel_tests": {}, "last_sms_sent": None,
    "telegram_reply_status": "已停用", "telegram_reply_error": "",
    "telegram_reply_last_at": None,
}

DEFAULTS = {
    "schema_version": CONFIG_SCHEMA_VERSION,
    "enabled": False,
    "serial_port": "/dev/ttyUSB2",
    "poll_interval": 10,
    "notification_title": "IG830 收到短信",
    "test_notification_title": "IG830 测试消息",
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
    "dingtalk_enabled": False,
    "dingtalk_webhook": "",
    "dingtalk_secret": "",
    "feishu_enabled": False,
    "feishu_webhook": "",
    "wecom_enabled": False,
    "wecom_webhook": "",
    "telegram_enabled": False,
    "telegram_bot_token": "",
    "telegram_chat_id": "",
    "telegram_reply_enabled": False,
    "telegram_reply_user_id": "",
    "wechat_enabled": False,
    "wechat_pushplus_token": "",
    "wechat_topic": "",
    "retention_days": 90,
    "low_signal_threshold": -105,
    "quiet_start": "",
    "quiet_end": "",
    "smtp_enabled": False,
    "smtp_host": "",
    "smtp_port": 465,
    "smtp_user": "",
    "smtp_password": "",
    "smtp_to": "",
    "mqtt_enabled": False,
    "mqtt_webhook": "",
    "bark_enabled": False,
    "bark_url": "",
    "ntfy_enabled": False,
    "ntfy_url": "",
    "update_channel": "stable",
}

SECRET_FIELDS = {"auth_value", "dingtalk_secret", "telegram_bot_token", "wechat_pushplus_token", "smtp_password"}
HIDDEN_LEGACY_FIELDS = {"delete_after_forward", "low_signal_threshold", "quiet_start", "quiet_end", "update_channel"}
CHANNEL_CONFIG_FIELDS = {
    "custom": ("webhook_url", "http_method", "auth_header", "auth_value"),
    "dingtalk": ("dingtalk_enabled", "dingtalk_webhook", "dingtalk_secret"),
    "feishu": ("feishu_enabled", "feishu_webhook"),
    "wecom": ("wecom_enabled", "wecom_webhook"),
    "telegram": ("telegram_enabled", "telegram_bot_token", "telegram_chat_id"),
    "wechat": ("wechat_enabled", "wechat_pushplus_token", "wechat_topic"),
    "email": ("smtp_enabled", "smtp_host", "smtp_port", "smtp_user", "smtp_password", "smtp_to"),
    "bark": ("bark_enabled", "bark_url"),
    "ntfy": ("ntfy_enabled", "ntfy_url"),
    "mqtt": ("mqtt_enabled", "mqtt_webhook"),
}
SUPPORTED_IG830_USB_IDS = {("2ca3", "4006"): "factory", ("2c7c", "0125"): "compatible"}


def utcnow():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def bounded_int(value, default, minimum, maximum):
    try:
        return max(minimum, min(maximum, int(value)))
    except (TypeError, ValueError):
        return default


def valid_hhmm(value):
    if value == "":
        return True
    if not re.fullmatch(r"\d{2}:\d{2}", str(value)):
        return False
    hour, minute = map(int, str(value).split(":"))
    return 0 <= hour <= 23 and 0 <= minute <= 59


def changed_channel_configs(before, after):
    """Return only channels whose own connection settings changed."""
    return {
        channel
        for channel, fields in CHANNEL_CONFIG_FIELDS.items()
        if any(before.get(field) != after.get(field) for field in fields)
    }


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
        if int(raw.get("schema_version", 0)) < CONFIG_SCHEMA_VERSION:
            raw["schema_version"] = CONFIG_SCHEMA_VERSION
            changed = True
        if "admin_token_hash" not in raw:
            token = secrets.token_urlsafe(24)
            raw["admin_token_hash"] = hashlib.sha256(token.encode()).hexdigest()
            (DATA / "admin-token.txt").write_text(token + "\n", encoding="utf-8")
            os.chmod(DATA / "admin-token.txt", 0o600)
            changed = True
        if "admin_username" not in raw:
            raw["admin_username"] = "admin"
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


def load_state():
    with LOCK:
        if not STATE_FILE.exists():
            return {"seen": []}
        try:
            state = json.loads(STATE_FILE.read_text(encoding="utf-8"))
            return state if isinstance(state, dict) else {"seen": []}
        except (OSError, json.JSONDecodeError):
            return {"seen": []}


def save_state(state):
    with LOCK:
        tmp = STATE_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(state, ensure_ascii=False), encoding="utf-8")
        os.chmod(tmp, 0o600)
        tmp.replace(STATE_FILE)


def persist_channel_runtime():
    state = load_state()
    state["channel_tests"] = dict(RUNTIME["channel_tests"])
    state["channel_errors"] = dict(RUNTIME["channel_errors"])
    save_state(state)


def restore_channel_runtime():
    state = load_state()
    valid_channels = set(CHANNEL_CONFIG_FIELDS)
    RUNTIME["channel_tests"] = {
        channel: status
        for channel, status in state.get("channel_tests", {}).items()
        if channel in valid_channels and status in ("success", "error")
    }
    RUNTIME["channel_errors"] = {
        channel: str(error)[:300]
        for channel, error in state.get("channel_errors", {}).items()
        if channel in valid_channels
    }


def restart_current_process():
    os.execv(sys.executable, [sys.executable, str(Path(__file__).resolve())])


def public_config(cfg):
    result = {k: cfg.get(k, v) for k, v in DEFAULTS.items() if k not in HIDDEN_LEGACY_FIELDS}
    for key in SECRET_FIELDS:
        result[key + "_set"] = bool(cfg.get(key))
        result[key] = ""
    return result


def log_event(kind, message, **extra):
    item = {"time": utcnow(), "kind": kind, "message": message, **extra}
    with LOCK:
        with LOG_FILE.open("a", encoding="utf-8") as f:
            f.write(json.dumps(item, ensure_ascii=False) + "\n")


def all_logs():
    if not LOG_FILE.exists():
        return []
    out = []
    for line in LOG_FILE.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    return out


def paged_logs(page=1, page_size=20):
    items = list(reversed(all_logs()))
    page_size = bounded_int(page_size, 20, 10, 100)
    total = len(items)
    pages = max(1, (total + page_size - 1) // page_size)
    page = min(bounded_int(page, 1, 1, 1_000_000), pages)
    start = (page - 1) * page_size
    return {"items": items[start:start + page_size], "total": total, "page": page, "page_size": page_size, "pages": pages}


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


def logs_csv():
    output = io.StringIO()
    writer = csv.writer(output, lineterminator="\n")
    writer.writerow(["时间", "事件"])
    for item in reversed(all_logs()):
        kind = str(item.get("kind", "event"))
        message = str(item.get("message", ""))
        writer.writerow([item.get("time", ""), f"[{kind}] {message}".strip()])
    return output.getvalue()


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

    def submit_pdu(self, pdu_hex, tpdu_length, timeout=120):
        """Submit one SMS PDU after the modem presents the CMGS prompt."""
        termios.tcflush(self.fd, termios.TCIFLUSH)
        os.write(self.fd, f"AT+CMGS={tpdu_length}\r".encode("ascii"))
        prompt_end, data = time.monotonic() + 8, bytearray()
        while time.monotonic() < prompt_end:
            ready, _, _ = select.select([self.fd], [], [], min(0.25, prompt_end - time.monotonic()))
            if not ready:
                continue
            chunk = os.read(self.fd, 8192)
            if chunk:
                data.extend(chunk)
                text = data.decode("utf-8", "replace")
                if ">" in text:
                    break
                if "ERROR" in text or "+CMS ERROR:" in text or "+CME ERROR:" in text:
                    raise RuntimeError(text.strip())
        else:
            raise TimeoutError("IG830 未返回短信发送提示符")

        os.write(self.fd, pdu_hex.encode("ascii") + b"\x1a")
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            ready, _, _ = select.select([self.fd], [], [], min(0.5, end - time.monotonic()))
            if not ready:
                continue
            chunk = os.read(self.fd, 8192)
            if chunk:
                data.extend(chunk)
                text = data.decode("utf-8", "replace")
                if "+CMS ERROR:" in text or "+CME ERROR:" in text or "\r\nERROR\r\n" in text:
                    raise RuntimeError(text.strip())
                if "+CMGS:" in text and "\r\nOK\r\n" in text:
                    return text
        raise TimeoutError("IG830 短信发送超时，结果未知；请勿立即重复发送")


def normalize_sms_recipient(value):
    number = re.sub(r"[\s-]", "", str(value or "").strip())
    if not re.fullmatch(r"\+?[0-9]{5,15}", number):
        raise ValueError("接收号码应为 5-15 位数字，可使用 + 国际区号；不支持多个号码")
    return number


def build_sms_submit_pdu(recipient, message):
    """Build a single-part UCS2 SMS-SUBMIT PDU using the SIM's stored SMSC."""
    number = normalize_sms_recipient(recipient)
    body = str(message or "")
    if not body.strip():
        raise ValueError("短信内容不能为空")
    if any(ord(char) < 32 and char not in "\r\n\t" for char in body):
        raise ValueError("短信内容包含不支持的控制字符")
    user_data = body.encode("utf-16-be")
    if len(user_data) > 140:
        raise ValueError("单条短信最多 70 个 UCS2 字符，请缩短内容")

    digits = number.lstrip("+")
    padded = digits + ("F" if len(digits) % 2 else "")
    semi_octets = "".join(padded[index + 1] + padded[index] for index in range(0, len(padded), 2))
    type_of_address = "91" if number.startswith("+") else "81"
    tpdu_header = f"0100{len(digits):02X}{type_of_address}{semi_octets}0008{len(user_data):02X}"
    tpdu = bytes.fromhex(tpdu_header) + user_data
    pdu = b"\x00" + tpdu
    return pdu.hex().upper(), len(tpdu), number


def mask_phone_number(number):
    digits = str(number or "")
    if len(digits) <= 7:
        return "*" * max(1, len(digits) - 2) + digits[-2:]
    return digits[:3] + "*" * (len(digits) - 7) + digits[-4:]


def send_outbound_sms(recipient, message, confirm, remote=""):
    global LAST_OUTBOUND_SMS_AT
    if confirm != "我确认号码和内容无误，同意发送此短信":
        raise ValueError("请勾选号码与内容确认后再发送")
    pdu_hex, tpdu_length, number = build_sms_submit_pdu(recipient, message)
    masked = mask_phone_number(number)
    with MODEM_LOCK:
        elapsed = time.monotonic() - LAST_OUTBOUND_SMS_AT
        if LAST_OUTBOUND_SMS_AT and elapsed < OUTBOUND_SMS_COOLDOWN:
            raise ValueError(f"发送冷却中，请等待 {int(OUTBOUND_SMS_COOLDOWN - elapsed) + 1} 秒")
        LAST_OUTBOUND_SMS_AT = time.monotonic()
        modem = Modem(load_config().get("serial_port", "/dev/ttyUSB2"))
        try:
            if "+CPIN: READY" not in modem.command("AT+CPIN?", 6):
                raise RuntimeError("SIM 卡尚未就绪")
            if "OK" not in modem.command("AT+CMGF=0", 6):
                raise RuntimeError("IG830 无法切换到 PDU 短信模式")
            response = modem.submit_pdu(pdu_hex, tpdu_length)
        finally:
            modem.close()

    reference_match = re.search(r"\+CMGS:\s*(\d+)", response)
    sent_at = utcnow()
    RUNTIME["last_sms_sent"] = sent_at
    reference = reference_match.group(1) if reference_match else ""
    log_event("sms.outbound", "主动短信发送成功", recipient=masked, reference=reference)
    DB.audit("sms.send", f"recipient={masked} reference={reference or '-'}", remote)
    return {"ok": True, "recipient_masked": masked, "message_reference": reference, "sent_at": sent_at}


def at_value(raw, prefix):
    for line in raw.replace("\r", "").split("\n"):
        line = line.strip()
        if line.startswith(prefix):
            return line[len(prefix):].strip()
    return ""


def parse_cnum(raw):
    match = re.search(r'\+CNUM:\s*"[^"]*",\s*"([^"]+)"', raw or "")
    return match.group(1).strip() if match else ""


def clear_network_status(reason="设备离线"):
    with LOCK:
        RUNTIME.update({
            "sim_ready": False,
            "phone_number": "",
            "signal_rssi": None,
            "signal_dbm": None,
            "signal_level": 0,
            "operator": "",
            "registered": False,
            "registration": reason,
        })


def update_network_status(modem):
    RUNTIME["sim_ready"] = "+CPIN: READY" in modem.command("AT+CPIN?")
    try:
        RUNTIME["phone_number"] = parse_cnum(modem.command("AT+CNUM"))
    except (TimeoutError, OSError):
        RUNTIME["phone_number"] = ""
    csq = at_value(modem.command("AT+CSQ"), "+CSQ:")
    try:
        rssi = int(csq.split(",", 1)[0])
    except (ValueError, IndexError):
        rssi = 99
    RUNTIME["signal_rssi"] = None if rssi == 99 else rssi
    RUNTIME["signal_dbm"] = None if rssi == 99 else -113 + 2 * rssi
    RUNTIME["signal_level"] = 0 if rssi == 99 else (1 if rssi <= 6 else 2 if rssi <= 12 else 3 if rssi <= 18 else 4 if rssi <= 24 else 5)
    cops = at_value(modem.command("AT+COPS?"), "+COPS:")
    quoted = cops.split('"')
    RUNTIME["operator"] = quoted[1] if len(quoted) >= 3 else ""
    reg_raw = at_value(modem.command("AT+CEREG?"), "+CEREG:")
    if not reg_raw:
        reg_raw = at_value(modem.command("AT+CREG?"), "+CREG:")
    try:
        reg = int(reg_raw.split(",")[1])
    except (ValueError, IndexError):
        reg = -1
    labels = {-1: "未知", 0: "未注册", 1: "已注册（本地）", 2: "正在搜索", 3: "注册被拒绝", 4: "未知", 5: "已注册（漫游）"}
    RUNTIME["registered"] = reg in (1, 5)
    RUNTIME["registration"] = labels.get(reg, f"状态 {reg}")


def parse_usb_config(raw):
    match = re.search(r'\+QCFG:\s*["“]usbcfg["”]\s*,\s*(0x[0-9A-Fa-f]+)\s*,\s*(0x[0-9A-Fa-f]+)\s*,\s*([0-9,\s]+)', raw)
    if not match:
        raise ValueError("模块未返回可识别的 usbcfg 参数")
    tail = [int(x.strip()) for x in match.group(3).split(",") if x.strip() != ""]
    if len(tail) < 7 or any(x not in (0, 1) for x in tail):
        raise ValueError("usbcfg 接口参数异常，已拒绝继续")
    return {"vid": int(match.group(1), 16), "pid": int(match.group(2), 16), "tail": tail, "raw": match.group(0)}


def usb_config_command(cfg, vid, pid):
    tail = ",".join(str(x) for x in cfg["tail"])
    return f'AT+QCFG="usbcfg",0x{vid:04X},0x{pid:04X},{tail}'


def read_modem_usb_config(save_factory_backup=True):
    cfg = load_config()
    with MODEM_LOCK:
        modem = Modem(cfg["serial_port"])
        try:
            modem.command("ATE0")
            identity = modem.command("ATI")
            raw = modem.command('AT+QCFG="usbcfg"')
        finally:
            modem.close()
    parsed = parse_usb_config(raw)
    result = {
        "identity": " ".join(x.strip() for x in identity.replace("\r", "").split("\n") if x.strip() not in ("OK", "ATI")),
        "vid": f"{parsed['vid']:04x}", "pid": f"{parsed['pid']:04x}",
        "tail": parsed["tail"], "raw": parsed["raw"],
        "is_factory": parsed["vid"] == 0x2CA3 and parsed["pid"] == 0x4006,
        "is_compatible": parsed["vid"] == 0x2C7C and parsed["pid"] == 0x0125,
        "backup_exists": USB_BACKUP_FILE.exists(),
    }
    if save_factory_backup and result["is_factory"] and not USB_BACKUP_FILE.exists():
        backup = {**result, "saved_at": utcnow(), "command": usb_config_command(parsed, parsed["vid"], parsed["pid"])}
        USB_BACKUP_FILE.write_text(json.dumps(backup, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        os.chmod(USB_BACKUP_FILE, 0o600)
        result["backup_exists"] = True
    return result


def apply_compatible_usb_config(confirm_text):
    if confirm_text != "我已备份并确认修改IG830":
        raise ValueError("风险确认无效，请重新勾选后操作")
    current = read_modem_usb_config(save_factory_backup=True)
    if not current["is_factory"]:
        raise ValueError("仅允许从大疆原始 2ca3:4006 状态转换")
    if "QDC507" not in current["identity"] and "Baiwang" not in current["identity"]:
        raise ValueError("硬件身份不是已验证的 Baiwang QDC507，已拒绝写入")
    parsed = {"tail": current["tail"]}
    command = usb_config_command(parsed, 0x2C7C, 0x0125)
    with MODEM_LOCK:
        modem = Modem(load_config()["serial_port"])
        try:
            response = modem.command(command, timeout=8)
        finally:
            modem.close()
    if "OK" not in response:
        raise RuntimeError("模块未确认写入成功")
    log_event("hardware", "已写入 Linux 兼容 USB ID，等待用户重启模块")
    return {"ok": True, "target": "2c7c:0125", "restart_required": True}


def restore_factory_usb_config(confirm_text):
    if confirm_text != "我确认恢复IG830出厂USB参数":
        raise ValueError("风险确认无效，请重新勾选后操作")
    if not USB_BACKUP_FILE.exists():
        raise ValueError("没有找到本机原始参数备份")
    backup = json.loads(USB_BACKUP_FILE.read_text(encoding="utf-8"))
    command = backup.get("command", "")
    if not re.fullmatch(r'AT\+QCFG="usbcfg",0x2CA3,0x4006(?:,[01])+', command):
        raise ValueError("备份内容未通过安全校验")
    with MODEM_LOCK:
        modem = Modem(load_config()["serial_port"])
        try:
            response = modem.command(command, timeout=8)
        finally:
            modem.close()
    if "OK" not in response:
        raise RuntimeError("模块未确认恢复成功")
    log_event("hardware", "已写回本机出厂 USB 参数，等待用户重启模块")
    return {"ok": True, "target": "2ca3:4006", "restart_required": True}


def restart_modem(confirm_text):
    if confirm_text != "确认重启IG830":
        raise ValueError("风险确认无效，请重新勾选后操作")
    with MODEM_LOCK:
        modem = Modem(load_config()["serial_port"])
        try:
            try:
                response = modem.command("AT+CFUN=1,1", timeout=3)
            except (TimeoutError, OSError):
                response = "restart command sent"
        finally:
            try:
                modem.close()
            except OSError:
                pass
    log_event("hardware", "用户已重启 IG830，USB 将重新枚举")
    return {"ok": True, "message": response.strip() or "restart command sent"}


def mask_identifier(value):
    digits = "".join(x for x in value if x.isdigit())
    return ("*" * max(0, len(digits)-4) + digits[-4:]) if digits else ""


def modem_capabilities():
    cfg=load_config(); results={"devices":sorted(str(x) for x in Path('/dev').glob('ttyUSB*'))}
    with MODEM_LOCK:
        modem=Modem(cfg["serial_port"])
        try:
            modem.command("ATE0")
            def safe(cmd):
                try:return modem.command(cmd,timeout=3)
                except Exception as e:return f"ERROR: {e}"
            results["identity"]=safe("ATI")
            results["sim_state"]=at_value(safe("AT+CPIN?"),"+CPIN:") or "不可用"
            results["iccid_masked"]=mask_identifier(at_value(safe("AT+QCCID"),"+QCCID:"))
            results["imsi_masked"]=mask_identifier(safe("AT+CIMI"))
            results["sms_send_supported"]="ERROR" not in safe("AT+CMGF=?") and "ERROR" not in safe("AT+CMGS=?")
            results["ussd_supported"]="ERROR" not in safe("AT+CUSD=?")
            results["esim_supported"]="ERROR" not in safe("AT+QESIM=?")
            results["network_mode"]=at_value(safe('AT+QCFG="nwscanmode"'),'+QCFG:')
            results["band_configurable"]="ERROR" not in safe('AT+QCFG="band"')
        finally:modem.close()
    results["vowifi_supported"]=False
    results["data_dialing_supported"]=Path('/dev/cdc-wdm0').exists()
    return results


def run_ussd(code, confirm):
    if confirm!="确认执行USSD":raise ValueError("风险确认无效，请重新勾选后操作")
    if not re.fullmatch(r"[0-9*#]{2,32}",code):raise ValueError("USSD 代码格式无效")
    with MODEM_LOCK:
        modem=Modem(load_config()["serial_port"])
        try: response=modem.command(f'AT+CUSD=1,"{code}",15',timeout=15)
        finally:modem.close()
    DB.audit("modem.ussd","code redacted")
    return {"response":response}


def unlock_sim_pin(pin, confirm):
    if confirm!="确认解锁SIM":raise ValueError("风险确认无效，请重新勾选后操作")
    if not re.fullmatch(r"[0-9]{4,8}",pin):raise ValueError("PIN 格式无效")
    with MODEM_LOCK:
        modem=Modem(load_config()["serial_port"])
        try: response=modem.command(f'AT+CPIN="{pin}"',timeout=10)
        finally:modem.close()
    DB.audit("sim.unlock","PIN redacted")
    return {"ok":"OK" in response}


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
    for message in out:
        message["_fingerprint_sender"] = message["sender"]
        message["_fingerprint_message"] = message["message"]
        message["sender"] = decode_modem_text(message["sender"])
        message["message"] = decode_modem_text(message["message"])
    return out


GSM7_ALPHABET = (
    "@£$¥èéùìòÇ\nØø\rÅåΔ_ΦΓΛΩΠΨΣΘΞ\x1bÆæßÉ "
    "!\"#¤%&'()*+,-./0123456789:;<=>?¡"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZÄÖÑÜ§¿"
    "abcdefghijklmnopqrstuvwxyzäöñüà"
)


def swap_bcd(octet):
    return ((octet & 0x0F) * 10) + ((octet >> 4) & 0x0F)


def decode_semi_octets(data, digits):
    value = "".join(f"{byte & 0x0F:X}{(byte >> 4) & 0x0F:X}" for byte in data)
    return value[:digits].replace("F", "")


def decode_scts(data):
    if len(data) != 7:
        return ""
    values = [swap_bcd(byte) for byte in data[:6]]
    tz_byte = data[6]
    negative = bool(tz_byte & 0x08)
    tz_value = swap_bcd(tz_byte & 0xF7)
    sign = "-" if negative else "+"
    return (
        f"{values[0]:02d}/{values[1]:02d}/{values[2]:02d},"
        f"{values[3]:02d}:{values[4]:02d}:{values[5]:02d}{sign}{tz_value:02d}"
    )


def unpack_gsm7(data, septet_count, skip_septets=0):
    chars = []
    escaped = False
    for index in range(skip_septets, septet_count):
        bit = index * 7
        byte_index, shift = divmod(bit, 8)
        if byte_index >= len(data):
            break
        value = (data[byte_index] >> shift) & 0x7F
        if shift > 1 and byte_index + 1 < len(data):
            value |= (data[byte_index + 1] << (8 - shift)) & 0x7F
        if escaped:
            chars.append({10: "\f", 20: "^", 40: "{", 41: "}", 47: "\\", 60: "[", 61: "~", 62: "]", 64: "|", 101: "€"}.get(value, "?"))
            escaped = False
        elif value == 0x1B:
            escaped = True
        else:
            chars.append(GSM7_ALPHABET[value] if value < len(GSM7_ALPHABET) else "?")
    return "".join(chars)


def parse_concat_udh(header):
    cursor = 0
    while cursor + 2 <= len(header):
        iei, length = header[cursor], header[cursor + 1]
        value = header[cursor + 2:cursor + 2 + length]
        cursor += 2 + length
        if iei == 0x00 and length == 3:
            return {"ref": value[0], "total": value[1], "part": value[2]}
        if iei == 0x08 and length == 4:
            return {"ref": int.from_bytes(value[:2], "big"), "total": value[2], "part": value[3]}
    return None


def decode_deliver_pdu(pdu_hex, index=0):
    """Decode an SMS-DELIVER PDU and retain UDH concatenation metadata."""
    compact = re.sub(r"\s+", "", str(pdu_hex or ""))
    if not compact or len(compact) % 2 or not re.fullmatch(r"[0-9A-Fa-f]+", compact):
        raise ValueError("短信 PDU 格式无效")
    data = bytes.fromhex(compact)
    cursor = 0
    smsc_length = data[cursor]
    cursor += 1 + smsc_length
    first_octet = data[cursor]
    cursor += 1
    if first_octet & 0x03 != 0:
        raise ValueError("不是 SMS-DELIVER PDU")
    address_digits = data[cursor]
    cursor += 1
    address_type = data[cursor]
    cursor += 1
    address_length = (address_digits + 1) // 2
    sender = decode_semi_octets(data[cursor:cursor + address_length], address_digits)
    cursor += address_length
    if address_type & 0x70 == 0x10:
        sender = "+" + sender
    cursor += 1  # PID
    dcs = data[cursor]
    cursor += 1
    received_at = decode_scts(data[cursor:cursor + 7])
    cursor += 7
    udl = data[cursor]
    cursor += 1
    user_data = data[cursor:]
    concat = None
    header_bytes = 0
    if first_octet & 0x40 and user_data:
        header_bytes = min(len(user_data), user_data[0] + 1)
        concat = parse_concat_udh(user_data[1:header_bytes])
    if dcs & 0x0C == 0x08:
        payload = user_data[header_bytes:udl]
        message = payload.decode("utf-16-be", "replace")
    elif dcs & 0x0C == 0x04:
        message = user_data[header_bytes:udl].decode("latin-1", "replace")
    else:
        header_septets = (header_bytes * 8 + 6) // 7 if header_bytes else 0
        message = unpack_gsm7(user_data, udl, header_septets)
    return {
        "index": index,
        "sender": sender,
        "received_at": received_at,
        "message": message,
        "_concat": concat,
        "_fingerprint_sender": sender,
        "_fingerprint_message": message,
    }


def merge_concatenated_messages(messages):
    singles, groups = [], {}
    for message in messages:
        concat = message.get("_concat")
        if not concat or concat.get("total", 0) < 2:
            message.pop("_concat", None)
            singles.append(message)
            continue
        key = (message.get("sender", ""), concat["ref"], concat["total"])
        groups.setdefault(key, []).append(message)
    for (_, _, total), parts in groups.items():
        by_part = {item["_concat"]["part"]: item for item in parts}
        if len(by_part) != total or any(part not in by_part for part in range(1, total + 1)):
            continue
        first = by_part[1]
        joined = dict(first)
        joined["message"] = "".join(by_part[part]["message"] for part in range(1, total + 1))
        joined["index"] = min(item["index"] for item in parts)
        joined["_fingerprint_message"] = joined["message"]
        joined.pop("_concat", None)
        singles.append(joined)
    return sorted(singles, key=lambda item: item.get("index", 0))


def parse_cmgl_pdu(raw):
    lines = [line.strip() for line in str(raw or "").replace("\r", "").split("\n") if line.strip()]
    messages = []
    decoded_any = False
    saw_header = False
    for position, line in enumerate(lines):
        if not line.startswith("+CMGL:") or position + 1 >= len(lines):
            continue
        saw_header = True
        try:
            index = int(line.split(":", 1)[1].split(",", 1)[0].strip())
            messages.append(decode_deliver_pdu(lines[position + 1], index))
            decoded_any = True
        except (ValueError, IndexError):
            continue
    if not saw_header:
        return []
    return merge_concatenated_messages(messages) if decoded_any else None


def decode_modem_text(value):
    """Decode UCS2 hex returned by the modem without changing ordinary OTP text."""
    text = str(value or "").strip()
    compact = re.sub(r"\s+", "", text)
    if len(compact) < 4 or len(compact) % 4 or not re.fullmatch(r"[0-9A-Fa-f]+", compact):
        return text
    try:
        decoded = bytes.fromhex(compact).decode("utf-16-be")
    except (ValueError, UnicodeDecodeError):
        return text
    if not decoded or any(not char.isprintable() and char not in "\r\n\t" for char in decoded):
        return text
    code_units = [int(compact[index:index + 4], 16) for index in range(0, len(compact), 4)]
    ascii_units = sum(unit <= 0x7F for unit in code_units)
    cjk_units = sum(
        0x3400 <= unit <= 0x4DBF or 0x4E00 <= unit <= 0x9FFF or 0xF900 <= unit <= 0xFAFF
        for unit in code_units
    )
    if ascii_units >= 2 or cjk_units >= 2:
        return decoded
    return text


def migrate_stored_message_encoding():
    changed = DB.transform_message_bodies(decode_modem_text)
    duplicates = DB.deduplicate_messages()
    fragments = DB.merge_contained_message_parts()
    if changed:
        log_event("storage", "已修复历史短信字符编码", messages=changed)
    if duplicates:
        log_event("storage", "已合并重复短信记录", messages=duplicates)
    if fragments:
        log_event("storage", "已合并历史长短信分片", messages=fragments)
    return changed


def post_json(url, payload, headers=None, method="POST", timeout=15, max_body=1_000_000):
    data = json.dumps(payload, ensure_ascii=False).encode()
    request_headers = {"Content-Type": "application/json", "User-Agent": f"NexRelay-sdjoint/{APP_VERSION}"}
    request_headers.update(headers or {})
    req = urllib.request.Request(url, data=data, headers=request_headers, method=method)
    with urllib.request.urlopen(req, timeout=timeout) as res:
        body = res.read(max_body).decode("utf-8", "replace")
        if not 200 <= res.status < 300:
            raise RuntimeError(f"HTTP {res.status}: {body[:200]}")
        return {"status": res.status, "body": body}


def notification_title(cfg, test=False):
    key = "test_notification_title" if test else "notification_title"
    fallback = "IG830 测试消息" if test else "IG830 收到短信"
    title = str(cfg.get(key, fallback) or fallback).strip()
    if title.startswith("【") and title.endswith("】"):
        title = title[1:-1].strip()
    return title or fallback


def sms_text(sms, cfg, test=False):
    title = notification_title(cfg, test)
    return f"【{title}】\n发送方：{sms['sender']}\n时间：{sms['received_at']}\n内容：{sms['message']}"


def send_channel(channel, cfg, sms, test=False):
    title = notification_title(cfg, test)
    text = sms_text(sms, cfg, test)
    if channel == "custom":
        url = cfg.get("webhook_url", "").strip()
        if not url.startswith(("http://", "https://")):
            raise ValueError("自定义 Webhook URL 未配置")
        payload = {"event": "test" if test else "sms.received", "device": "IG830", "title": title, "formatted_text": text, **sms}
        headers = {}
        if cfg.get("auth_header") and cfg.get("auth_value"):
            headers[cfg["auth_header"]] = cfg["auth_value"]
        return post_json(url, payload, headers, cfg.get("http_method", "POST"))
    if channel == "dingtalk":
        url = cfg.get("dingtalk_webhook", "").strip()
        if not url:
            raise ValueError("钉钉 Webhook 未配置")
        secret = cfg.get("dingtalk_secret", "").strip()
        if secret:
            import base64
            timestamp = str(int(time.time() * 1000))
            digest = hmac.new(secret.encode(), f"{timestamp}\n{secret}".encode(), hashlib.sha256).digest()
            sign = urllib.parse.quote_plus(base64.b64encode(digest).decode())
            url += ("&" if "?" in url else "?") + f"timestamp={timestamp}&sign={sign}"
        return post_json(url, {"msgtype": "text", "text": {"content": text}})
    if channel == "feishu":
        url = cfg.get("feishu_webhook", "").strip()
        if not url:
            raise ValueError("飞书 Webhook 未配置")
        return post_json(url, {"msg_type": "text", "content": {"text": text}})
    if channel == "wecom":
        url = cfg.get("wecom_webhook", "").strip()
        if not url:
            raise ValueError("企业微信 Webhook 未配置")
        return post_json(url, {"msgtype": "text", "text": {"content": text}})
    if channel == "telegram":
        token = cfg.get("telegram_bot_token", "").strip()
        chat_id = cfg.get("telegram_chat_id", "").strip()
        if not token or not chat_id:
            raise ValueError("Telegram Bot Token 或 Chat ID 未配置")
        payload = {"chat_id": chat_id, "text": text}
        if not test and cfg.get("telegram_reply_enabled"):
            payload["text"] += "\n\n↩️ 如需回复短信，请使用 Telegram 的“回复”功能回复本消息。回复内容将通过当前 SIM 卡发送给原发件人。"
            payload["reply_markup"] = {
                "force_reply": True,
                "input_field_placeholder": "回复将通过 SIM 卡发送短信",
                "selective": True,
            }
        result = post_json(f"https://api.telegram.org/bot{token}/sendMessage", payload)
        try:
            response = json.loads(result["body"])
            if not response.get("ok"):
                raise RuntimeError(response.get("description", "Telegram 返回失败"))
            telegram_message_id = response.get("result", {}).get("message_id")
            stored_message_id = sms.get("_stored_message_id")
            if not test and telegram_message_id is not None and stored_message_id is not None:
                DB.link_telegram_message(chat_id, telegram_message_id, stored_message_id)
        except (json.JSONDecodeError, TypeError, ValueError) as error:
            log_event("error", "Telegram 回执映射失败", error=str(error))
        return result
    if channel == "wechat":
        token = cfg.get("wechat_pushplus_token", "").strip()
        if not token:
            raise ValueError("微信 PushPlus Token 未配置")
        payload = {"token": token, "title": title, "content": text, "template": "txt", "channel": "wechat"}
        topic = cfg.get("wechat_topic", "").strip()
        if topic:
            payload["topic"] = topic
        result = post_json("https://www.pushplus.plus/send", payload)
        try:
            response = json.loads(result["body"])
            if int(response.get("code", 0)) != 200:
                raise RuntimeError(response.get("msg", "PushPlus 返回失败"))
        except json.JSONDecodeError:
            raise RuntimeError("PushPlus 返回内容无法解析")
        return result
    if channel == "email":
        host, user, password = cfg.get("smtp_host", ""), cfg.get("smtp_user", ""), cfg.get("smtp_password", "")
        recipients = [x.strip() for x in cfg.get("smtp_to", "").split(",") if x.strip()]
        if not host or not user or not password or not recipients:
            raise ValueError("邮件 SMTP 配置不完整")
        from email.message import EmailMessage
        msg = EmailMessage(); msg["Subject"]=title; msg["From"]=user; msg["To"]=", ".join(recipients); msg.set_content(text)
        with smtplib.SMTP_SSL(host, int(cfg.get("smtp_port",465)), context=ssl.create_default_context(), timeout=15) as smtp:
            smtp.login(user,password); smtp.send_message(msg)
        return {"status":200,"body":"sent"}
    if channel == "bark":
        url=cfg.get("bark_url","").strip()
        if not url: raise ValueError("Bark URL 未配置")
        return post_json(url,{"title":title,"body":text})
    if channel == "ntfy":
        url=cfg.get("ntfy_url","").strip()
        if not url: raise ValueError("ntfy URL 未配置")
        return post_json(url,{"title":title,"message":text})
    if channel == "mqtt":
        url=cfg.get("mqtt_webhook","").strip()
        if not url: raise ValueError("MQTT 桥接 Webhook 未配置")
        return post_json(url,{"topic":"ig830/sms","title":title,"payload":text,"sms":sms})
    raise ValueError("未知通知通道")


def enabled_channels(cfg):
    channels = []
    if cfg.get("webhook_url"):
        channels.append("custom")
    for name in ("dingtalk", "feishu", "wecom", "telegram", "wechat", "bark", "ntfy", "mqtt"):
        if cfg.get(name + "_enabled"):
            channels.append(name)
    if cfg.get("smtp_enabled"):
        channels.append("email")
    return channels


def deliver_sms(cfg, sms):
    channels = enabled_channels(cfg)
    if not channels:
        raise ValueError("没有启用任何通知通道")
    errors = []
    for channel in channels:
        try:
            send_channel(channel, cfg, sms)
            log_event("channel", f"{channel} 发送成功", sender=sms["sender"])
        except Exception as e:
            errors.append(f"{channel}: {e}")
    if errors:
        raise RuntimeError("; ".join(errors))


def poll_once():
    cfg = load_config()
    with MODEM_LOCK:
        modem = Modem(cfg["serial_port"])
        try:
            modem.command("ATE0")
            update_network_status(modem)
            if not cfg.get("enabled"):
                return
            if not RUNTIME["sim_ready"]:
                raise RuntimeError("SIM 未就绪")
            state = load_state()
            seen = set(state.get("seen", []))
            if "OK" not in modem.command("AT+CMGF=0"):
                raise RuntimeError("模块不支持短信 PDU 模式")
            raw = modem.command("AT+CMGL=4", timeout=8)
            messages = parse_cmgl_pdu(raw)
            if messages is None:
                # Some firmware reports non-standard PDU output. Preserve the
                # proven text-mode reader as a safe fallback for that hardware.
                if "OK" not in modem.command("AT+CMGF=1"):
                    raise RuntimeError("模块短信 PDU 无法解析，且不支持文本模式")
                messages = parse_cmgl(modem.command('AT+CMGL="ALL"', timeout=8))
            for sms in messages:
                fingerprint_sender = sms.get("_fingerprint_sender", sms["sender"])
                fingerprint_message = sms.get("_fingerprint_message", sms["message"])
                key = hashlib.sha256(f"{sms['index']}|{fingerprint_sender}|{sms['received_at']}|{fingerprint_message}".encode()).hexdigest()
                allowed = should_forward(sms["sender"], sms["message"], cfg)
                message_id = DB.store_message(key, sms, filtered=not allowed)
                if key not in seen and allowed and (cfg.get("forward_existing") or state.get("initialized")):
                    DB.enqueue(message_id, enabled_channels(cfg))
                elif not allowed:
                    log_event("filter", "短信被规则忽略", sender=sms["sender"], index=sms["index"])
                seen.add(key)
            state["initialized"] = True
            state["seen"] = list(seen)[-2000:]
            save_state(state)
        finally:
            modem.close()


def telegram_reply_offset(token):
    state = load_state()
    token_fingerprint = hashlib.sha256(token.encode()).hexdigest()[:16]
    if state.get("telegram_reply_token") != token_fingerprint:
        state["telegram_reply_token"] = token_fingerprint
        state["telegram_reply_offset"] = 0
        save_state(state)
    return bounded_int(state.get("telegram_reply_offset", 0), 0, 0, 2_147_483_647)


def save_telegram_reply_offset(token, offset):
    state = load_state()
    state["telegram_reply_token"] = hashlib.sha256(token.encode()).hexdigest()[:16]
    state["telegram_reply_offset"] = max(0, int(offset))
    save_state(state)


def telegram_get_updates(token, offset):
    result = post_json(
        f"https://api.telegram.org/bot{token}/getUpdates",
        {"offset": offset, "timeout": 20, "allowed_updates": ["message"]},
        timeout=25,
    )
    response = json.loads(result["body"])
    if not response.get("ok"):
        raise RuntimeError(response.get("description", "Telegram getUpdates 失败"))
    updates = response.get("result", [])
    return updates if isinstance(updates, list) else []


def telegram_reply_request(update, cfg, storage=DB):
    if not cfg.get("telegram_reply_enabled") or not isinstance(update, dict):
        return None
    message = update.get("message")
    if not isinstance(message, dict) or not isinstance(message.get("text"), str):
        return None
    chat = message.get("chat") or {}
    chat_id = str(chat.get("id", ""))
    if not chat_id or chat_id != str(cfg.get("telegram_chat_id", "")).strip():
        return None
    sender = message.get("from") or {}
    if sender.get("is_bot"):
        return None
    allowed_user_id = str(cfg.get("telegram_reply_user_id", "")).strip()
    sender_user_id = str(sender.get("id", ""))
    if allowed_user_id and sender_user_id != allowed_user_id:
        return None
    if chat.get("type") != "private" and not allowed_user_id:
        return None
    body = message["text"].strip()
    if not body or body.startswith("/"):
        return None
    replied = message.get("reply_to_message") or {}
    replied_message_id = replied.get("message_id")
    if replied_message_id is None:
        return None
    target = storage.telegram_reply_target(chat_id, replied_message_id)
    if not target:
        return None
    return {
        "update_id": int(update.get("update_id", 0)),
        "telegram_message_id": int(replied_message_id),
        "telegram_user_message_id": int(message.get("message_id", 0)),
        "chat_id": chat_id,
        "body": body,
        "target": target,
    }


def telegram_bot_notice(cfg, text, reply_to_message_id):
    token = cfg.get("telegram_bot_token", "").strip()
    chat_id = cfg.get("telegram_chat_id", "").strip()
    if not token or not chat_id:
        return
    payload = {"chat_id": chat_id, "text": text}
    if reply_to_message_id:
        payload["reply_parameters"] = {"message_id": int(reply_to_message_id)}
    post_json(f"https://api.telegram.org/bot{token}/sendMessage", payload)


def handle_telegram_reply(update, cfg, storage=DB, sms_sender=send_outbound_sms):
    request = telegram_reply_request(update, cfg, storage)
    if not request:
        return False
    target = request["target"]
    masked = mask_phone_number(target["sender"])
    if not storage.claim_telegram_reply(
        request["update_id"], request["chat_id"], request["telegram_message_id"],
        target["message_id"], masked,
    ):
        return False
    try:
        result = sms_sender(
            target["sender"], request["body"], "我确认号码和内容无误，同意发送此短信",
            f"telegram:{request['chat_id']}",
        )
        storage.finish_telegram_reply(request["update_id"], "sent")
        RUNTIME["telegram_reply_last_at"] = result.get("sent_at", utcnow())
        log_event("telegram.reply", "Telegram 回复已通过 SIM 发送", recipient=masked, update_id=request["update_id"])
        try:
            telegram_bot_notice(cfg, f"✅ 短信已通过 SIM 卡发送至 {masked}", request["telegram_user_message_id"])
        except Exception as notice_error:
            log_event("error", "Telegram 发送成功回执失败", error=str(notice_error))
        return True
    except Exception as error:
        storage.finish_telegram_reply(request["update_id"], "failed", str(error))
        log_event("error", "Telegram 回复短信发送失败", recipient=masked, error=str(error))
        try:
            telegram_bot_notice(cfg, f"❌ 短信发送失败：{str(error)[:160]}", request["telegram_user_message_id"])
        except Exception as notice_error:
            log_event("error", "Telegram 失败回执发送失败", error=str(notice_error))
        return False


def telegram_reply_worker():
    last_reported_error = ""
    while True:
        cfg = load_config()
        token = cfg.get("telegram_bot_token", "").strip()
        chat_id = cfg.get("telegram_chat_id", "").strip()
        if not cfg.get("telegram_reply_enabled"):
            RUNTIME["telegram_reply_status"] = "已停用"
            RUNTIME["telegram_reply_error"] = ""
            time.sleep(3)
            continue
        if not cfg.get("telegram_enabled") or not token or not chat_id:
            RUNTIME["telegram_reply_status"] = "配置不完整"
            RUNTIME["telegram_reply_error"] = "请先启用 Telegram 并配置 Bot Token 与 Chat ID"
            time.sleep(3)
            continue
        try:
            offset = telegram_reply_offset(token)
            updates = telegram_get_updates(token, offset)
            for update in updates:
                handle_telegram_reply(update, cfg)
            if updates:
                next_offset = max(int(item.get("update_id", 0)) for item in updates) + 1
                save_telegram_reply_offset(token, next_offset)
            RUNTIME["telegram_reply_status"] = "监听中"
            RUNTIME["telegram_reply_error"] = ""
            last_reported_error = ""
        except Exception as error:
            message = str(error)[:300]
            RUNTIME["telegram_reply_status"] = "监听异常"
            RUNTIME["telegram_reply_error"] = message
            if message != last_reported_error:
                log_event("error", "Telegram 反向回复监听失败", error=message)
                last_reported_error = message
            time.sleep(5)


def worker():
    global LAST_POLL_ERROR
    while True:
        cfg = load_config()
        try:
            poll_once()
            cfg = load_config()
            for delivery in DB.due_deliveries():
                sms = {"sender":delivery["sender"],"message":delivery["body"],"received_at":delivery["received_at"],"index":delivery["modem_index"],"_stored_message_id":delivery["message_id"]}
                try:
                    send_channel(delivery["channel"], cfg, sms)
                    DB.delivery_result(delivery["id"], True)
                    RUNTIME["forwarded"] += 1
                    RUNTIME["channel_errors"].pop(delivery["channel"], None)
                except Exception as channel_error:
                    DB.delivery_result(delivery["id"], False, str(channel_error))
                    RUNTIME["channel_errors"][delivery["channel"]] = str(channel_error)[:300]
            RUNTIME["last_error"] = ""
            LAST_POLL_ERROR = ""
        except Exception as e:
            RUNTIME["last_error"] = str(e)
            error_text = str(e)
            if error_text != LAST_POLL_ERROR:
                log_event("error", "短信轮询失败", error=error_text)
                LAST_POLL_ERROR = error_text
        RUNTIME["last_poll"] = utcnow()
        try:
            DB.add_signal(RUNTIME)
            DB.retention(max(1, int(load_config().get("retention_days", 90))))
        except Exception as maintenance_error:
            log_event("error", "数据维护失败", error=str(maintenance_error))
        time.sleep(max(3, int(cfg.get("poll_interval", 10))))


def detect_ig830_usb(root=Path("/sys/bus/usb/devices")):
    if not root.exists():
        return {"present": False, "id": "", "mode": ""}
    for vendor_file in root.glob("*/idVendor"):
        try:
            vendor = vendor_file.read_text(errors="ignore").strip().lower()
            product = (vendor_file.parent / "idProduct").read_text(errors="ignore").strip().lower()
        except OSError:
            continue
        mode = SUPPORTED_IG830_USB_IDS.get((vendor, product))
        if mode:
            return {"present": True, "id": f"{vendor}:{product}", "mode": mode}
    return {"present": False, "id": "", "mode": ""}


def device_status():
    cfg = load_config()
    port = cfg.get("serial_port", "/dev/ttyUSB2")
    exists = Path(port).exists()
    usb = detect_ig830_usb()
    device_online = bool(usb["present"] and exists)
    record_device_transition(device_online, usb.get("id", ""), port)
    if not device_online:
        clear_network_status()
    with LOCK:
        runtime = dict(RUNTIME)
    return {
        "usb_present": usb["present"],
        "usb_id": usb["id"],
        "usb_mode": usb["mode"],
        "serial_port": port,
        "serial_present": exists,
        "device_online": device_online,
        "service_time": utcnow(),
        "note": "串口已就绪" if exists else "未找到串口，请检查 UTM USB 直通和驱动绑定",
        "runtime": runtime,
        "version": APP_VERSION,
        "config_schema": CONFIG_SCHEMA_VERSION,
    }


def record_device_transition(online, usb_id="", port=""):
    global DEVICE_ONLINE_STATE
    online = bool(online)
    with LOCK:
        if DEVICE_ONLINE_STATE is online:
            return False
        DEVICE_ONLINE_STATE = online
    if online:
        log_event("hardware", "IG830 设备已上线", usb_id=usb_id, serial_port=port)
    else:
        log_event("hardware", "IG830 设备已离线")
    return True


def device_monitor():
    while True:
        try:
            device_status()
        except Exception as error:
            RUNTIME["last_error"] = str(error)
        time.sleep(3)


def test_webhook(cfg):
    sms = {
        "sender": "+8613800000000",
        "message": "这是一条 IG830 短信转发测试消息",
        "received_at": utcnow(),
        "index": 0,
    }
    return send_channel("custom", cfg, sms, test=True)


def test_channel(channel, cfg):
    sms = {"sender": "+8613800000000", "message": "这是一条 IG830 短信转发测试消息", "received_at": utcnow(), "index": 0}
    return send_channel(channel, cfg, sms, test=True)


HTML = r'''<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>NexRelay-sdjoint</title>
<style>
:root{color-scheme:dark;--bg:#071018;--panel:#101d28;--line:#40596a;--text:#fff;--muted:#c5d3da;--accent:#4ce8b5;--warn:#ffda7a;--bad:#ff858e}*{box-sizing:border-box}html{font-size:17px}body{margin:0;background:var(--bg);color:var(--text);font-family:Inter,"SF Pro Text","PingFang SC","Microsoft YaHei",system-ui,sans-serif;font-size:1rem;line-height:1.7;font-weight:450;letter-spacing:.01em;-webkit-font-smoothing:antialiased;text-rendering:optimizeLegibility}.wrap{margin-left:264px;padding:32px;max-width:1520px}.top{display:flex;justify-content:space-between;align-items:center;gap:18px;margin-bottom:26px}h1{font-size:1.75rem;line-height:1.25;margin:0;color:var(--text);font-weight:800;letter-spacing:0}h2{font-size:1.15rem;line-height:1.4;margin:0 0 18px;font-weight:750;color:var(--text)}p{margin:.55em 0}.sub{color:var(--muted);margin-top:7px;font-size:.94rem;line-height:1.65}.pill{border:1px solid var(--line);border-radius:999px;padding:8px 14px;color:var(--text);font-size:.94rem;font-weight:650}.grid{display:grid;grid-template-columns:1fr 1fr;gap:20px}.card{background:var(--panel);border:1px solid var(--line);border-radius:16px;padding:24px;box-shadow:0 14px 35px #0003}.wide{grid-column:1/-1}.danger-card{border-color:#a65a63;background:linear-gradient(135deg,#25161b,#101d28)}.row{display:grid;grid-template-columns:1fr 1fr;gap:16px}.field{margin:14px 0}label{display:block;color:var(--muted);font-size:.94rem;line-height:1.5;font-weight:650;margin-bottom:7px}input,select{width:100%;min-height:46px;padding:11px 13px;border:1px solid var(--line);border-radius:9px;background:#07131c;color:var(--text);outline:none;font:inherit;font-size:1rem}input::placeholder{color:#93a7b2;opacity:1}input:focus,select:focus{border-color:var(--accent);box-shadow:0 0 0 3px #4ce8b526}.check{display:flex;align-items:flex-start;gap:11px;margin:14px 0}.check input{width:18px;min-height:18px;margin-top:5px}.check label{font-size:1rem;color:var(--text);font-weight:500}.actions{display:flex;flex-wrap:wrap;gap:11px;margin-top:20px}button{border:0;border-radius:9px;min-height:44px;padding:10px 17px;background:var(--accent);color:#03251a;font:inherit;font-size:.96rem;font-weight:750;cursor:pointer}button.secondary{background:#345365;color:#fff}button.danger{background:var(--bad);color:#35070b}button:disabled{opacity:.55;cursor:wait}.status{display:grid;grid-template-columns:repeat(auto-fit,minmax(165px,1fr));gap:12px}.metric{background:#09151e;border:1px solid var(--line);padding:16px;border-radius:11px;color:var(--muted);font-size:.94rem;font-weight:600}.metric b{display:block;margin-top:5px;color:var(--text);font-size:1.05rem;font-weight:750}.signal{height:22px;display:flex;align-items:flex-end;gap:3px;margin-top:6px}.signal i{display:block;width:7px;background:#456070;border-radius:2px}.signal i.on{background:var(--accent)}.signal i:nth-child(1){height:5px}.signal i:nth-child(2){height:9px}.signal i:nth-child(3){height:13px}.signal i:nth-child(4){height:17px}.signal i:nth-child(5){height:21px}.ok{color:var(--accent)!important}.warn{color:var(--warn)!important}.bad{color:var(--bad)!important}#toast{position:fixed;right:24px;bottom:24px;max-width:560px;background:#fff;color:#10232d;border:2px solid var(--accent);box-shadow:0 15px 50px #0008;padding:16px 19px;border-radius:11px;display:none;z-index:99;font-size:1rem;font-weight:750;line-height:1.55}.log{max-height:340px;overflow:auto}.entry{border-bottom:1px solid var(--line);padding:12px 0;font-size:.96rem}.entry small{color:var(--muted);font-size:.88rem}.login{max-width:540px;margin:6vh auto}.disclaimer{max-height:220px;overflow:auto;background:#09151e;border:1px solid var(--line);padding:16px;border-radius:10px;font-size:.96rem;line-height:1.75}.sidebar{position:fixed;left:0;top:0;bottom:0;width:248px;background:var(--panel);border-right:1px solid var(--line);padding:25px 16px;display:flex;flex-direction:column;z-index:20}.brand{font-size:1.35rem;line-height:1.3;font-weight:850;padding:4px 12px 24px;letter-spacing:0}.nav{display:grid;gap:7px}.nav button{text-align:left;background:transparent;color:var(--text);padding:12px 14px;font-size:1rem;font-weight:650}.nav button:hover,.nav button.active{background:#1d6655;color:#fff}.userbox{margin-top:auto;border-top:1px solid var(--line);padding:18px 11px 0}.userbox>b{font-size:1.03rem}.table{font-size:.95rem}.table th{color:var(--text);font-weight:750}.table td{color:var(--text)}pre{white-space:pre-wrap;word-break:break-word;font-size:.94rem;line-height:1.65;color:var(--text)!important}.hidden{display:none!important}@media(max-width:800px){html{font-size:16px}.sidebar{position:static;width:auto}.wrap{margin:0;padding:18px}.nav{grid-template-columns:1fr 1fr}.grid,.row{grid-template-columns:1fr}.wide{grid-column:auto}.status{grid-template-columns:1fr 1fr}.card{padding:19px}}
.intro-card{position:relative;overflow:hidden;border-color:#2a9478;background:linear-gradient(120deg,#12372f 0%,#102934 58%,var(--panel) 100%)}.intro-card:after{content:"N";position:absolute;right:28px;top:-50px;color:#4ce8b512;font-size:12rem;font-weight:900;line-height:1}.intro-card h2{font-size:1.45rem;margin-bottom:8px}.intro-card p{position:relative;z-index:1;max-width:850px;font-size:1.02rem}.intro-points{display:flex;position:relative;z-index:1;flex-wrap:wrap;gap:9px;margin-top:16px}.intro-points span{border:1px solid #4ce8b559;background:#071d19aa;border-radius:999px;padding:5px 11px;color:#dffdf3;font-size:.88rem;font-weight:650}.nav button{display:flex;align-items:center;gap:12px}.nav-icon{width:24px;height:24px;flex:0 0 24px;display:grid;place-items:center;border-radius:7px;color:var(--muted);transition:background .18s,color .18s,transform .18s}.nav-icon svg{width:20px;height:20px;display:block;fill:none;stroke:currentColor;stroke-width:1.9;stroke-linecap:round;stroke-linejoin:round}.nav button:hover .nav-icon{color:#fff;transform:translateX(1px)}.nav button.active .nav-icon{background:#ffffff20;color:#fff}.nav-label{line-height:1.2}html[data-theme="light"] .intro-card{background:linear-gradient(120deg,#e4faf2,#edf8fb 65%,#fff)}html[data-theme="light"] .intro-points span{background:#fff;color:#12624e;border-color:#78bda9}html[data-theme="light"] .nav button:not(.active) .nav-icon{color:#45626f}
.group-title{grid-column:1/-1;padding:12px 2px 0;border:0;background:transparent;box-shadow:none}.group-title h2{display:flex;align-items:center;gap:11px;margin:0;font-size:1.25rem}.group-title h2:before{content:"";width:5px;height:25px;border-radius:5px;background:var(--accent)}.group-title p{margin:5px 0 0 16px;color:var(--muted);font-size:.92rem}.primary-control{grid-column:1/-1;border:2px solid #2b9d7f;background:linear-gradient(120deg,#12362e,var(--panel) 65%)}.primary-control h2{font-size:1.22rem}.primary-control .check{border:1px solid #4ce8b54d;background:#071d1980;border-radius:11px;padding:13px 15px}.primary-control .check label{font-size:1.08rem;font-weight:750}.primary-control .check input{width:21px;min-height:21px}html[data-theme="light"] .primary-control{background:linear-gradient(120deg,#e5faf3,#fff 70%)}html[data-theme="light"] .primary-control .check{background:#f3fffb}
.proxy-tabs{grid-column:1/-1;display:flex;gap:6px;padding:6px;background:var(--panel);border:1px solid var(--line);border-radius:13px;box-shadow:0 8px 22px #0002;overflow-x:auto}.proxy-tabs h2{display:none}.proxy-tabs button{flex:1;min-width:150px;background:transparent;color:var(--muted);border:1px solid transparent;white-space:nowrap}.proxy-tabs button:hover{background:#203743;color:var(--text)}.proxy-tabs button.active{background:var(--accent);color:#06261d;box-shadow:0 5px 15px #0002}.proxy-tab-count{display:inline-grid;place-items:center;min-width:23px;height:23px;margin-left:6px;border-radius:999px;background:#ffffff20;font-size:.78rem}.proxy-tabs button.active .proxy-tab-count{background:#06261d1f}@media(max-width:800px){.proxy-tabs{justify-content:flex-start}.proxy-tabs button{flex:0 0 auto}}
.channel-tabs{grid-column:1/-1;display:flex;gap:4px;padding:5px;background:#e8e8ed;border:0;border-radius:12px;box-shadow:none;overflow-x:auto}.channel-tabs h2{display:none}.channel-tabs button{flex:1;min-width:104px;min-height:40px;padding:8px 13px;border:0;border-radius:9px;background:transparent;color:#515154;font-size:.9rem;font-weight:650;white-space:nowrap;box-shadow:none}.channel-tabs button:hover{background:#ffffffa8;color:#1d1d1f}.channel-tabs button.active{background:#fff;color:#1d1d1f;box-shadow:0 1px 4px #0000001f}.sidebar-save{display:flex;align-items:center;justify-content:center;gap:9px;margin:16px 8px 13px;min-height:40px;padding:8px 12px;border-radius:9px;background:#3a3a3c;color:#fff;box-shadow:none;font-size:.9rem}.sidebar-save svg{width:18px;height:18px;fill:none;stroke:currentColor;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round}.sidebar-save:hover{background:#1d1d1f}.status-note{display:inline-flex;align-items:center;gap:7px;border:0;border-radius:999px;padding:7px 11px;background:#e8f2ff;color:#0058b0;font-size:.88rem;font-weight:650;cursor:default}.status-note:before{content:"";width:7px;height:7px;border-radius:50%;background:currentColor}.status-note.warn-state{background:#fff4d6;color:#8a5a00}.status-note.bad-state{background:#ffebed;color:#b42332}
/* Apple-inspired neutral surfaces and blue interaction color. */
html[data-theme="light"]{--bg:#f5f5f7;--panel:#fff;--line:#d2d2d7;--text:#1d1d1f;--muted:#6e6e73;--accent:#0071e3;--warn:#9a6700;--bad:#d70015}html[data-theme="light"] body{background:#f5f5f7}html[data-theme="light"] .sidebar{background:#fbfbfd}html[data-theme="light"] .card{box-shadow:0 1px 2px #00000008,0 8px 30px #0000000b}html[data-theme="light"] .nav button:hover{background:#e8e8ed;color:#1d1d1f}html[data-theme="light"] .nav button.active{background:#e5f1ff;color:#0058b0}html[data-theme="light"] .nav button.active .nav-icon{background:#0071e318;color:#0071e3}html[data-theme="light"] .primary-control{border-color:#b8d9fa;background:#fff}html[data-theme="light"] .primary-control .check{border-color:#d2d2d7;background:#f5f5f7}html[data-theme="light"] button{background:#0071e3;color:#fff}html[data-theme="light"] button:hover{background:#0077ed}html[data-theme="light"] button.secondary{background:#fff;color:#0066cc;border:1px solid #b8d2ea}html[data-theme="light"] button.secondary:hover{background:#f0f7ff;color:#004f9e}html[data-theme="light"] .pill{background:#f0f0f2;border:0;color:#515154}html[data-theme="light"] .intro-card{border-color:#d2d2d7;background:linear-gradient(135deg,#fff,#f1f6ff)}
html[data-theme="dark"]{--bg:#000;--panel:#1c1c1e;--line:#38383a;--text:#f5f5f7;--muted:#a1a1a6;--accent:#0a84ff;--warn:#ffd60a;--bad:#ff453a}html[data-theme="dark"] body{background:#000}html[data-theme="dark"] .card{box-shadow:none}html[data-theme="dark"] .nav button.active{background:#0a84ff26;color:#64b5ff}html[data-theme="dark"] .nav button:hover{background:#2c2c2e;color:#fff}html[data-theme="dark"] button{background:#0a84ff;color:#fff}html[data-theme="dark"] button:hover{background:#409cff}html[data-theme="dark"] button.secondary{background:#2c2c2e;color:#64b5ff;border:1px solid #48484a}html[data-theme="dark"] .channel-tabs{background:#2c2c2e}html[data-theme="dark"] .channel-tabs button{color:#aeaeb2}html[data-theme="dark"] .channel-tabs button:hover{background:#3a3a3c;color:#fff}html[data-theme="dark"] .channel-tabs button.active{background:#636366;color:#fff}html[data-theme="dark"] .primary-control{border-color:#0a84ff;background:#1c1c1e}html[data-theme="dark"] .primary-control .check{border-color:#48484a;background:#2c2c2e}html[data-theme="dark"] .sidebar-save{background:#0a84ff;color:#fff}@media(max-width:800px){.channel-tabs{justify-content:flex-start}.channel-tabs button{flex:0 0 auto}}
[data-channel-card]{grid-column:1/-1}
.channel-dot{display:inline-block;width:8px;height:8px;margin-right:7px;border-radius:50%;background:#8e8e93;box-shadow:0 0 0 2px #8e8e9318;vertical-align:1px}.channel-dot.enabled{background:#34c759;box-shadow:0 0 0 2px #34c7591f}.channel-dot.error{background:#ff3b30;box-shadow:0 0 0 2px #ff3b301f}
/* Keep navigation and segmented controls grayscale; blue is reserved for small accents. */
html[data-theme="light"] .nav button{background:transparent;color:#1d1d1f}html[data-theme="light"] .nav button:hover{background:#e8e8ed;color:#1d1d1f}html[data-theme="light"] .nav button.active{background:#d9d9de;color:#1d1d1f}html[data-theme="light"] .nav button.active .nav-icon{background:transparent;color:#0071e3}html[data-theme="light"] .sidebar-save{background:#3a3a3c;color:#fff}html[data-theme="light"] .sidebar-save:hover{background:#1d1d1f}html[data-theme="light"] .channel-tabs button{background:transparent;color:#515154}html[data-theme="light"] .channel-tabs button:hover{background:#dcdce1;color:#1d1d1f}html[data-theme="light"] .channel-tabs button.active{background:#fff;color:#1d1d1f;box-shadow:0 1px 4px #00000024}html[data-theme="dark"] .nav button{background:transparent;color:#f5f5f7}html[data-theme="dark"] .nav button:hover{background:#2c2c2e;color:#fff}html[data-theme="dark"] .nav button.active{background:#3a3a3c;color:#fff}html[data-theme="dark"] .nav button.active .nav-icon{background:transparent;color:#0a84ff}html[data-theme="dark"] .sidebar-save{background:#48484a;color:#fff}html[data-theme="dark"] .sidebar-save:hover{background:#636366}
.sidebar-save-wrap{display:grid;justify-items:center;gap:3px;margin:13px auto 10px}.sidebar-save-wrap .sidebar-save{width:38px;height:38px;min-height:38px;margin:0;padding:0;border-radius:10px}.sidebar-save-wrap .sidebar-save svg{width:18px;height:18px}.save-caption{font-size:.7rem;line-height:1.2;color:var(--muted);font-weight:600}.confirm-check{border:1px solid var(--line);border-radius:11px;padding:11px 13px;background:#f5f5f7}.confirm-check label{margin:0;color:var(--text);font-size:.94rem;font-weight:650}.confirm-check input{width:18px;min-height:18px}.confirm-hint{font-size:.86rem;color:var(--muted);margin:5px 0 0}.danger-zone{border-top:1px solid var(--line);margin-top:15px;padding-top:12px}
html[data-theme="light"] button:not(.theme-toggle):not(.sidebar-save){background:#d9d9de;color:#1d1d1f;border:1px solid #c7c7cc}html[data-theme="light"] button:not(.theme-toggle):not(.sidebar-save):hover{background:#c7c7cc;color:#1d1d1f}html[data-theme="light"] button.secondary{background:#f5f5f7;color:#1d1d1f;border-color:#d2d2d7}html[data-theme="light"] button.secondary:hover{background:#e8e8ed;color:#1d1d1f}html[data-theme="light"] button.danger{background:#fff;color:#c20a20;border-color:#e3a7ae}html[data-theme="light"] button.danger:hover{background:#fff1f2;color:#a00013}html[data-theme="light"] .sidebar-save{background:#d9d9de;color:#1d1d1f;border:1px solid #c7c7cc}html[data-theme="light"] .sidebar-save:hover{background:#c7c7cc}html[data-theme="light"] .channel-tabs button{border:0;background:transparent;color:#515154}html[data-theme="light"] .channel-tabs button:hover{background:#dcdce1}html[data-theme="light"] .channel-tabs button.active{background:#fff;color:#1d1d1f}
html[data-theme="dark"] button:not(.theme-toggle):not(.sidebar-save){background:#3a3a3c;color:#f5f5f7;border:1px solid #48484a}html[data-theme="dark"] button:not(.theme-toggle):not(.sidebar-save):hover{background:#48484a}html[data-theme="dark"] button.secondary{background:#2c2c2e;color:#f5f5f7;border-color:#48484a}html[data-theme="dark"] button.danger{background:#2c2c2e;color:#ff6961;border-color:#74343a}html[data-theme="dark"] .sidebar-save{background:#3a3a3c;color:#f5f5f7;border:1px solid #48484a}html[data-theme="dark"] .confirm-check{background:#2c2c2e}html[data-theme="dark"] .channel-tabs button{border:0;background:transparent;color:#aeaeb2}html[data-theme="dark"] .channel-tabs button.active{background:#636366;color:#fff}
html[data-theme="light"] button.danger:not(.theme-toggle):not(.sidebar-save){background:#fff;color:#c20a20;border-color:#e3a7ae}html[data-theme="light"] button.danger:not(.theme-toggle):not(.sidebar-save):hover{background:#fff1f2;color:#a00013}html[data-theme="dark"] button.danger:not(.theme-toggle):not(.sidebar-save){background:#2c2c2e;color:#ff6961;border-color:#74343a}html[data-theme="dark"] button.danger:not(.theme-toggle):not(.sidebar-save):hover{background:#3a2427;color:#ff8a84}
html[data-theme="light"]{color-scheme:light;--bg:#edf4f7;--panel:#fff;--line:#c9d9e1;--text:#12232e;--muted:#506975;--accent:#078d67;--warn:#8a5700;--bad:#b72d3b}html[data-theme="light"] input,html[data-theme="light"] select{background:#f8fbfc}html[data-theme="light"] .metric,html[data-theme="light"] .disclaimer{background:#f5fafc}html[data-theme="light"] button.secondary{background:#dce8ed;color:#16303c}html[data-theme="light"] .danger-card{background:#fff7f7}html[data-theme="light"] .badge{background:#e3edf1}.theme-toggle{font-size:20px;width:44px;height:40px;padding:0;background:transparent!important;color:var(--text)!important;border:1px solid var(--line)!important}.table{width:100%;border-collapse:collapse}.table th,.table td{text-align:left;padding:9px;border-bottom:1px solid var(--line);vertical-align:top}.badge{display:inline-block;padding:2px 7px;border-radius:10px;background:#253947;margin:2px;font-size:12px}
/* Final platform tokens and dashboard layout. */
html[data-theme="light"]{--bg:#f5f5f7;--panel:#fff;--line:#d2d2d7;--text:#1d1d1f;--muted:#6e6e73;--accent:#34c759;--warn:#9a6700;--bad:#d70015}html[data-theme="light"] body{background:#f5f5f7}html[data-theme="light"] input,html[data-theme="light"] select{background:#fbfbfd}html[data-theme="light"] .metric,html[data-theme="light"] .disclaimer{background:#f5f5f7}html[data-theme="dark"]{--bg:#000;--panel:#1c1c1e;--line:#38383a;--text:#f5f5f7;--muted:#a1a1a6;--accent:#34c759;--warn:#ffd60a;--bad:#ff453a}.forward-card,.stats-card{grid-column:1/-1}.forward-row{grid-template-columns:repeat(3,minmax(170px,1fr))}.stats-row{grid-template-columns:repeat(4,minmax(150px,1fr))}.site-footer{margin-top:26px;padding:20px 12px 8px;border-top:1px solid var(--line);text-align:center}.site-footer h2{margin-bottom:10px;font-size:1rem}.author-line{display:flex;flex-wrap:wrap;justify-content:center;gap:8px 18px;color:var(--muted);font-size:.88rem}.author-line a{color:inherit;text-decoration:none}.author-line a:hover{text-decoration:underline;color:var(--text)}.userbox{margin-top:auto;border-top:0;padding:0 11px}.user-divider{height:1px;background:var(--line);margin:9px 0 16px}.sidebar-save-wrap{margin:0 auto 8px}.user-identity{padding-bottom:2px}@media(max-width:800px){.forward-row,.stats-row{display:flex;overflow-x:auto}.forward-row .metric,.stats-row .metric{min-width:155px}.author-line{display:grid;gap:4px}.site-footer{margin-top:20px}}
html[data-theme="light"] .nav button{background:transparent;color:#1d1d1f}html[data-theme="light"] .nav button:hover{background:#e8e8ed}html[data-theme="light"] .nav button.active{background:#d9d9de;color:#1d1d1f}html[data-theme="light"] button:not(.theme-toggle):not(.sidebar-save){background:#d9d9de;color:#1d1d1f;border:1px solid #c7c7cc}html[data-theme="light"] button.secondary{background:#f5f5f7;color:#1d1d1f;border-color:#d2d2d7}html[data-theme="light"] button.danger:not(.theme-toggle):not(.sidebar-save){background:#fff;color:#c20a20;border-color:#e3a7ae}html[data-theme="light"] .channel-tabs button{border:0;background:transparent;color:#515154}html[data-theme="light"] .channel-tabs button:hover{background:#dcdce1}html[data-theme="light"] .channel-tabs button.active{background:#fff;color:#1d1d1f}html[data-theme="dark"] .nav button.active{background:#3a3a3c;color:#fff}html[data-theme="dark"] button:not(.theme-toggle):not(.sidebar-save){background:#3a3a3c;color:#f5f5f7;border:1px solid #48484a}html[data-theme="dark"] button.secondary{background:#2c2c2e;color:#f5f5f7}html[data-theme="dark"] button.danger:not(.theme-toggle):not(.sidebar-save){background:#2c2c2e;color:#ff6961;border-color:#74343a}
.channel-guide{margin-top:18px;border-top:1px solid var(--line);padding-top:14px}.channel-guide summary{display:flex;align-items:center;gap:9px;width:max-content;max-width:100%;color:var(--text);font-size:.92rem;font-weight:700;cursor:pointer;list-style:none;user-select:none}.channel-guide summary::-webkit-details-marker{display:none}.channel-guide summary:before{content:"?";display:grid;place-items:center;width:20px;height:20px;flex:0 0 20px;border:1px solid var(--line);border-radius:50%;color:var(--muted);font-size:.75rem}.channel-guide[open] summary:before{content:"−"}.guide-body{margin-top:12px;padding:14px 16px;border-radius:11px;background:#f5f5f7;color:var(--muted);font-size:.88rem;line-height:1.65}.guide-body ol,.guide-body ul{margin:0;padding-left:1.25rem}.guide-body li+li{margin-top:5px}.guide-body code{padding:2px 5px;border-radius:5px;background:#e8e8ed;color:var(--text);font-size:.84rem;word-break:break-all}.guide-links{display:flex;flex-wrap:wrap;gap:7px 14px;margin-top:10px}.guide-links a{color:var(--text);font-weight:650;text-decoration:none;border-bottom:1px solid var(--line)}.guide-links a:hover{border-color:var(--text)}.guide-warning{margin:10px 0 0;color:var(--warn);font-weight:600}html[data-theme="dark"] .guide-body{background:#2c2c2e}html[data-theme="dark"] .guide-body code{background:#3a3a3c}
.log-card{padding:0;overflow:hidden}.log-card-head{display:flex;align-items:center;justify-content:space-between;gap:16px;padding:22px 24px;border-bottom:1px solid var(--line)}.log-card-head h2{margin:0}.log-card-head .sub{margin:2px 0 0}.log-table-wrap{overflow-x:auto}.log-table{table-layout:fixed}.log-table th{background:#f5f5f7;color:var(--muted);font-size:.82rem;text-transform:none;letter-spacing:.02em}.log-table th,.log-table td{padding:13px 20px}.log-table th:first-child,.log-table td:first-child{width:245px;white-space:nowrap}.log-event{display:flex;align-items:flex-start;gap:10px;min-width:0}.log-kind{display:inline-flex;align-items:center;min-width:64px;justify-content:center;padding:2px 7px;border-radius:999px;background:#e8e8ed;color:#515154;font-size:.72rem;font-weight:750;line-height:1.55}.log-message{min-width:0;overflow-wrap:anywhere}.log-pagination{display:flex;align-items:center;justify-content:center;gap:12px;padding:15px 20px;border-top:1px solid var(--line)}.log-pagination button{min-height:34px;padding:6px 12px;font-size:.84rem}.log-page-info{min-width:112px;text-align:center;color:var(--muted);font-size:.85rem;font-weight:650}html[data-theme="dark"] .log-table th{background:#2c2c2e}html[data-theme="dark"] .log-kind{background:#3a3a3c;color:#d1d1d6}@media(max-width:800px){.log-card-head{align-items:flex-start;padding:18px}.log-table th,.log-table td{padding:11px 14px}.log-table th:first-child,.log-table td:first-child{width:205px}.log-event{display:block}.log-kind{margin-bottom:5px}}
.secret-input{position:relative}.secret-input input{padding-right:54px}.secret-toggle{position:absolute;right:6px;top:50%;transform:translateY(-50%);display:grid;place-items:center;width:36px;height:36px;min-height:36px;padding:0!important;border:0!important;border-radius:8px!important;background:transparent!important;color:var(--muted)!important}.secret-toggle:hover{background:#e8e8ed!important;color:var(--text)!important}.secret-toggle svg{width:20px;height:20px;fill:none;stroke:currentColor;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round}.secret-toggle .eye-slash{display:none}.secret-toggle.revealing .eye-slash{display:block}html[data-theme="dark"] .secret-toggle:hover{background:#3a3a3c!important}
.sms-compose textarea{width:100%;min-height:128px;padding:12px 13px;border:1px solid var(--line);border-radius:10px;background:#fbfbfd;color:var(--text);outline:none;resize:vertical;font:inherit;line-height:1.65}.sms-compose textarea::placeholder{color:#8e8e93}.sms-compose textarea:focus{border-color:#8e8e93;box-shadow:0 0 0 3px #8e8e9324}.compose-meta{display:flex;justify-content:flex-end;gap:14px;margin-top:6px;color:var(--muted);font-size:.84rem}.send-status{align-self:center;margin:0}.sms-compose .actions button{min-width:108px}html[data-theme="dark"] .sms-compose textarea{background:#2c2c2e}
.top>.actions{align-items:center;margin-top:0}.user-identity-row{display:flex;align-items:center;justify-content:space-between;gap:10px}.user-save{min-height:38px;margin:0;padding:7px 10px;gap:6px;border-radius:10px;font-size:.82rem;white-space:nowrap}.user-save svg{width:17px;height:17px}.user-save:focus-visible{outline:3px solid #8e8e9340;outline-offset:2px}.test-action{display:flex;align-items:center;flex-wrap:wrap;gap:9px 12px;margin-top:12px}.test-action .test-hint{color:var(--muted);font-size:.82rem;line-height:1.45}.test-action .actions{margin-top:0}.retry-link{display:inline!important;min-height:0!important;margin-left:4px!important;padding:0!important;border:0!important;border-radius:0!important;background:transparent!important;color:inherit!important;box-shadow:none!important;font:inherit!important;font-weight:650!important;line-height:inherit!important;vertical-align:baseline!important}.retry-link:hover{background:transparent!important;color:inherit!important;text-decoration:underline}.retry-link:focus-visible{text-decoration:underline;outline:none}
.mobile-bar,.sidebar-close,.mobile-backdrop{display:none}.sidebar-head{display:block}.message-tools{align-items:center}.message-tools input{max-width:320px}.icon-button{min-width:44px;padding:8px 12px;font-size:1.2rem}.message-table-wrap{overflow:auto}.capability-summary{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:10px;margin:16px 0}.capability-item{border:1px solid var(--line);background:var(--bg);border-radius:12px;padding:13px}.capability-item span{display:block;color:var(--muted);font-size:.82rem}.capability-item b{display:block;margin-top:3px;font-size:.96rem;word-break:break-word}.diagnostic-details{margin:10px 0 20px}.diagnostic-details summary{cursor:pointer;color:var(--muted);font-weight:650}.intro-card:after{content:"";width:180px;height:180px;top:-65px;border-radius:50%;background:radial-gradient(circle,#34c75922,transparent 68%)}.channel-guide summary:before{content:"";background:radial-gradient(circle at center,var(--muted) 0 2px,transparent 2.5px)}.channel-guide[open] summary:before{content:"";background:linear-gradient(var(--muted),var(--muted)) center/9px 1px no-repeat}.modal{position:fixed;inset:0;z-index:120;display:grid;place-items:center;padding:20px;background:#0009}.modal-card{width:min(520px,100%);max-height:90vh;overflow:auto;border:1px solid var(--line);border-radius:18px;background:var(--panel);padding:24px;box-shadow:0 24px 80px #0006}.audit-card{width:min(900px,100%)}.modal-head{display:flex;justify-content:space-between;align-items:center;gap:20px}.modal-head h2{margin:0}.modal-close{min-width:38px!important;width:38px;height:38px;min-height:38px!important;padding:0!important;border-radius:50%!important;font-size:1.35rem!important}.modal-card .bad{font-size:.9rem}.forward-row{grid-template-columns:repeat(4,minmax(155px,1fr))}
@media(max-width:800px){body.sidebar-open{overflow:hidden}.sidebar{position:fixed;display:flex!important;width:min(86vw,320px);transform:translateX(-105%);transition:transform .22s ease;box-shadow:20px 0 60px #0005}.sidebar.open{transform:translateX(0)}.sidebar-head{display:flex;align-items:flex-start;justify-content:space-between}.sidebar-close{display:grid;place-items:center;width:38px;height:38px;min-height:38px;padding:0;background:transparent!important;color:var(--text)!important;border:1px solid var(--line)!important;font-size:1.3rem}.mobile-backdrop{position:fixed;display:block;inset:0;z-index:19;background:#0007}.mobile-bar{display:flex;position:sticky;top:0;z-index:15;align-items:center;gap:12px;margin:-18px -18px 18px;padding:10px 18px;border-bottom:1px solid var(--line);background:color-mix(in srgb,var(--bg) 92%,transparent);backdrop-filter:blur(18px)}.mobile-bar button{width:40px;height:40px;min-height:40px;padding:0;background:transparent!important;color:var(--text)!important;border:1px solid var(--line)!important}.nav{grid-template-columns:1fr}.wrap{padding-top:18px}.message-tools input{max-width:none;flex:1 1 100%}.message-table-wrap{margin:0 -8px}.modal{padding:12px}.modal-card{padding:19px}.forward-row{display:flex;overflow-x:auto}.forward-row .metric{min-width:165px}}
.column-sort{display:inline-flex;align-items:center;gap:4px;min-height:0!important;padding:0!important;border:0!important;border-radius:0!important;outline-offset:3px;background:transparent!important;color:inherit!important;box-shadow:none!important;font:inherit;font-weight:inherit;line-height:inherit;white-space:nowrap}.column-sort:hover,.column-sort:active{border:0!important;background:transparent!important;box-shadow:none!important}.column-sort:hover .sort-label{text-decoration:underline;text-underline-offset:3px}.sort-arrow{display:inline-block;min-width:.8em;color:var(--muted);font-size:.78em;line-height:1}.column-sort.active .sort-arrow{color:var(--text)}html{font-size:16px}@media(max-width:800px){html{font-size:15px}}
html[data-theme="light"] .sidebar-save.user-save{color:#355f73!important}html[data-theme="light"] .sidebar-save.user-save:hover{color:#274b5d!important}html[data-theme="dark"] .sidebar-save.user-save{color:#9fc0cf!important}html[data-theme="dark"] .sidebar-save.user-save:hover{color:#c0d7e1!important}
</style></head><body>
<section id="login" class="login card"><h1>NexRelay-sdjoint</h1><p class="sub">IG830 多通道短信中继平台 · 登录前请阅读并确认免责声明。</p><div class="disclaimer"><b>免责声明</b><p>本软件仅用于管理用户本人合法持有、获授权使用的设备、SIM 卡和短信。用户应遵守所在地法律、运营商协议及第三方平台规则，不得用于窃取隐私、未授权监控、垃圾信息或其他违法用途。软件按现状提供，设备参数修改及数据转发风险由实际操作者承担。</p></div><div class="check"><input id="disclaimer" type="checkbox"><label for="disclaimer">我已阅读、理解并同意上述免责声明</label></div><div class="field"><label>用户名</label><input id="username" autocomplete="username" value="admin"></div><div class="field"><label>密码</label><input id="token" type="password" autocomplete="current-password"></div><button onclick="login()">登录控制台</button></section>
<div id="mobileBackdrop" class="mobile-backdrop hidden" onclick="toggleSidebar(false)"></div>
<aside id="sidebar" class="sidebar hidden"><div class="sidebar-head"><div class="brand">NexRelay<span class="sub" style="display:block;font-size:12px">sdjoint</span></div><button type="button" class="sidebar-close" onclick="toggleSidebar(false)" aria-label="关闭导航菜单">×</button></div><div class="nav">
<button data-page="dashboard" class="active" aria-label="仪表盘"><span class="nav-icon"><svg viewBox="0 0 24 24" aria-hidden="true"><rect x="3" y="3" width="7" height="7" rx="2"/><rect x="14" y="3" width="7" height="7" rx="2"/><rect x="3" y="14" width="7" height="7" rx="2"/><rect x="14" y="14" width="7" height="7" rx="2"/></svg></span><span class="nav-label" aria-hidden="true">仪 表 盘</span></button>
<button data-page="device"><span class="nav-icon"><svg viewBox="0 0 24 24" aria-hidden="true"><rect x="6" y="2.5" width="12" height="19" rx="3"/><path d="M10 18h4M9 6h6"/></svg></span><span class="nav-label">设备管理</span></button>
<button data-page="proxy"><span class="nav-icon"><svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="5" cy="12" r="2.5"/><circle cx="19" cy="5" r="2.5"/><circle cx="19" cy="19" r="2.5"/><path d="m7.3 10.8 9.3-4.6M7.3 13.2l9.3 4.6"/></svg></span><span class="nav-label">转发管理</span></button>
<button data-page="sms"><span class="nav-icon"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 5h16a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2H8l-4 3v-3a2 2 0 0 1-2-2V7a2 2 0 0 1 2-2Z"/><path d="M7 10h10M7 14h6"/></svg></span><span class="nav-label">短信中心</span></button>
<button data-page="logs"><span class="nav-icon"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M6 3h9l4 4v14H6a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2Z"/><path d="M14 3v5h5M8 12h8M8 16h8"/></svg></span><span class="nav-label">运行日志</span></button>
<button data-page="settings"><span class="nav-icon"><svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .34 1.88l.06.06-2.83 2.83-.06-.06A1.7 1.7 0 0 0 15 19.4a1.7 1.7 0 0 0-1 .6 1.7 1.7 0 0 0-.4 1v.1h-4v-.1a1.7 1.7 0 0 0-1.1-1.6 1.7 1.7 0 0 0-1.88.34l-.06.06-2.83-2.83.06-.06A1.7 1.7 0 0 0 4.6 15a1.7 1.7 0 0 0-.6-1 1.7 1.7 0 0 0-1-.4h-.1v-4H3A1.7 1.7 0 0 0 4.6 8.5a1.7 1.7 0 0 0-.34-1.88l-.06-.06 2.83-2.83.06.06A1.7 1.7 0 0 0 9 4.6a1.7 1.7 0 0 0 1-.6 1.7 1.7 0 0 0 .4-1v-.1h4V3A1.7 1.7 0 0 0 15.5 4.6a1.7 1.7 0 0 0 1.88-.34l.06-.06 2.83 2.83-.06.06A1.7 1.7 0 0 0 19.4 9c.2.4.5.8.9 1 .3.2.7.4 1.1.4h.1v4h-.1a1.7 1.7 0 0 0-1.6 1.1Z"/></svg></span><span class="nav-label">系统设置</span></button>
</div><div class="userbox"><div class="user-divider"></div><div class="user-identity-row"><div class="user-identity"><b id="sidebarUser">admin</b><div class="sub">Administrator</div></div><button class="sidebar-save user-save" onclick="save()" title="保存全部配置" aria-label="保存全部配置"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M5 3h12l3 3v15H4V4a1 1 0 0 1 1-1Z"/><path d="M8 3v6h8V3M8 21v-7h8v7"/></svg><span>保存</span></button></div><div class="actions"><button class="secondary" onclick="openCredentials()">修改凭据</button><button class="secondary" onclick="logout()">退出</button></div></div></aside>
<main id="app" class="wrap hidden"><div class="mobile-bar"><button type="button" onclick="toggleSidebar(true)" aria-label="打开导航菜单">☰</button><b>NexRelay</b></div><div class="top"><div><h1 id="pageTitle">仪表盘</h1></div><div class="actions"><button id="themeBtn" class="theme-toggle" onclick="toggleTheme()" title="切换到夜间模式" aria-label="切换到夜间模式">☾</button><span id="enabledPill" class="status-note">读取中</span></div></div>
<div class="grid"><section class="card wide intro-card"><h2>欢迎使用 NexRelay-sdjoint</h2><p>NexRelay-sdjoint 是为 IG830 打造的本地自托管短信中继平台，集中管理设备、SIM 与短信，并将收到的消息安全转发至钉钉、飞书、企业微信、Telegram、个人微信及其他自定义服务。</p><div class="intro-points"><span>本地自主部署</span><span>多通道转发</span><span>设备实时监控</span><span>敏感配置留在服务器</span></div></section><section class="card wide"><h2>设备与运营商状态</h2><div class="status"><div class="metric">USB 设备<b id="usb">—</b></div><div class="metric">USB 模式<b id="usbMode">读取中</b></div><div class="metric">短信串口<b id="serial">—</b></div><div class="metric">SIM 卡<b id="sim">—</b></div><div class="metric">本机号码<b id="phoneNumber">读取中</b></div><div class="metric">信号强度<div id="signalBars" class="signal"><i></i><i></i><i></i><i></i><i></i></div><b id="signalText">—</b></div><div class="metric">运营商<b id="operator">—</b></div><div class="metric">网络注册<b id="registration">—</b></div></div><p id="phoneNote" class="sub">号码由 SIM/运营商写入信息提供；部分 SIM 不保存本机号码。</p><p id="note" class="sub"></p><p class="sub">设备状态每 3 秒自动刷新。</p></section>
<section class="card wide danger-card"><h2>IG830 USB 兼容模式转换（高级操作）</h2><p class="bad"><b>高风险：</b>这里修改的是 IG830 模块自身的永久 USB 参数，UTM 快照和 Ubuntu 备份都无法回滚。不同硬件不能照抄参数。</p><p class="sub">安全流程：读取本机参数 → 自动保存出厂备份 → 用户核对硬件身份 → 写入兼容 VID/PID → 用户单独确认重启。平台只替换 VID/PID，其余接口开关完全沿用本机原值。</p><div class="status"><div class="metric">硬件身份<b id="usbIdentity">尚未读取</b></div><div class="metric">当前 USB ID<b id="usbCurrent">—</b></div><div class="metric">目标状态<b id="usbTarget">2c7c:0125</b></div><div class="metric">出厂备份<b id="usbBackup">—</b></div></div><div class="field"><label>当前原始参数</label><input id="usbRaw" readonly placeholder="点击读取并备份"></div><div class="actions"><button class="secondary" onclick="readUsbConfig()">1. 读取并备份原始参数</button></div><div class="check confirm-check"><input id="usbApplyConfirm" type="checkbox"><label for="usbApplyConfirm">我已核对硬件身份和出厂备份，同意写入兼容 USB ID</label></div><p class="confirm-hint">刷新页面后默认不勾选；执行后会自动复位。</p><div class="actions"><button class="danger" onclick="applyUsbConfig()">2. 写入 Linux 兼容 USB ID</button></div><div class="check confirm-check"><input id="usbRestartConfirm" type="checkbox"><label for="usbRestartConfirm">我了解设备会暂时离线，同意重启 IG830 使参数生效</label></div><div class="actions"><button class="danger" onclick="restartIg830()">3. 重启 IG830</button></div><div class="danger-zone"><div class="check confirm-check"><input id="usbRestoreConfirm" type="checkbox"><label for="usbRestoreConfirm">我确认使用本机备份恢复 IG830 出厂 USB 参数</label></div><div class="actions"><button class="danger" onclick="restoreUsbConfig()">从本机备份恢复出厂参数</button></div></div></section>
<section class="group-title"><h2>一、全局控制</h2><p>总开关决定平台是否执行短信转发，各通道开关不会覆盖这里的状态。</p></section><section class="card primary-control"><h2>短信转发总开关</h2><div class="check"><input id="enabled" type="checkbox"><label for="enabled">启用短信转发</label></div><div class="row"><div class="field"><label>短信检查间隔（秒）</label><input id="poll_interval" type="number" min="3" max="3600"></div><div class="field"><label>短信串口</label><input id="serial_port" placeholder="通常为 /dev/ttyUSB2"></div></div><p class="sub">总开关开启后，平台只向已经单独启用、配置完整且测试成功的通道转发。</p></section><section class="group-title"><h2>二、转发通道</h2><p>选择一个通道进行配置；已启用的其他通道会继续正常工作。</p></section><section class="channel-tabs"><h2>通道选择</h2><button type="button" data-channel-tab="custom" class="active" onclick="showChannel('custom')"><i class="channel-dot" data-channel-dot="custom"></i>Webhook</button><button type="button" data-channel-tab="dingtalk" onclick="showChannel('dingtalk')"><i class="channel-dot" data-channel-dot="dingtalk"></i>钉钉</button><button type="button" data-channel-tab="feishu" onclick="showChannel('feishu')"><i class="channel-dot" data-channel-dot="feishu"></i>飞书</button><button type="button" data-channel-tab="wecom" onclick="showChannel('wecom')"><i class="channel-dot" data-channel-dot="wecom"></i>企业微信</button><button type="button" data-channel-tab="telegram" onclick="showChannel('telegram')"><i class="channel-dot" data-channel-dot="telegram"></i>Telegram</button><button type="button" data-channel-tab="wechat" onclick="showChannel('wechat')"><i class="channel-dot" data-channel-dot="wechat"></i>微信通知</button><button type="button" data-channel-tab="email" onclick="showChannel('email')"><i class="channel-dot" data-channel-dot="email"></i>邮件</button><button type="button" data-channel-tab="more" onclick="showChannel('more')"><i class="channel-dot" data-channel-dot="more"></i>更多</button></section>
<section class="card"><h2>自定义 Webhook</h2><div class="field"><label>Webhook URL</label><input id="webhook_url" placeholder="https://your-app.example/sms"></div><div class="row"><div class="field"><label>请求方法</label><select id="http_method"><option>POST</option><option>PUT</option></select></div><div class="field"><label>鉴权请求头名称</label><input id="auth_header" placeholder="Authorization"></div></div><div class="field"><label>鉴权请求头值（留空保持原值）</label><div class="secret-input"><input id="auth_value" type="password" placeholder="Bearer ..."><button type="button" class="secret-toggle" onclick="toggleSecret('auth_value',this)" aria-label="显示敏感内容" aria-pressed="false" title="显示"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M2.5 12s3.5-6 9.5-6 9.5 6 9.5 6-3.5 6-9.5 6S2.5 12 2.5 12Z"/><circle cx="12" cy="12" r="2.8"/><path class="eye-slash" d="m4 4 16 16"/></svg></button></div></div><button class="secondary" onclick="testChannel('custom','自定义 Webhook')">测试 Webhook</button><details class="channel-guide"><summary>如何获取 Webhook 和鉴权信息</summary><div class="guide-body"><ol><li>在接收短信的 App 或服务端创建一个可接收 HTTP JSON 的接口，并启用 HTTPS。</li><li>把接口完整地址填入 Webhook URL；根据接口要求选择 <code>POST</code> 或 <code>PUT</code>。</li><li>若接口要求 Token，将请求头名称填为 <code>Authorization</code> 等实际字段，请求头值填入完整内容，例如 <code>Bearer xxxxx</code>。</li><li>先保存配置，再点击测试；在接收端核对测试请求与返回状态。</li></ol><p class="guide-warning">Webhook 与鉴权信息等同密码，不要发布到公开仓库或截图中。</p></div></details></section>
<section class="card"><h2>钉钉机器人</h2><div class="check"><input id="dingtalk_enabled" type="checkbox"><label for="dingtalk_enabled">启用钉钉</label></div><div class="field"><label>机器人 Webhook</label><input id="dingtalk_webhook" placeholder="https://oapi.dingtalk.com/robot/send?... "></div><div class="field"><label>加签 Secret（可选，留空保持原值）</label><div class="secret-input"><input id="dingtalk_secret" type="password" placeholder="SEC..."><button type="button" class="secret-toggle" onclick="toggleSecret('dingtalk_secret',this)" aria-label="显示敏感内容" aria-pressed="false" title="显示"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M2.5 12s3.5-6 9.5-6 9.5 6 9.5 6-3.5 6-9.5 6S2.5 12 2.5 12Z"/><circle cx="12" cy="12" r="2.8"/><path class="eye-slash" d="m4 4 16 16"/></svg></button></div></div><button class="secondary" onclick="testChannel('dingtalk','钉钉')">测试钉钉</button><details class="channel-guide"><summary>如何获取钉钉 Webhook 和 Secret</summary><div class="guide-body"><ol><li>打开目标钉钉群，进入群设置中的机器人管理，添加“自定义机器人”。</li><li>设置机器人名称并选择安全方式；完成后复制机器人 Webhook。</li><li>若选择“加签”，同时复制以 <code>SEC</code> 开头的 Secret；若只使用关键词或 IP 白名单，Secret 可留空。</li><li>在此处填入、启用、保存，再点击测试钉钉。</li></ol><div class="guide-links"><a href="https://open.dingtalk.com/document/orgapp/custom-robot-access" target="_blank" rel="noopener noreferrer">钉钉官方获取说明 ↗</a></div><p class="guide-warning">建议启用安全设置；Webhook 和 Secret 泄露后应立即在钉钉中重置。</p></div></details></section>
<section class="card"><h2>飞书机器人</h2><div class="check"><input id="feishu_enabled" type="checkbox"><label for="feishu_enabled">启用飞书</label></div><div class="field"><label>机器人 Webhook</label><input id="feishu_webhook" placeholder="https://open.feishu.cn/open-apis/bot/v2/hook/..."></div><button class="secondary" onclick="testChannel('feishu','飞书')">测试飞书</button><details class="channel-guide"><summary>如何获取飞书机器人 Webhook</summary><div class="guide-body"><ol><li>进入目标飞书群，在群设置中打开“群机器人”，添加“自定义机器人”。</li><li>填写名称和描述，按需设置关键词、IP 白名单或签名安全策略。</li><li>复制形如 <code>https://open.feishu.cn/open-apis/bot/v2/hook/...</code> 的 V2 Webhook。</li><li>填入并保存后点击测试飞书。</li></ol><div class="guide-links"><a href="https://open.feishu.cn/document/ukTMukTMukTM/ucTM5YjL3ETO24yNxkjN" target="_blank" rel="noopener noreferrer">飞书官方自定义机器人指南 ↗</a></div><p class="guide-warning">自定义机器人 Webhook 只能向所在群推送，请勿公开该地址。</p></div></details></section>
<section class="card"><h2>企业微信机器人</h2><div class="check"><input id="wecom_enabled" type="checkbox"><label for="wecom_enabled">启用企业微信</label></div><div class="field"><label>群机器人 Webhook</label><input id="wecom_webhook" placeholder="https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=..."></div><button class="secondary" onclick="testChannel('wecom','企业微信')">测试企业微信</button><details class="channel-guide"><summary>如何获取企业微信群机器人 Webhook</summary><div class="guide-body"><ol><li>在企业微信客户端进入目标内部群聊，打开群设置并选择“群机器人”。</li><li>添加机器人，填写名称后复制 Webhook 地址。</li><li>地址通常形如 <code>https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=...</code>。</li><li>填入、启用并保存，再点击测试企业微信。</li></ol><div class="guide-links"><a href="https://developer.work.weixin.qq.com/document/path/91770" target="_blank" rel="noopener noreferrer">企业微信官方群机器人说明 ↗</a></div><p class="guide-warning">URL 中的 key 是调用凭据；机器人只对创建它的群聊生效。</p></div></details></section>
<section class="card"><h2>Telegram Bot</h2><div class="check"><input id="telegram_enabled" type="checkbox"><label for="telegram_enabled">启用 Telegram</label></div><div class="field"><label>Bot Token（留空保持原值）</label><div class="secret-input"><input id="telegram_bot_token" type="password" placeholder="123456:ABC..."><button type="button" class="secret-toggle" onclick="toggleSecret('telegram_bot_token',this)" aria-label="显示敏感内容" aria-pressed="false" title="显示"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M2.5 12s3.5-6 9.5-6 9.5 6 9.5 6-3.5 6-9.5 6S2.5 12 2.5 12Z"/><circle cx="12" cy="12" r="2.8"/><path class="eye-slash" d="m4 4 16 16"/></svg></button></div></div><div class="field"><label>Chat ID</label><input id="telegram_chat_id" placeholder="-1001234567890"></div><div class="check"><input id="telegram_reply_enabled" type="checkbox"><label for="telegram_reply_enabled">允许在 Telegram 中回复并通过 SIM 卡发送短信</label></div><div class="field"><label>授权回复用户 ID（群聊必填，私聊可留空）</label><input id="telegram_reply_user_id" inputmode="numeric" placeholder="例如 123456789"></div><p class="sub">反向回复状态：<b id="telegramReplyStatus">读取中</b></p><div class="actions"><button class="secondary" onclick="testChannel('telegram','Telegram')">测试 Telegram</button><span class="sub">测试只验证发送；反向回复需保存并开启上方开关</span></div><details class="channel-guide"><summary>如何获取 Bot Token、Chat ID 并使用反向回复</summary><div class="guide-body"><ol><li>在 Telegram 打开官方 <code>@BotFather</code>，发送 <code>/newbot</code>，按提示创建机器人并复制 Bot Token。</li><li>私聊接收：打开新机器人并发送一条消息。群组接收：把机器人加入目标群，并在群中发送一条消息。</li><li>浏览器访问 <code>https://api.telegram.org/bot&lt;TOKEN&gt;/getUpdates</code>，在返回内容中找到 <code>message.chat.id</code>，将其作为 Chat ID；群组 ID 通常为负数。</li><li>开启反向回复并保存。收到转发短信后，必须对那条机器人消息使用 Telegram 的“回复”操作；普通独立消息不会触发短信。</li><li>私聊只接受当前 Chat ID；群聊还必须填写获准操作人的 <code>from.id</code>，防止其他群成员代发短信。</li></ol><div class="guide-links"><a href="https://core.telegram.org/bots/features#botfather" target="_blank" rel="noopener noreferrer">Telegram 官方 BotFather 指南 ↗</a><a href="https://core.telegram.org/bots/api#getupdates" target="_blank" rel="noopener noreferrer">getUpdates 官方说明 ↗</a></div><p class="guide-warning">Bot Token 可完全控制机器人。反向回复会产生运营商短信费用；系统只接受引用已映射短信的文本回复，并继续执行 70 字限制、30 秒冷却和审计记录。</p></div></details></section>
<section class="card"><h2>个人微信（PushPlus）</h2><div class="check"><input id="wechat_enabled" type="checkbox"><label for="wechat_enabled">启用微信通知</label></div><div class="field"><label>PushPlus Token（留空保持原值）</label><div class="secret-input"><input id="wechat_pushplus_token" type="password" placeholder="在 pushplus.plus 获取"><button type="button" class="secret-toggle" onclick="toggleSecret('wechat_pushplus_token',this)" aria-label="显示敏感内容" aria-pressed="false" title="显示"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M2.5 12s3.5-6 9.5-6 9.5 6 9.5 6-3.5 6-9.5 6S2.5 12 2.5 12Z"/><circle cx="12" cy="12" r="2.8"/><path class="eye-slash" d="m4 4 16 16"/></svg></button></div></div><div class="field"><label>群组编码 Topic（可选）</label><input id="wechat_topic" placeholder="留空仅发送给自己"></div><p class="sub">通过 PushPlus 微信公众号接收，不使用微信账号密码。</p><button class="secondary" onclick="testChannel('wechat','个人微信')">测试微信</button><details class="channel-guide"><summary>如何获取 PushPlus Token 和 Topic</summary><div class="guide-body"><ol><li>关注“pushplus 推送加”公众号并登录 PushPlus 官网，完成账号绑定。</li><li>在个人中心复制用户 Token，或创建一个专用于 NexRelay 的消息 Token。</li><li>仅发给自己时 Topic 留空；需要一对多时，在 PushPlus 创建群组并复制群组编码 Topic。</li><li>填入、启用并保存，再点击测试微信。</li></ol><div class="guide-links"><a href="https://www.pushplus.plus/" target="_blank" rel="noopener noreferrer">PushPlus 官网 ↗</a><a href="https://pushplus.plus/doc/help/token.html" target="_blank" rel="noopener noreferrer">官方 Token 说明 ↗</a></div><p class="guide-warning">建议使用独立消息 Token，便于日后单独撤销；平台不会保存微信账号密码。</p></div></details></section>
<section class="card"><h2>邮件 SMTP</h2><div class="check"><input id="smtp_enabled" type="checkbox"><label for="smtp_enabled">启用邮件</label></div><div class="row"><div class="field"><label>SMTP 主机</label><input id="smtp_host"></div><div class="field"><label>SSL 端口</label><input id="smtp_port" type="number"></div></div><div class="field"><label>用户名</label><input id="smtp_user"></div><div class="field"><label>密码/授权码（留空保持）</label><div class="secret-input"><input id="smtp_password" type="password"><button type="button" class="secret-toggle" onclick="toggleSecret('smtp_password',this)" aria-label="显示敏感内容" aria-pressed="false" title="显示"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M2.5 12s3.5-6 9.5-6 9.5 6 9.5 6-3.5 6-9.5 6S2.5 12 2.5 12Z"/><circle cx="12" cy="12" r="2.8"/><path class="eye-slash" d="m4 4 16 16"/></svg></button></div></div><div class="field"><label>收件人（逗号分隔）</label><input id="smtp_to"></div><button class="secondary" onclick="testChannel('email','邮件')">测试邮件</button><details class="channel-guide"><summary>如何获取 SMTP 主机、端口和授权码</summary><div class="guide-body"><ol><li>登录发件邮箱的网页设置，找到“SMTP/IMAP/POP3”或“客户端授权”并启用 SMTP。</li><li>从邮箱服务商的帮助页面确认 SMTP 主机和 SSL 端口；常见 SSL 端口为 <code>465</code>，以服务商说明为准。</li><li>用户名通常是完整邮箱地址；开启两步验证后，请生成“应用专用密码”或“客户端授权码”，不要填写网页登录密码。</li><li>收件人可填写一个或多个邮箱，多个地址用英文逗号分隔。</li></ol><p class="guide-warning">授权码视同密码。若服务商只支持 STARTTLS 587，当前 SSL 通道可能不兼容，请使用其 SSL 配置。</p></div></details></section>
<section class="card"><h2>更多推送与自动化</h2><div class="check"><input id="bark_enabled" type="checkbox"><label for="bark_enabled">启用 Bark</label></div><div class="field"><label>Bark 推送 URL</label><input id="bark_url"></div><div class="check"><input id="ntfy_enabled" type="checkbox"><label for="ntfy_enabled">启用 ntfy</label></div><div class="field"><label>ntfy Topic URL</label><input id="ntfy_url"></div><div class="check"><input id="mqtt_enabled" type="checkbox"><label for="mqtt_enabled">启用 MQTT 桥接</label></div><div class="field"><label>MQTT 桥接 Webhook</label><input id="mqtt_webhook"></div><div class="actions"><button class="secondary" onclick="testChannel('bark','Bark')">测 Bark</button><button class="secondary" onclick="testChannel('ntfy','ntfy')">测 ntfy</button><button class="secondary" onclick="testChannel('mqtt','MQTT')">测 MQTT</button></div><details class="channel-guide"><summary>如何获取 Bark、ntfy 和 MQTT 桥接信息</summary><div class="guide-body"><ul><li><b>Bark：</b>在 iPhone/iPad 安装并打开 Bark，复制应用显示的推送地址，通常形如 <code>https://api.day.app/设备密钥</code>。</li><li><b>ntfy：</b>在 ntfy App 或网页订阅一个难以猜测的 Topic，填写完整 Topic URL，例如 <code>https://ntfy.sh/随机主题名</code>；Topic 本身相当于密码。</li><li><b>MQTT 桥接：</b>先在你自己的自动化平台创建一个接收 HTTP JSON、再发布到 MQTT Broker 的桥接 Webhook，把该 HTTPS 地址填入这里。</li></ul><div class="guide-links"><a href="https://bark.day.app/#/tutorial" target="_blank" rel="noopener noreferrer">Bark 官方教程 ↗</a><a href="https://docs.ntfy.sh/publish/" target="_blank" rel="noopener noreferrer">ntfy 官方发布说明 ↗</a><a href="https://mqtt.org/getting-started/" target="_blank" rel="noopener noreferrer">MQTT 官方入门 ↗</a></div><p class="guide-warning">MQTT 桥接字段当前接收的是 <code>https://</code> Webhook，不是 <code>mqtt://</code> Broker 地址。</p></div></details></section>
<section class="group-title"><h2>三、规则与策略</h2><p>控制消息标题、短信筛选和本地数据保留时间。</p></section><section class="card"><h2>消息格式</h2><div class="field"><label for="notification_title">转发消息标题</label><input id="notification_title" maxlength="40" placeholder="IG830 收到短信"></div><div class="field"><label for="test_notification_title">测试消息标题</label><input id="test_notification_title" maxlength="40" placeholder="IG830 测试消息"></div><p class="sub">统一应用于全部转发通道；无需输入【】方括号，平台会自动添加。</p></section><section class="card"><h2>筛选与处理</h2><div class="field"><label>允许的发送方（英文逗号分隔，留空为全部）</label><input id="sender_allow"></div><div class="field"><label>屏蔽的发送方（英文逗号分隔）</label><input id="sender_block"></div><div class="field"><label>正文必须包含的关键词（英文逗号分隔）</label><input id="keyword_include"></div><div class="field"><label>正文排除关键词（英文逗号分隔）</label><input id="keyword_exclude"></div><p class="sub">所有规则均采用包含匹配；屏蔽规则优先于允许规则。</p><div class="check"><input id="forward_existing" type="checkbox"><label for="forward_existing">首次启用时转发现有短信</label></div></section>
<section class="card"><h2>数据保留</h2><div class="field"><label>本地数据保留天数</label><input id="retention_days" type="number" min="1" max="3650"></div><p class="sub">到期后自动清理短信记录、信号历史和审计记录；不会删除第三方平台中已经收到的消息。</p></section>
<section class="card wide sms-compose"><h2>编写与发送短信</h2><p class="sub">通过当前 IG830 与 SIM 卡主动发送一条短信。仅支持单号码人工发送，不支持群发、定时或自动发送。</p><div class="field"><label for="smsRecipient">接收号码</label><input id="smsRecipient" inputmode="tel" autocomplete="off" placeholder="例如 +8613800000000" maxlength="20"></div><div class="field"><label for="smsBody">短信内容</label><textarea id="smsBody" maxlength="70" oninput="updateSmsCount()" placeholder="请输入短信内容，最多 70 个字符"></textarea><div class="compose-meta"><span id="smsCharCount">0 / 70</span></div></div><p class="confirm-hint">为避免误发，两次发送至少间隔 30 秒。</p><div class="actions"><button id="smsSendButton" class="secondary" onclick="sendSms()">发送短信</button><span id="smsSendStatus" class="sub send-status">尚未发送</span></div></section>
<section class="card wide"><h2>短信收件箱与转发状态</h2><div class="actions message-tools"><input id="messageSearch" placeholder="搜索号码或正文"><button class="secondary" onclick="loadMessages()">查询</button><button class="secondary icon-button" onclick="clearMessageSearch()" title="清除搜索并刷新" aria-label="清除搜索并刷新">↻</button></div><p class="sub">时间均按 Asia/Shanghai（UTC+8）显示。</p><div class="message-table-wrap"><table class="table"><thead><tr><th><button type="button" class="column-sort active" data-sort="time" onclick="setMessageSort('time')"><span class="sort-label">时间</span><span class="sort-arrow" aria-hidden="true">↓</span></button></th><th><button type="button" class="column-sort" data-sort="sender" onclick="setMessageSort('sender')"><span class="sort-label">发送方</span><span class="sort-arrow" aria-hidden="true">↕</span></button></th><th><button type="button" class="column-sort" data-sort="body" onclick="setMessageSort('body')"><span class="sort-label">内容</span><span class="sort-arrow" aria-hidden="true">↕</span></button></th><th><button type="button" class="column-sort" data-sort="status" onclick="setMessageSort('status')"><span class="sort-label">转发状态</span><span class="sort-arrow" aria-hidden="true">↕</span></button></th></tr></thead><tbody id="messageRows"><tr><td colspan="4" class="sub">暂无短信</td></tr></tbody></table></div></section>
<section class="card forward-card"><h2>短信转发状态</h2><div class="status forward-row"><div class="metric">运行状态<b id="dashboardForwardStatus">读取中</b></div><div class="metric">通道状态<b id="dashboardChannelCount">0 正常 / 0 已启用</b></div><div class="metric">异常通道<b id="dashboardChannelErrors">0</b></div><div class="metric">最近检查<b id="dashboardLastPoll">—</b></div></div></section><section class="card stats-card"><h2>统计概览</h2><div class="status stats-row"><div class="metric">短信总数<b id="statMessages">0</b></div><div class="metric">今日收到<b id="statToday">0</b></div><div class="metric">成功投递次数<b id="statSuccess">0</b></div><div class="metric">失败/待处理投递<b id="statFailed">0</b></div></div><div id="topSenders" class="sub"></div></section>
<section class="card"><h2>安全与运维</h2><div class="actions"><button class="secondary" onclick="downloadJson('/api/config/export','ig830-config.json')">导出脱敏配置</button><button class="secondary" onclick="downloadJson('/api/diagnostics','ig830-diagnostics.json')">导出诊断包</button><button class="secondary" onclick="showAudit()">查看审计日志</button><button class="secondary" onclick="openCredentials()">修改用户名和密码</button></div><div class="danger-zone"><div class="check confirm-check"><input id="serviceRestartConfirm" type="checkbox"><label for="serviceRestartConfirm">我了解页面会短暂中断，同意重启 NexRelay 服务</label></div><div class="actions"><button class="danger" onclick="restartService()">重启服务</button></div></div><p class="sub">USSD 与 SIM PIN 操作会根据模块响应执行；网络模式、频段、eSIM、VoWiFi 和数据拨号目前仅提供能力检测。</p></section>
<section class="card"><h2>关于 NexRelay-sdjoint</h2><div class="status"><div class="metric">产品名称<b>NexRelay-sdjoint</b></div><div class="metric">软件版本<b id="appVersion">读取中</b></div><div class="metric">配置格式版本<b id="configSchema">读取中</b></div><div class="metric">部署方式<b>本地自托管</b></div></div><p class="sub">面向 IG830 的多通道短信中继与设备管理平台。配置、凭据和短信数据均存储在当前服务器中。</p></section>
<section class="card wide"><h2>SIM、USSD 与高级网络能力</h2><div class="actions"><button class="secondary" onclick="loadCapabilities()">检测硬件能力</button></div><div id="capabilitySummary" class="capability-summary"><p class="sub">尚未检测。敏感标识只显示末四位。</p></div><details class="diagnostic-details"><summary>查看原始诊断信息</summary><pre id="capabilityText" class="sub">尚未检测</pre></details><div class="row"><div><div class="field"><label>USSD 代码</label><input id="ussdCode" placeholder="例如 *100#"></div><div class="check confirm-check"><input id="ussdConfirm" type="checkbox"><label for="ussdConfirm">我了解 USSD 可能变更运营商业务，同意执行</label></div><button class="danger" onclick="runUssd()">发送 USSD 指令</button></div><div><div class="field"><label>SIM PIN（不保存）</label><input id="simPin" type="password"></div><div class="check confirm-check"><input id="simPinConfirm" type="checkbox"><label for="simPinConfirm">我确认 PIN 正确，并同意只尝试一次</label></div><button class="danger" onclick="unlockPin()">解锁 SIM</button></div></div><p class="sub">网络模式、频段、eSIM、VoWiFi 和数据拨号目前仅提供能力检测；检测结果会列出全部可用的 ttyUSB 端口。</p></section>
<section class="card wide log-card"><div class="log-card-head"><div><h2>最近事件</h2><p id="logSummary" class="sub">正在读取日志</p></div><button class="secondary" onclick="downloadLogs()">导出全部日志（CSV）</button></div><p class="sub">时间均按 Asia/Shanghai（UTC+8）显示。</p><div class="log-table-wrap"><table class="table log-table"><thead><tr><th>时间</th><th>事件</th></tr></thead><tbody id="logRows"><tr><td colspan="2" class="sub">暂无记录</td></tr></tbody></table></div><div id="logs" class="hidden"></div><div class="log-pagination"><button id="logPrev" class="secondary" onclick="changeLogPage(-1)">上一页</button><span id="logPageInfo" class="log-page-info">第 1 / 1 页</span><button id="logNext" class="secondary" onclick="changeLogPage(1)">下一页</button></div></section></div><footer class="site-footer"><h2>作者与版权</h2><div class="author-line"><span>NexRelay-sdjoint</span><span>作者：<a href="mailto:zhangzhen01@gmail.com">zhangzhen01@gmail.com</a></span><span>Copyright © <span id="copyrightYear">2026</span> NexRelay-sdjoint contributors</span><span>MIT License</span><span>本地自托管 · 数据由用户掌控</span></div></footer></main><div id="toast"></div>
<div id="credentialsModal" class="modal hidden" role="dialog" aria-modal="true" aria-labelledby="credentialsTitle"><div class="modal-card"><div class="modal-head"><h2 id="credentialsTitle">修改用户名和密码</h2><button type="button" class="modal-close" onclick="closeCredentials()" aria-label="关闭">×</button></div><div class="field"><label for="newUsername">新用户名</label><input id="newUsername" autocomplete="username"></div><div class="field"><label for="newPassword">新密码（至少 10 位）</label><input id="newPassword" type="password" autocomplete="new-password"></div><div class="field"><label for="confirmPassword">确认新密码</label><input id="confirmPassword" type="password" autocomplete="new-password"></div><p id="credentialsError" class="bad hidden"></p><div class="actions"><button class="secondary" onclick="closeCredentials()">取消</button><button onclick="saveCredentials()">保存新凭据</button></div></div></div>
<div id="auditModal" class="modal hidden" role="dialog" aria-modal="true" aria-labelledby="auditTitle"><div class="modal-card audit-card"><div class="modal-head"><h2 id="auditTitle">审计日志</h2><button type="button" class="modal-close" onclick="closeAudit()" aria-label="关闭">×</button></div><div class="message-table-wrap"><table class="table"><thead><tr><th>时间</th><th>操作</th><th>说明</th></tr></thead><tbody id="auditRows"><tr><td colspan="3" class="sub">正在读取</td></tr></tbody></table></div></div></div>
<script>
const fields=['enabled','serial_port','poll_interval','notification_title','test_notification_title','webhook_url','http_method','auth_header','auth_value','sender_allow','sender_block','keyword_include','keyword_exclude','forward_existing','dingtalk_enabled','dingtalk_webhook','dingtalk_secret','feishu_enabled','feishu_webhook','wecom_enabled','wecom_webhook','telegram_enabled','telegram_bot_token','telegram_chat_id','telegram_reply_enabled','telegram_reply_user_id','wechat_enabled','wechat_pushplus_token','wechat_topic','smtp_enabled','smtp_host','smtp_port','smtp_user','smtp_password','smtp_to','bark_enabled','bark_url','ntfy_enabled','ntfy_url','mqtt_enabled','mqtt_webhook','retention_days'];
const secretFields=['auth_value','dingtalk_secret','telegram_bot_token','wechat_pushplus_token','smtp_password'];
let tok=sessionStorage.getItem('ig830Token')||'', user=sessionStorage.getItem('ig830User')||'', lastChannelConfig={}, lastRuntimeChannelErrors={}, lastRuntimeChannelTests={}, channelTestState={}, logPage=1, logPages=1, messageSortField='time', messageSortOrder='desc'; const LOG_PAGE_SIZE=20; const $=id=>document.getElementById(id);
function applyTheme(theme){document.documentElement.dataset.theme=theme;localStorage.setItem('ig830Theme',theme);let button=$('themeBtn');if(button){let dark=theme==='dark';button.textContent=dark?'☀':'☾';let label=dark?'切换到日间模式':'切换到夜间模式';button.title=label;button.setAttribute('aria-label',label)}}
function toggleTheme(){applyTheme((document.documentElement.dataset.theme||'dark')==='dark'?'light':'dark')}
function toggleSecret(id,button){let input=$(id);if(!input)return;let reveal=input.type==='password';input.type=reveal?'text':'password';button.classList.toggle('revealing',reveal);button.setAttribute('aria-pressed',String(reveal));button.setAttribute('aria-label',reveal?'隐藏敏感内容':'显示敏感内容');button.title=reveal?'隐藏':'显示';input.focus()}
applyTheme(localStorage.getItem('ig830Theme')||'dark');
function msg(s,bad=false){let t=$('toast');t.textContent=s;t.style.display='block';t.style.borderColor=bad?'var(--bad)':'var(--accent)';t.style.background=bad?'#fff1f2':'#effff9';t.style.color=bad?'#8b1020':'#073d2d';setTimeout(()=>t.style.display='none',4500)}
async function api(path,opt={}){opt.headers={...(opt.headers||{}),'X-Admin-Token':tok,'X-Admin-Username':user};let r=await fetch(path,opt);let j=await r.json().catch(()=>({error:'响应格式错误'}));if(!r.ok)throw Error(j.error||('HTTP '+r.status));return j}
async function login(){if(!$('disclaimer').checked)return msg('请先阅读并确认免责声明',true);tok=$('token').value;user=$('username').value.trim();try{await api('/api/config');sessionStorage.setItem('ig830Token',tok);sessionStorage.setItem('ig830User',user);showApp();refreshAll()}catch(e){msg('用户名或密码错误',true)}}
async function refreshTelegramReplyStatus(){if(!$('telegramReplyStatus')||!tok)return;try{let s=await api('/api/status'),r=s.runtime||{},e=$('telegramReplyStatus');e.textContent=r.telegram_reply_status||'已停用';e.className=r.telegram_reply_status==='监听中'?'ok':r.telegram_reply_status==='已停用'?'':'bad';e.title=r.telegram_reply_error||''}catch(e){}}
function showApp(){$('login').classList.add('hidden');$('app').classList.remove('hidden');$('sidebar').classList.remove('hidden');$('sidebarUser').textContent=user;refreshTelegramReplyStatus()}
setInterval(refreshTelegramReplyStatus,5000);
function logout(){sessionStorage.clear();location.reload()}
function toggleSidebar(open){let sidebar=$('sidebar'),backdrop=$('mobileBackdrop');if(!sidebar||!backdrop)return;sidebar.classList.toggle('open',!!open);backdrop.classList.toggle('hidden',!open);document.body.classList.toggle('sidebar-open',!!open)}
function openCredentials(){$('newUsername').value=user;$('newPassword').value='';$('confirmPassword').value='';$('credentialsError').classList.add('hidden');$('credentialsModal').classList.remove('hidden');setTimeout(()=>$('newUsername').focus(),0)}
function closeCredentials(){$('credentialsModal').classList.add('hidden');$('newPassword').value='';$('confirmPassword').value=''}
async function saveCredentials(){let nu=$('newUsername').value.trim(),np=$('newPassword').value,confirm=$('confirmPassword').value,error=$('credentialsError');error.classList.add('hidden');if(!nu)return showCredentialError('请输入新用户名');if(np.length<10)return showCredentialError('新密码至少需要 10 个字符');if(np!==confirm)return showCredentialError('两次输入的密码不一致');try{await api('/api/admin/credentials',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:nu,password:np})});closeCredentials();msg('凭据已修改，请使用新凭据重新登录');setTimeout(logout,900)}catch(e){showCredentialError(e.message)}}
function showCredentialError(message){let error=$('credentialsError');error.textContent=message;error.classList.remove('hidden')}
function setChannelDot(name,state){let dot=document.querySelector(`[data-channel-dot="${name}"]`);if(dot){dot.className='channel-dot '+(state==='enabled'?'enabled':state==='error'?'error':'');dot.title=state==='enabled'?'已通过测试':state==='error'?'等待成功测试':'未启用'}}
function getChannelStates(c){let state=(on,ok)=>on&&ok?'enabled':'disabled';let states={custom:state(!!c.webhook_url,/^https?:\/\//i.test(c.webhook_url||'')),dingtalk:state(c.dingtalk_enabled,!!c.dingtalk_webhook),feishu:state(c.feishu_enabled,!!c.feishu_webhook),wecom:state(c.wecom_enabled,!!c.wecom_webhook),telegram:state(c.telegram_enabled,!!c.telegram_bot_token_set&&!!c.telegram_chat_id),wechat:state(c.wechat_enabled,!!c.wechat_pushplus_token_set),email:state(c.smtp_enabled,!!c.smtp_host&&!!c.smtp_user&&!!c.smtp_password_set&&!!c.smtp_to)};let more=[state(c.bark_enabled,!!c.bark_url),state(c.ntfy_enabled,!!c.ntfy_url),state(c.mqtt_enabled,!!c.mqtt_webhook)];states.more=more.includes('enabled')?'enabled':'disabled';return states}
function getChannelActivations(c){return{custom:!!String(c.webhook_url||'').trim(),dingtalk:!!c.dingtalk_enabled,feishu:!!c.feishu_enabled,wecom:!!c.wecom_enabled,telegram:!!c.telegram_enabled,wechat:!!c.wechat_enabled,email:!!c.smtp_enabled,bark:!!c.bark_enabled,ntfy:!!c.ntfy_enabled,mqtt:!!c.mqtt_enabled}}
function updateChannelDots(c,runtimeErrors=lastRuntimeChannelErrors,runtimeTests=lastRuntimeChannelTests){lastChannelConfig=c;lastRuntimeChannelErrors=runtimeErrors||{};lastRuntimeChannelTests=runtimeTests||{};let active=getChannelActivations(c);let tested=name=>channelTestState[name]||lastRuntimeChannelTests[name]||'';for(let name of ['custom','dingtalk','feishu','wecom','telegram','wechat','email']){if(!active[name])setChannelDot(name,'disabled');else setChannelDot(name,!lastRuntimeChannelErrors[name]&&tested(name)==='success'?'enabled':'error')}let moreNames=['bark','ntfy','mqtt'].filter(name=>active[name]);if(!moreNames.length)setChannelDot('more','disabled');else setChannelDot('more',moreNames.every(name=>!lastRuntimeChannelErrors[name]&&tested(name)==='success')?'enabled':'error')}
function parseTimeValue(value){if(!value)return null;let raw=String(value).trim(),match=raw.match(/^(\d{2})\/(\d{2})\/(\d{2}),(\d{2}):(\d{2}):(\d{2})([+-])(\d{2})$/);if(match){let year=2000+Number(match[1]),offset=Number(match[8])*15*(match[7]==='-'?-1:1);return new Date(Date.UTC(year,Number(match[2])-1,Number(match[3]),Number(match[4]),Number(match[5]),Number(match[6]))-offset*60000)}let parsed=new Date(raw);return Number.isNaN(parsed.getTime())?null:parsed}
function localTime(value){let date=parseTimeValue(value);if(!date)return value?String(value):'—';return new Intl.DateTimeFormat('zh-CN',{year:'numeric',month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',second:'2-digit',hourCycle:'h23',timeZone:'Asia/Shanghai'}).format(date).replaceAll('/','-')}
function channelHealthSummary(c,errors={},tests={}){let active=getChannelActivations(c),names=Object.keys(active).filter(name=>active[name]),healthy=names.filter(name=>!errors[name]&&tests[name]==='success');return{active:names.length,healthy:healthy.length,abnormal:names.length-healthy.length,untested:names.filter(name=>!tests[name]).length}}
const channelLabels={custom:'Webhook',dingtalk:'钉钉',feishu:'飞书',wecom:'企业微信',telegram:'Telegram',wechat:'微信通知',email:'邮件',bark:'Bark',ntfy:'ntfy',mqtt:'MQTT 桥接'};
const deliveryLabels={success:'已投递',failed:'投递失败',pending:'等待投递'};
const logKindLabels={service:'系统服务',config:'配置变更',channel:'通道事件',error:'错误',filter:'筛选规则',hardware:'硬件操作',storage:'数据维护','sms.outbound':'主动发送','telegram.reply':'Telegram 回复'};
function logKindLabel(kind){return logKindLabels[kind]||kind||'系统事件'}
function localizedLogMessage(message){let text=String(message||'');for(let [key,label] of Object.entries(channelLabels)){if(text.startsWith(key+' '))return label+text.slice(key.length)}return text}
function fill(c){for(let k of fields){let e=$(k);if(!e)continue;if(e.type==='checkbox')e.checked=!!c[k];else if(!secretFields.includes(k))e.value=c[k]??''}$('enabledPill').textContent=c.enabled?'转发已启用':'转发已停用';$('enabledPill').className='status-note '+(c.enabled?'':'warn-state');updateChannelDots(c)}
async function refreshAll(){try{let [c,s,l,st]=await Promise.all([api('/api/config'),api('/api/status'),api('/api/logs'),api('/api/stats')]);fill(c);let r=s.runtime||{},errors=r.channel_errors||{},tests=r.channel_tests||{};updateChannelDots(c,errors,tests);let health=channelHealthSummary(c,errors,tests),status=!s.device_online?'设备离线':!c.enabled?'已停用':health.active===0?'等待通道配置':health.healthy===health.active?'运行中':health.healthy>0?'部分通道异常':health.untested===health.active?'等待通道测试':'转发异常';$('dashboardForwardStatus').textContent=status;$('dashboardForwardStatus').className=status==='运行中'?'ok':status==='设备离线'||status.includes('异常')?'bad':'warn';$('dashboardChannelCount').textContent=`${health.healthy} 正常 / ${health.active} 已启用`;$('dashboardChannelErrors').textContent=String(health.abnormal);$('dashboardChannelErrors').className=health.abnormal?'bad':'ok';$('dashboardLastPoll').textContent=localTime(r.last_poll);if($('appVersion'))$('appVersion').textContent=`v${s.version}`;if($('configSchema'))$('configSchema').textContent=String(s.config_schema);let deviceOnline=Boolean(s.device_online);if(!deviceOnline){$('enabledPill').textContent='设备离线';$('enabledPill').className='status-note bad-state'}$('usb').textContent=s.usb_present?'已识别':'未检测到';$('usb').className=s.usb_present?'ok':'bad';let usbModeLabel=s.usb_mode==='compatible'?'Linux 兼容':s.usb_mode==='factory'?'大疆出厂':'未知';$('usbMode').textContent=s.usb_present?`${usbModeLabel} · ${s.usb_id||'—'}`:'未检测到';$('usbMode').className=s.usb_present?'ok':'bad';$('serial').textContent=s.serial_present?s.serial_port:'不可用';$('serial').className=s.serial_present?'ok':'bad';$('sim').textContent=deviceOnline?(r.sim_ready?'已就绪':'未就绪'):'设备离线';$('sim').className=deviceOnline&&r.sim_ready?'ok':'bad';$('phoneNumber').textContent=deviceOnline?(r.phone_number||'SIM 未提供'):'设备离线';$('phoneNumber').className=deviceOnline?(r.phone_number?'ok':'warn'):'bad';$('operator').textContent=deviceOnline?(r.operator||'未识别'):'设备离线';$('operator').className=deviceOnline&&r.registered?'ok':deviceOnline?'warn':'bad';$('registration').textContent=deviceOnline?(r.registration||'未知'):'设备离线';$('registration').className=deviceOnline&&r.registered?'ok':deviceOnline?'warn':'bad';let level=deviceOnline?Number(r.signal_level||0):0;document.querySelectorAll('#signalBars i').forEach((e,i)=>e.classList.toggle('on',i<level));$('signalText').textContent=deviceOnline?(r.signal_dbm==null?'未知':`${r.signal_dbm} dBm · ${level}/5`):'设备离线';$('signalText').className=deviceOnline?'':'bad';$('note').textContent=s.note+(deviceOnline&&r.last_error?'；'+r.last_error:'');$('logs').innerHTML=l.length?l.map(x=>`<div class="entry"><b>${esc(logKindLabel(x.kind))}</b> ${esc(localizedLogMessage(x.message))}<br><small>${esc(localTime(x.time))}</small></div>`).join(''):'<div class="sub">暂无记录</div>';$('statMessages').textContent=st.messages;$('statToday').textContent=st.today;$('statSuccess').textContent=st.deliveries.success||0;$('statFailed').textContent=(st.deliveries.failed||0)+(st.deliveries.pending||0);$('topSenders').textContent=st.top_senders.length?'常见发送方：'+st.top_senders.map(x=>`${x.sender}（${x.count} 条）`).join(' · '):'暂无发送方统计';$('copyrightYear').textContent=String(new Date().getFullYear());loadMessages()}catch(e){if(e.message.includes('401'))logout();else msg(e.message,true)}}
async function refreshDeviceStatus(){if(!tok)return;try{let s=await api('/api/status'),c=lastChannelConfig||{},r=s.runtime||{},errors=r.channel_errors||{},tests=r.channel_tests||{},health=channelHealthSummary(c,errors,tests),status=!s.device_online?'设备离线':!c.enabled?'已停用':health.active===0?'等待通道配置':health.healthy===health.active?'运行中':health.healthy>0?'部分通道异常':health.untested===health.active?'等待通道测试':'转发异常';$('dashboardForwardStatus').textContent=status;$('dashboardForwardStatus').className=status==='运行中'?'ok':status==='设备离线'||status.includes('异常')?'bad':'warn';$('dashboardLastPoll').textContent=localTime(r.last_poll);let deviceOnline=Boolean(s.device_online);$('enabledPill').textContent=deviceOnline?(c.enabled?'转发已启用':'转发已停用'):'设备离线';$('enabledPill').className='status-note '+(!deviceOnline?'bad-state':c.enabled?'':'warn-state');$('usb').textContent=s.usb_present?'已识别':'未检测到';$('usb').className=s.usb_present?'ok':'bad';let usbModeLabel=s.usb_mode==='compatible'?'Linux 兼容':s.usb_mode==='factory'?'大疆出厂':'未知';$('usbMode').textContent=s.usb_present?`${usbModeLabel} · ${s.usb_id||'—'}`:'未检测到';$('usbMode').className=s.usb_present?'ok':'bad';$('serial').textContent=s.serial_present?s.serial_port:'不可用';$('serial').className=s.serial_present?'ok':'bad';$('sim').textContent=deviceOnline?(r.sim_ready?'已就绪':'未就绪'):'设备离线';$('sim').className=deviceOnline&&r.sim_ready?'ok':'bad';$('phoneNumber').textContent=deviceOnline?(r.phone_number||'SIM 未提供'):'设备离线';$('phoneNumber').className=deviceOnline?(r.phone_number?'ok':'warn'):'bad';$('operator').textContent=deviceOnline?(r.operator||'未识别'):'设备离线';$('operator').className=deviceOnline&&r.registered?'ok':deviceOnline?'warn':'bad';$('registration').textContent=deviceOnline?(r.registration||'未知'):'设备离线';$('registration').className=deviceOnline&&r.registered?'ok':deviceOnline?'warn':'bad';let level=deviceOnline?Number(r.signal_level||0):0;document.querySelectorAll('#signalBars i').forEach((e,i)=>e.classList.toggle('on',i<level));$('signalText').textContent=deviceOnline?(r.signal_dbm==null?'未知':`${r.signal_dbm} dBm · ${level}/5`):'设备离线';$('signalText').className=deviceOnline?'':'bad';$('note').textContent=s.note+(deviceOnline&&r.last_error?'；'+r.last_error:'')}catch(e){if(e.message.includes('401'))logout()}}
setInterval(()=>{if(!document.hidden)refreshDeviceStatus()},3000);
function collect(){let c={};for(let k of fields){let e=$(k);c[k]=e.type==='checkbox'?e.checked:e.value}c.poll_interval=Number(c.poll_interval);return c}
async function save(){try{let c=await api('/api/config',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify(collect())});channelTestState={};fill(c);await refreshAll();await refreshTelegramReplyStatus();msg('配置已保存；仅修改的通道需重新测试')}catch(e){msg(e.message,true)}}
async function testChannel(channel,label){try{let r=await api('/api/test-channel',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({channel})});channelTestState[channel]='success';updateChannelDots(lastChannelConfig);msg(`${label}测试成功，HTTP ${r.status}`)}catch(e){channelTestState[channel]='error';updateChannelDots(lastChannelConfig);msg(`${label}测试失败：${e.message}`,true)}}
async function loadLogs(page=1){try{let r=await api(`/api/logs?page=${page}&page_size=${LOG_PAGE_SIZE}`);logPage=r.page;logPages=r.pages;$('logRows').innerHTML=r.items.length?r.items.map(x=>`<tr><td>${esc(localTime(x.time))}</td><td><div class="log-event"><span class="log-kind">${esc(logKindLabel(x.kind))}</span><span class="log-message">${esc(localizedLogMessage(x.message))}</span></div></td></tr>`).join(''):'<tr><td colspan="2" class="sub">暂无日志记录</td></tr>';$('logSummary').textContent=`共 ${r.total} 条记录 · 每页 ${r.page_size} 条`;$('logPageInfo').textContent=`第 ${r.page} / ${r.pages} 页`;$('logPrev').disabled=r.page<=1;$('logNext').disabled=r.page>=r.pages}catch(e){msg('日志加载失败：'+e.message,true)}}
function changeLogPage(delta){let target=Math.max(1,Math.min(logPages,logPage+delta));if(target!==logPage)loadLogs(target)}
async function downloadLogs(){try{let r=await fetch('/api/logs/export.csv',{headers:{'X-Admin-Token':tok,'X-Admin-Username':user}});if(!r.ok){let j=await r.json().catch(()=>({}));throw Error(j.error||('HTTP '+r.status))}let blob=await r.blob();let a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download='nexrelay-events.csv';a.click();setTimeout(()=>URL.revokeObjectURL(a.href),1000);msg('全部日志 CSV 已下载')}catch(e){msg('日志下载失败：'+e.message,true)}}
async function readUsbConfig(){try{let u=await api('/api/modem/usb-config');$('usbIdentity').textContent=u.identity||'未知';$('usbCurrent').textContent=`${u.vid}:${u.pid}`;$('usbCurrent').className=u.is_factory?'warn':u.is_compatible?'ok':'bad';$('usbRaw').value=u.raw;$('usbBackup').textContent=u.backup_exists?'已安全保存':'未保存';$('usbBackup').className=u.backup_exists?'ok':'bad';msg('已读取参数并保存符合条件的出厂备份')}catch(e){msg('读取失败：'+e.message,true)}}
function requireCheck(id,message){let e=$(id);if(!e?.checked){msg(message,true);return false}e.checked=false;return true}
async function hardwareAction(path,confirmText,label){try{await api(path,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({confirm:confirmText})});msg(label+'命令已完成');setTimeout(readUsbConfig,1200)}catch(e){msg(label+'失败：'+e.message,true)}}
async function applyUsbConfig(){if(!requireCheck('usbApplyConfirm','请先勾选写入兼容 USB ID 的风险确认'))return;await hardwareAction('/api/modem/usb-config/apply','我已备份并确认修改IG830','写入兼容 USB ID')}
async function restoreUsbConfig(){if(!requireCheck('usbRestoreConfirm','请先勾选恢复出厂参数确认'))return;await hardwareAction('/api/modem/usb-config/restore','我确认恢复IG830出厂USB参数','恢复出厂 USB 参数')}
async function restartIg830(){if(!requireCheck('usbRestartConfirm','请先勾选 IG830 重启确认'))return;try{await api('/api/modem/restart',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({confirm:'确认重启IG830'})});msg('重启命令已发送，请等待 20 秒后重新连接 USB')}catch(e){msg('重启命令失败：'+e.message,true)}}
function updateSmsCount(){let body=$('smsBody')?.value||'';if($('smsCharCount'))$('smsCharCount').textContent=`${body.length} / 70`}
async function sendSms(){let recipient=$('smsRecipient').value.trim(),message=$('smsBody').value;if(!recipient)return msg('请输入一个接收号码',true);if(!message.trim())return msg('请输入短信内容',true);let button=$('smsSendButton');button.disabled=true;$('smsSendStatus').textContent='正在通过 IG830 发送…';$('smsSendStatus').className='sub send-status';try{let result=await api('/api/sms/send',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({recipient,message,confirm:'我确认号码和内容无误，同意发送此短信'})});let reference=result.message_reference?` · 参考号 ${result.message_reference}`:'';$('smsSendStatus').textContent=`发送成功 · ${localTime(result.sent_at)}${reference}`;$('smsSendStatus').className='sub send-status ok';$('smsRecipient').value='';$('smsBody').value='';updateSmsCount();msg('短信已发送');loadLogs(1)}catch(e){$('smsSendStatus').textContent='发送失败：'+e.message;$('smsSendStatus').className='sub send-status bad';msg('短信发送失败：'+e.message,true)}finally{button.disabled=false}}
async function loadMessages(){try{let q=encodeURIComponent($('messageSearch')?.value||'');let r=await api(`/api/messages?q=${q}&sort_by=${messageSortField}&sort=${messageSortOrder}`);$('messageRows').innerHTML=r.items.length?r.items.map(m=>`<tr><td>${esc(localTime(m.received_at||m.stored_at))}</td><td>${esc(m.sender)}</td><td>${esc(m.body)}</td><td>${m.deliveries.filter(d=>d.channel).map(d=>`<span class="badge ${d.status==='success'?'ok':d.status==='failed'?'bad':'warn'}">${esc(channelLabels[d.channel]||d.channel)} · ${esc(deliveryLabels[d.status]||d.status)}${d.status==='failed'?` <button type="button" class="retry-link" onclick="retryDelivery(${d.id})">重试</button>`:''}</span>`).join('')||'<span class="sub">尚未转发</span>'}</td></tr>`).join(''):'<tr><td colspan="4" class="sub">暂无短信</td></tr>'}catch(e){msg('收件箱加载失败：'+e.message,true)}}
function updateMessageSortHeaders(){const labels={time:'时间',sender:'发送方',body:'内容',status:'转发状态'};document.querySelectorAll('.column-sort').forEach(button=>{let active=button.dataset.sort===messageSortField,arrow=button.querySelector('.sort-arrow');button.classList.toggle('active',active);arrow.textContent=active?(messageSortOrder==='desc'?'↓':'↑'):'↕';button.setAttribute('aria-label',active?`按${labels[button.dataset.sort]}排序，当前${messageSortOrder==='desc'?'降序':'升序'}，点击切换`:`按${labels[button.dataset.sort]}排序`)})}
function setMessageSort(field){if(messageSortField===field)messageSortOrder=messageSortOrder==='desc'?'asc':'desc';else{messageSortField=field;messageSortOrder=field==='time'?'desc':'asc'}updateMessageSortHeaders();loadMessages()}
function clearMessageSearch(){if($('messageSearch'))$('messageSearch').value='';loadMessages()}
async function retryDelivery(id){try{await api('/api/delivery/retry',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id})});msg('已加入立即重试队列');loadMessages()}catch(e){msg(e.message,true)}}
async function downloadJson(path,name){try{let data=await api(path);let blob=new Blob([JSON.stringify(data,null,2)],{type:'application/json'});let a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download=name;a.click();URL.revokeObjectURL(a.href)}catch(e){msg(e.message,true)}}
const auditActionLabels={'config.update':'配置更新','sms.send':'发送短信','delivery.retry':'重试投递','sim.unlock':'解锁 SIM','admin.credentials':'修改登录凭据','admin.credentials_changed':'修改登录凭据','admin.rotate_token':'更换管理令牌','service.restart':'重启服务','usb.config.apply':'写入 USB 参数','usb.config.restore':'恢复 USB 参数','modem.restart':'重启 IG830','ussd.run':'执行 USSD'};
function auditDetail(detail){if(!detail)return '—';let text=String(detail);text=text.replace(/enabled=(True|False)/g,(_,v)=>`转发启用：${v==='True'?'是':'否'}`).replace(/recipient=([^ ]+)/g,'接收方：$1').replace(/reference=([^ ]+)/g,'参考号：$1').replace(/username=([^ ]+)/g,'用户名：$1').replace(/PIN redacted/g,'PIN 已隐藏').replace(/code redacted/g,'USSD 代码已隐藏');return text.replace(/\s+(?=(参考号|用户名)：)/g,' · ')}
async function showAudit(){try{let rows=await api('/api/audit');$('auditRows').innerHTML=rows.length?rows.slice(0,100).map(x=>`<tr><td>${esc(localTime(x.created_at))}</td><td>${esc(auditActionLabels[x.action]||x.action)}</td><td>${esc(auditDetail(x.detail))}</td></tr>`).join(''):'<tr><td colspan="3" class="sub">暂无审计记录</td></tr>';$('auditModal').classList.remove('hidden')}catch(e){msg(e.message,true)}}
function closeAudit(){$('auditModal').classList.add('hidden')}
async function restartService(){if(!requireCheck('serviceRestartConfirm','请先勾选服务重启确认'))return;try{await api('/api/service/restart',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({confirm:'确认重启服务'})});msg('服务正在重启，请稍后刷新')}catch(e){msg(e.message,true)}}
function capabilityItem(label,value,state=''){return `<div class="capability-item"><span>${esc(label)}</span><b class="${state}">${esc(value)}</b></div>`}
function yesNo(value){return value?['支持','ok']:['不支持','']}
async function loadCapabilities(){try{let c=await api('/api/modem/capabilities'),identity=String(c.identity||'').split(/\r?\n/).map(x=>x.trim()).filter(x=>x&&x!=='OK').join(' · ')||'未识别',devices=Array.isArray(c.devices)&&c.devices.length?c.devices.join('、'):'未发现',ussd=yesNo(c.ussd_supported),esim=yesNo(c.esim_supported),vowifi=yesNo(c.vowifi_supported),dialing=yesNo(c.data_dialing_supported),band=yesNo(c.band_configurable);$('capabilitySummary').innerHTML=[capabilityItem('模块身份',identity),capabilityItem('可用串口',devices),capabilityItem('SIM 状态',c.sim_state||'未知',c.sim_state==='就绪'?'ok':c.sim_state==='不可用'?'bad':'warn'),capabilityItem('ICCID',c.iccid_masked||'未读取'),capabilityItem('IMSI',c.imsi_masked||'未读取'),capabilityItem('USSD',ussd[0],ussd[1]),capabilityItem('频段配置',band[0],band[1]),capabilityItem('网络模式',c.network_mode||'未知'),capabilityItem('eSIM',esim[0],esim[1]),capabilityItem('VoWiFi',vowifi[0],vowifi[1]),capabilityItem('数据拨号',dialing[0],dialing[1])].join('');$('capabilityText').textContent=JSON.stringify(c,null,2)}catch(e){msg('能力检测失败：'+e.message,true)}}
async function runUssd(){if(!requireCheck('ussdConfirm','请先勾选 USSD 执行确认'))return;try{let r=await api('/api/modem/ussd',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({code:$('ussdCode').value,confirm:'确认执行USSD'})});alert(r.response)}catch(e){msg(e.message,true)}}
async function unlockPin(){if(!requireCheck('simPinConfirm','请先勾选 SIM PIN 尝试确认'))return;try{let r=await api('/api/modem/unlock-pin',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({pin:$('simPin').value,confirm:'确认解锁SIM'})});$('simPin').value='';msg(r.ok?'SIM 已解锁':'模块未确认解锁',!r.ok)}catch(e){$('simPin').value='';msg(e.message,true)}}
function esc(s){return String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
const pageMap={
 '欢迎使用 NexRelay-sdjoint':'dashboard',
 '设备与运营商状态':'dashboard device','短信转发状态':'dashboard','统计概览':'dashboard',
 'IG830 USB 兼容模式转换（高级操作）':'device','SIM、USSD 与高级网络能力':'device',
 '一、全局控制':'proxy','短信转发总开关':'proxy','二、转发通道':'proxy','通道选择':'proxy','自定义 Webhook':'proxy','钉钉机器人':'proxy','飞书机器人':'proxy','企业微信机器人':'proxy','Telegram Bot':'proxy','微信通知（PushPlus）':'proxy','邮件 SMTP':'proxy','更多推送通道':'proxy','三、规则与策略':'proxy','消息格式':'proxy','筛选与处理':'proxy','数据保留':'proxy',
 '编写与发送短信':'sms','短信收件箱与转发状态':'sms','最近事件':'logs',
 '安全与运维':'settings','关于 NexRelay-sdjoint':'settings'
};
document.querySelectorAll('.grid>section').forEach(s=>{let h=s.querySelector('h2');s.dataset.page=pageMap[h?.textContent]||'settings'});
const channelByTitle={'自定义 Webhook':'custom','钉钉机器人':'dingtalk','飞书机器人':'feishu','企业微信机器人':'wecom','Telegram Bot':'telegram','微信通知（PushPlus）':'wechat','邮件 SMTP':'email','更多推送通道':'more'};
document.querySelectorAll('.grid>section[data-page="proxy"]').forEach(s=>{let channel=channelByTitle[s.querySelector('h2')?.textContent];if(channel)s.dataset.channelCard=channel});
document.querySelectorAll('[data-channel-card]').forEach(card=>{let buttons=[...card.querySelectorAll('button[onclick^="testChannel("]')];if(!buttons.length)return;let container=buttons[0].parentElement?.classList.contains('actions')?buttons[0].parentElement:document.createElement('div');if(!container.isConnected){container.className='test-action';buttons[0].before(container);buttons.forEach(button=>container.append(button))}else container.classList.add('test-action');let hint=document.createElement('span');hint.className='test-hint';hint.textContent='使用已保存配置；修改后请先保存';container.append(hint)});
function showChannel(channel){document.querySelectorAll('[data-channel-tab]').forEach(b=>b.classList.toggle('active',b.dataset.channelTab===channel));document.querySelectorAll('[data-channel-card]').forEach(s=>s.classList.toggle('hidden',s.dataset.channelCard!==channel));localStorage.setItem('nexrelayChannel',channel)}
function displayPage(page){document.querySelectorAll('.nav button').forEach(x=>x.classList.toggle('active',x.dataset.page===page));document.querySelectorAll('.grid>section').forEach(s=>s.classList.toggle('hidden',!s.dataset.page.split(' ').includes(page)));if(page==='proxy')showChannel(localStorage.getItem('nexrelayChannel')||'custom');let b=document.querySelector(`.nav button[data-page="${page}"]`);$('pageTitle').textContent=b?.getAttribute('aria-label')||b?.querySelector('.nav-label')?.textContent||'控制台';localStorage.setItem('nexrelayPage',page);toggleSidebar(false);scrollTo(0,0)}
async function refreshPageData(page){if(page==='sms')return Promise.all([refreshDeviceStatus(),loadMessages()]);if(page==='logs')return Promise.all([refreshDeviceStatus(),loadLogs(1)]);return refreshAll()}
let pageRequestId=0;async function showPage(page){let requestId=++pageRequestId,button=document.querySelector(`.nav button[data-page="${page}"]`);if(button)button.disabled=true;try{await refreshPageData(page);if(requestId===pageRequestId)displayPage(page)}finally{if(button)button.disabled=false}}
document.querySelectorAll('.nav button').forEach(b=>b.onclick=()=>showPage(b.dataset.page));
displayPage(localStorage.getItem('nexrelayPage')||'dashboard');
if(tok&&user){showApp();refreshAll()}
</script></body></html>'''

HTML_REPLACEMENTS = {
    "将收到的消息安全转发至钉钉、飞书、企业微信、Telegram、个人微信及其他自定义服务":
        "将收到的消息按配置转发至钉钉、飞书、企业微信、Telegram、微信通知及其他自定义服务",
    "设备实时监控": "设备状态监测",
    "敏感配置留在服务器": "敏感配置存储于本机服务器",
    "号码由 SIM/运营商写入信息提供": "号码由 SIM 或运营商写入的信息提供",
    "不同硬件不能照抄参数": "请勿将其他设备的参数直接用于本机",
    ">目标状态<": ">目标 USB ID<",
    ">当前原始参数<": ">读取到的原始 USB 参数<",
    "总开关开启后，平台只向已经单独启用、配置完整且测试成功的通道转发":
        "总开关开启后，平台只向已经单独启用且配置完整的通道转发",
    "个人微信（PushPlus）": "微信通知（PushPlus）",
    "testChannel('wechat','个人微信')": "testChannel('wechat','微信通知')",
    ">SMTP 主机<": ">SMTP 服务器<",
    "<label>用户名</label><input id=\"smtp_user\">": "<label>发件账号</label><input id=\"smtp_user\">",
    "密码/授权码（留空保持）": "密码或授权码（留空保持原值）",
    "收件人（逗号分隔）": "收件地址（英文逗号分隔）",
    "更多推送与自动化": "更多推送通道",
    "ntfy Topic URL": "ntfy 主题地址（Topic URL）",
    "MQTT 桥接 Webhook": "MQTT HTTP 桥接地址",
    ">测 Bark<": ">测试 Bark<",
    ">测 ntfy<": ">测试 ntfy<",
    ">测 MQTT<": ">测试 MQTT<",
}
for old_text, new_text in HTML_REPLACEMENTS.items():
    HTML = HTML.replace(old_text, new_text)


class Handler(BaseHTTPRequestHandler):
    server_version = f"NexRelay/{APP_VERSION}"

    def log_message(self, fmt, *args):
        pass

    def send_json(self, obj, status=200):
        data = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        self.wfile.write(data)

    def send_file(self, data, content_type, filename):
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        self.wfile.write(data)

    def read_json(self):
        size = int(self.headers.get("Content-Length", "0"))
        if size < 0 or size > 1024 * 1024:
            raise ValueError("请求内容超过 1 MiB 限制")
        return json.loads(self.rfile.read(size) or b"{}")

    def authorized(self):
        cfg = load_config()
        username = self.headers.get("X-Admin-Username", "")
        supplied = self.headers.get("X-Admin-Token", "")
        actual = hashlib.sha256(supplied.encode()).hexdigest()
        return secrets.compare_digest(username, cfg.get("admin_username", "admin")) and secrets.compare_digest(actual, cfg["admin_token_hash"])

    def require_auth(self):
        if self.authorized():
            return True
        self.send_json({"error": "未授权"}, 401)
        return False

    def do_HEAD(self):
        path = urllib.parse.urlparse(self.path).path
        self.send_response(200 if path == "/" else 404)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()

    def do_GET(self):
        parsed_path = urllib.parse.urlparse(self.path)
        path = parsed_path.path
        query = urllib.parse.parse_qs(parsed_path.query)
        if path == "/":
            data = HTML.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'")
            self.end_headers()
            self.wfile.write(data)
            return
        if not self.require_auth():
            return
        if path == "/api/config":
            self.send_json(public_config(load_config()))
        elif path == "/api/status":
            self.send_json(device_status())
        elif path == "/api/logs":
            if "page" in query or "page_size" in query:
                self.send_json(paged_logs(query.get("page", [1])[0], query.get("page_size", [20])[0]))
            else:
                self.send_json(recent_logs())
        elif path == "/api/logs/export.csv":
            self.send_file(logs_csv().encode("utf-8-sig"), "text/csv; charset=utf-8", "nexrelay-events.csv")
        elif path == "/api/messages":
            order = "asc" if query.get("sort", ["desc"])[0].lower() == "asc" else "desc"
            sort_by = query.get("sort_by", ["time"])[0].lower()
            self.send_json(DB.list_messages(query.get("q",[""])[0], bounded_int(query.get("page",[1])[0],1,1,1000000), order=order, sort_by=sort_by))
        elif path == "/api/stats":
            self.send_json(DB.stats())
        elif path == "/api/signal-history":
            self.send_json(DB.signal_history(bounded_int(query.get("hours",[24])[0],24,1,168)))
        elif path == "/api/audit":
            self.send_json(DB.list_audit())
        elif path == "/api/config/export":
            cfg=load_config().copy()
            for key in SECRET_FIELDS: cfg[key]=""
            for key in HIDDEN_LEGACY_FIELDS: cfg.pop(key,None)
            self.send_json({"exported_at":utcnow(),"version":APP_VERSION,"config":cfg})
        elif path == "/api/diagnostics":
            self.send_json({"version":APP_VERSION,"status":device_status(),"config":public_config(load_config()),"recent_logs":recent_logs(30),"stats":DB.stats()})
        elif path == "/api/modem/capabilities":
            try:self.send_json(modem_capabilities())
            except Exception as e:self.send_json({"error":str(e)},502)
        elif path == "/api/modem/usb-config":
            try:
                self.send_json(read_modem_usb_config(save_factory_backup=True))
            except Exception as e:
                self.send_json({"error": str(e)}, 502)
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
            previous_cfg = dict(cfg)
            for key, default in DEFAULTS.items():
                if key in incoming:
                    if key in SECRET_FIELDS and incoming[key] == "":
                        continue
                    cfg[key] = incoming[key]
            cfg["poll_interval"] = max(3, min(3600, int(cfg["poll_interval"])))
            cfg["retention_days"] = bounded_int(cfg.get("retention_days"), 90, 1, 3650)
            cfg["smtp_port"] = bounded_int(cfg.get("smtp_port"), 465, 1, 65535)
            cfg["low_signal_threshold"] = bounded_int(cfg.get("low_signal_threshold"), -105, -140, -30)
            if cfg["http_method"] not in ("POST", "PUT"):
                raise ValueError("请求方法仅支持 POST 或 PUT")
            for title_key in ("notification_title", "test_notification_title"):
                title_value = str(cfg.get(title_key, "")).strip()
                if title_value.startswith("【") and title_value.endswith("】"):
                    title_value = title_value[1:-1].strip()
                if not title_value or len(title_value) > 40 or any(char in title_value for char in "\r\n"):
                    raise ValueError("通知标题需为 1-40 个字符，且不能换行")
                cfg[title_key] = title_value
            reply_user_id = str(cfg.get("telegram_reply_user_id", "")).strip()
            if reply_user_id and not re.fullmatch(r"\d{4,20}", reply_user_id):
                raise ValueError("Telegram 授权回复用户 ID 只能填写数字")
            if cfg.get("telegram_reply_enabled") and str(cfg.get("telegram_chat_id", "")).strip().startswith("-") and not reply_user_id:
                raise ValueError("Telegram 群聊启用反向回复时必须填写授权回复用户 ID")
            changed_channels = changed_channel_configs(previous_cfg, cfg)
            save_config(cfg)
            for channel in changed_channels:
                RUNTIME["channel_errors"].pop(channel, None)
                RUNTIME["channel_tests"].pop(channel, None)
            if changed_channels:
                persist_channel_runtime()
            log_event("config", "转发配置已更新", enabled=bool(cfg["enabled"]))
            DB.audit("config.update", f"enabled={bool(cfg['enabled'])}", self.client_address[0])
            self.send_json(public_config(cfg))
        except (ValueError, TypeError, json.JSONDecodeError) as e:
            self.send_json({"error": str(e)}, 400)

    def do_POST(self):
        if not self.require_auth():
            return
        if self.path not in ("/api/test-webhook", "/api/test-channel", "/api/sms/send", "/api/modem/usb-config/apply", "/api/modem/usb-config/restore", "/api/modem/restart", "/api/modem/ussd", "/api/modem/unlock-pin", "/api/delivery/retry", "/api/admin/rotate-token", "/api/admin/credentials", "/api/service/restart"):
            return self.send_json({"error": "未找到"}, 404)
        operation_channel = ""
        try:
            if self.path == "/api/sms/send":
                body = self.read_json()
                result = send_outbound_sms(body.get("recipient", ""), body.get("message", ""), body.get("confirm", ""), self.client_address[0])
            elif self.path == "/api/modem/ussd":
                body=self.read_json(); result=run_ussd(body.get("code",""),body.get("confirm",""))
            elif self.path == "/api/modem/unlock-pin":
                body=self.read_json(); result=unlock_sim_pin(body.get("pin",""),body.get("confirm",""))
            elif self.path == "/api/delivery/retry":
                delivery_id=int(self.read_json().get("id",0)); DB.retry_delivery(delivery_id); DB.audit("delivery.retry",str(delivery_id),self.client_address[0]); result={"ok":True}
            elif self.path == "/api/admin/rotate-token":
                body=self.read_json()
                if body.get("confirm")!="确认更换管理令牌": raise ValueError("风险确认无效")
                token=secrets.token_urlsafe(24); cfg=load_config(); cfg["admin_token_hash"]=hashlib.sha256(token.encode()).hexdigest(); save_config(cfg); (DATA/"admin-token.txt").write_text(token+"\n"); os.chmod(DATA/"admin-token.txt",0o600); DB.audit("admin.rotate_token","",self.client_address[0]); result={"ok":True,"token":token}
            elif self.path == "/api/admin/credentials":
                body=self.read_json(); username=str(body.get("username","")).strip(); password=str(body.get("password",""))
                if not re.fullmatch(r"[A-Za-z0-9_.-]{3,32}",username): raise ValueError("用户名需为 3-32 位字母、数字、点、横线或下划线")
                if len(password)<10: raise ValueError("密码至少需要 10 位")
                cfg=load_config(); cfg["admin_username"]=username; cfg["admin_token_hash"]=hashlib.sha256(password.encode()).hexdigest(); save_config(cfg); DB.audit("admin.credentials_changed",f"username={username}",self.client_address[0]); result={"ok":True}
            elif self.path == "/api/service/restart":
                if self.read_json().get("confirm")!="确认重启服务": raise ValueError("风险确认无效，请重新勾选后操作")
                DB.audit("service.restart","",self.client_address[0]); self.send_json({"ok":True}); threading.Timer(0.3,restart_current_process).start(); return
            elif self.path == "/api/modem/usb-config/apply":
                result = apply_compatible_usb_config(self.read_json().get("confirm", ""))
            elif self.path == "/api/modem/usb-config/restore":
                result = restore_factory_usb_config(self.read_json().get("confirm", ""))
            elif self.path == "/api/modem/restart":
                result = restart_modem(self.read_json().get("confirm", ""))
            elif self.path == "/api/test-channel":
                channel = self.read_json().get("channel", "")
                operation_channel = channel
                if channel not in ("custom", "dingtalk", "feishu", "wecom", "telegram", "wechat", "email", "bark", "ntfy", "mqtt"):
                    raise ValueError("未知通知通道")
                result = test_channel(channel, load_config())
                RUNTIME["channel_errors"].pop(channel, None)
                RUNTIME["channel_tests"][channel] = "success"
                persist_channel_runtime()
                log_event("channel", f"{channel} 测试成功", status=result["status"])
            else:
                result = test_webhook(load_config())
                log_event("webhook", "测试消息发送成功", status=result["status"])
            self.send_json(result)
        except Exception as e:
            if operation_channel:
                RUNTIME["channel_errors"][operation_channel] = str(e)[:300]
                RUNTIME["channel_tests"][operation_channel] = "error"
                persist_channel_runtime()
            log_event("error", "控制台操作失败", path=self.path, error=str(e))
            self.send_json({"error": str(e)}, 400 if isinstance(e, ValueError) else 502)


if __name__ == "__main__":
    load_config()
    restore_channel_runtime()
    migrate_stored_message_encoding()
    log_event("service", "NexRelay 服务已启动")
    threading.Thread(target=device_monitor, name="device-monitor", daemon=True).start()
    threading.Thread(target=worker, name="sms-worker", daemon=True).start()
    threading.Thread(target=telegram_reply_worker, name="telegram-reply-worker", daemon=True).start()
    ThreadingHTTPServer(("0.0.0.0", 8765), Handler).serve_forever()
