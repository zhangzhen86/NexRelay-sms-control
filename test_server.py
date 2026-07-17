import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import server
from storage import Storage


class SmsControlTests(unittest.TestCase):
    def test_html_exposes_only_current_ui_and_clear_labels(self):
        for legacy in (
            "数据与告警策略", "短信收件箱与逐通道投递", "个人微信（PushPlus）",
            "更多推送与自动化", "启用全部短信转发任务", "实时日志",
        ):
            self.assertNotIn(legacy, server.HTML)
        for current in (
            "数据保留", "短信收件箱与转发状态", "微信通知（PushPlus）",
            "运行日志", "credentialsModal", "auditModal", "capabilitySummary", "device_online?'设备离线'",
        ):
            self.assertIn(current, server.HTML)
        self.assertNotIn('id="smsSendConfirm"', server.HTML)
        self.assertNotIn("$('smsSendConfirm')", server.HTML)
        self.assertIn("border:0!important", server.HTML)

    def test_filter_rules(self):
        cfg = dict(server.DEFAULTS, sender_allow="10086,+138", sender_block="spam", keyword_include="验证码,code", keyword_exclude="广告")
        self.assertTrue(server.should_forward("10086", "您的验证码是 1234", cfg))
        self.assertFalse(server.should_forward("95555", "您的验证码是 1234", cfg))
        self.assertFalse(server.should_forward("10086", "验证码广告", cfg))

    def test_parse_cmgl(self):
        raw = '\r\n+CMGL: 7,"REC UNREAD","+8613800000000",,"26/07/17,18:30:00+32"\r\nhello world\r\n\r\nOK\r\n'
        messages = server.parse_cmgl(raw)
        self.assertEqual(len(messages), 1)
        self.assertEqual(messages[0]["index"], 7)
        self.assertEqual(messages[0]["sender"], "+8613800000000")
        self.assertEqual(messages[0]["message"], "hello world")

    @staticmethod
    def deliver_pdu(body, index=1, concat=None):
        first_octet = 0x44 if concat else 0x04
        user_data = body.encode("utf-16-be")
        if concat:
            reference, total, part = concat
            user_data = bytes([5, 0, 3, reference, total, part]) + user_data
        header = bytes.fromhex("00") + bytes([first_octet, 5, 0x81]) + bytes.fromhex("0180F6")
        header += bytes.fromhex("000862708100807323")
        pdu = (header + bytes([len(user_data)]) + user_data).hex().upper()
        return f'\r\n+CMGL: {index},1,,{len(bytes.fromhex(pdu)) - 1}\r\n{pdu}\r\n\r\nOK\r\n'

    def test_parse_pdu_normalizes_sender_time_and_ucs2(self):
        messages = server.parse_cmgl_pdu(self.deliver_pdu("你好，验证码1234"))
        self.assertEqual(len(messages), 1)
        self.assertEqual(messages[0]["sender"], "10086")
        self.assertEqual(messages[0]["received_at"], "26/07/18,00:08:37+32")
        self.assertEqual(messages[0]["message"], "你好，验证码1234")

    def test_parse_pdu_merges_udh_long_sms_parts(self):
        first = self.deliver_pdu("这是长短信的前半段，", 7, (19, 2, 1)).replace("\r\nOK\r\n", "")
        second = self.deliver_pdu("这是后半段。", 8, (19, 2, 2)).replace("\r\n+CMGL:", "+CMGL:")
        messages = server.parse_cmgl_pdu(first + second)
        self.assertEqual(len(messages), 1)
        self.assertEqual(messages[0]["index"], 7)
        self.assertEqual(messages[0]["message"], "这是长短信的前半段，这是后半段。")

    def test_decodes_modem_ucs2_without_corrupting_plain_codes(self):
        encoded = "79FB5A036CA1740689E360A8768495EE9898FF0C60A863624E2A95EE6CD5518D8BD58BD553EF4EE55417FF1F30104E2D56FD79FB52A83011"
        self.assertEqual(server.decode_modem_text(encoded), "移娃没理解您的问题，您换个问法再试试可以吗？【中国移动】")
        self.assertEqual(server.decode_modem_text("0031003200330034"), "1234")
        self.assertEqual(server.decode_modem_text("12345678"), "12345678")
        self.assertEqual(server.decode_modem_text("ABCD1234"), "ABCD1234")

    def test_parse_cmgl_decodes_ucs2_body(self):
        raw = '\r\n+CMGL: 0,"REC READ","10086",,"26/07/17,22:39:07+32"\r\n4F60597DFF0C9A8C8BC17801662F0031003200330034\r\n\r\nOK\r\n'
        messages = server.parse_cmgl(raw)
        self.assertEqual(messages[0]["message"], "你好，验证码是1234")
        self.assertEqual(messages[0]["_fingerprint_message"], "4F60597DFF0C9A8C8BC17801662F0031003200330034")

    def test_public_config_redacts_auth(self):
        cfg = dict(server.DEFAULTS, auth_value="Bearer secret", dingtalk_secret="SECsecret", telegram_bot_token="123:secret", wechat_pushplus_token="push-secret")
        public = server.public_config(cfg)
        self.assertEqual(public["auth_value"], "")
        self.assertTrue(public["auth_value_set"])
        self.assertEqual(public["dingtalk_secret"], "")
        self.assertTrue(public["dingtalk_secret_set"])
        self.assertEqual(public["telegram_bot_token"], "")
        self.assertTrue(public["telegram_bot_token_set"])
        self.assertEqual(public["wechat_pushplus_token"], "")
        self.assertTrue(public["wechat_pushplus_token_set"])

    def test_custom_notification_titles_format_message(self):
        cfg = dict(server.DEFAULTS, notification_title="家庭短信中继", test_notification_title="通道自检")
        sms = {"sender": "10086", "message": "余额提醒", "received_at": "now"}
        self.assertTrue(server.sms_text(sms, cfg).startswith("【家庭短信中继】"))
        self.assertTrue(server.sms_text(sms, cfg, test=True).startswith("【通道自检】"))
        self.assertEqual(server.notification_title(dict(cfg, notification_title="【已有括号】")), "已有括号")

    def test_custom_title_reaches_channel_specific_payloads(self):
        sms = {"sender": "10086", "message": "余额提醒", "received_at": "now"}
        cfg = dict(
            server.DEFAULTS,
            notification_title="自定义通知",
            webhook_url="https://example.test/hook",
            dingtalk_webhook="https://example.test/dingtalk",
            telegram_bot_token="token",
            telegram_chat_id="123",
            wechat_pushplus_token="push",
            bark_url="https://example.test/bark",
            ntfy_url="https://example.test/topic",
            mqtt_webhook="https://example.test/mqtt",
        )
        generic_response = {"status": 200, "body": "{}"}
        telegram_response = {"status": 200, "body": json.dumps({"ok": True, "result": {"message_id": 1}})}
        push_response = {"status": 200, "body": json.dumps({"code": 200})}
        with mock.patch.object(server, "post_json", return_value=generic_response) as post:
            server.send_channel("custom", cfg, sms)
            self.assertEqual(post.call_args.args[1]["title"], "自定义通知")
            server.send_channel("dingtalk", cfg, sms)
            self.assertIn("【自定义通知】", post.call_args.args[1]["text"]["content"])
            for channel in ("bark", "ntfy", "mqtt"):
                server.send_channel(channel, cfg, sms)
                self.assertEqual(post.call_args.args[1]["title"], "自定义通知")
        with mock.patch.object(server, "post_json", return_value=telegram_response) as post:
            server.send_channel("telegram", cfg, sms)
            self.assertIn("【自定义通知】", post.call_args.args[1]["text"])
        with mock.patch.object(server, "post_json", return_value=push_response) as post:
            server.send_channel("wechat", cfg, sms)
            self.assertEqual(post.call_args.args[1]["title"], "自定义通知")
        email_cfg = dict(cfg, smtp_host="smtp.example.test", smtp_user="sender@example.test", smtp_password="secret", smtp_to="to@example.test")
        with mock.patch.object(server.smtplib, "SMTP_SSL") as smtp:
            server.send_channel("email", email_cfg, sms)
            sent_message = smtp.return_value.__enter__.return_value.send_message.call_args.args[0]
            self.assertEqual(sent_message["Subject"], "自定义通知")

    def test_at_value(self):
        self.assertEqual(server.at_value("\r\n+CSQ: 20,99\r\nOK\r\n", "+CSQ:"), "20,99")

    def test_parse_local_phone_number(self):
        self.assertEqual(server.parse_cnum('\r\n+CNUM: "","+8613800000000",145\r\nOK\r\n'), "+8613800000000")
        self.assertEqual(server.parse_cnum("\r\nOK\r\n"), "")

    def test_device_status_clears_stale_network_data_when_modem_is_removed(self):
        original_runtime = dict(server.RUNTIME)
        try:
            server.RUNTIME.update({
                "sim_ready": True,
                "phone_number": "+8613800000000",
                "signal_rssi": 20,
                "signal_dbm": -73,
                "signal_level": 4,
                "operator": "CHINA MOBILE",
                "registered": True,
                "registration": "已注册（本地）",
            })
            with tempfile.TemporaryDirectory() as directory, \
                    mock.patch.object(server, "load_config", return_value={"serial_port": str(Path(directory) / "ttyUSB2")}), \
                    mock.patch.object(server, "detect_ig830_usb", return_value={"present": False, "id": "", "mode": ""}):
                status = server.device_status()
            self.assertFalse(status["device_online"])
            self.assertFalse(status["runtime"]["sim_ready"])
            self.assertEqual(status["runtime"]["phone_number"], "")
            self.assertIsNone(status["runtime"]["signal_dbm"])
            self.assertEqual(status["runtime"]["signal_level"], 0)
            self.assertEqual(status["runtime"]["operator"], "")
            self.assertFalse(status["runtime"]["registered"])
            self.assertEqual(status["runtime"]["registration"], "设备离线")
        finally:
            server.RUNTIME.clear()
            server.RUNTIME.update(original_runtime)

    def test_builds_single_part_ucs2_sms_submit_pdu(self):
        message = "您的验证码是 123456"
        pdu_hex, tpdu_length, number = server.build_sms_submit_pdu("+86 138-0000-0000", message)
        pdu = bytes.fromhex(pdu_hex)
        self.assertEqual(number, "+8613800000000")
        self.assertEqual(pdu[0], 0)
        self.assertEqual(tpdu_length, len(pdu) - 1)
        self.assertTrue(pdu.endswith(message.encode("utf-16-be")))
        self.assertEqual(server.mask_phone_number(number), "+86*******0000")

    def test_rejects_bulk_or_oversized_outbound_sms(self):
        for invalid in ("", "13800000000,13900000000", "13800000000;13900000000", "abc"):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                server.normalize_sms_recipient(invalid)
        with self.assertRaises(ValueError):
            server.build_sms_submit_pdu("13800000000", "中" * 71)

    def test_bounded_int_and_quiet_time_validation(self):
        self.assertEqual(server.bounded_int("999", 10, 1, 100), 100)
        self.assertEqual(server.bounded_int("bad", 10, 1, 100), 10)
        self.assertTrue(server.valid_hhmm("23:59"))
        self.assertTrue(server.valid_hhmm(""))
        self.assertFalse(server.valid_hhmm("24:00"))
        self.assertFalse(server.valid_hhmm("7:30"))

    def test_enabled_channels(self):
        cfg = dict(server.DEFAULTS, dingtalk_enabled=True, feishu_enabled=True, wechat_enabled=True)
        self.assertEqual(server.enabled_channels(cfg), ["dingtalk", "feishu", "wechat"])

    def test_changed_channel_configs_only_invalidates_edited_channel(self):
        before = dict(
            server.DEFAULTS,
            telegram_enabled=True,
            telegram_bot_token="token",
            telegram_chat_id="123",
            feishu_enabled=True,
            feishu_webhook="https://example.test/old",
        )
        after = dict(before, feishu_webhook="https://example.test/new", quiet_start="22:00")
        self.assertEqual(server.changed_channel_configs(before, after), {"feishu"})

    def test_global_config_change_preserves_all_channel_tests(self):
        before = dict(server.DEFAULTS, telegram_enabled=True, telegram_bot_token="token", telegram_chat_id="123")
        after = dict(before, enabled=True, keyword_include="验证码")
        self.assertEqual(server.changed_channel_configs(before, after), set())

    def test_channel_test_state_survives_service_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            original = server.STATE_FILE
            original_tests = server.RUNTIME["channel_tests"]
            original_errors = server.RUNTIME["channel_errors"]
            try:
                server.STATE_FILE = Path(directory) / "state.json"
                server.RUNTIME["channel_tests"] = {"telegram": "success", "feishu": "error"}
                server.RUNTIME["channel_errors"] = {"feishu": "HTTP 400"}
                server.persist_channel_runtime()
                server.RUNTIME["channel_tests"] = {}
                server.RUNTIME["channel_errors"] = {}
                server.restore_channel_runtime()
                self.assertEqual(server.RUNTIME["channel_tests"], {"telegram": "success", "feishu": "error"})
                self.assertEqual(server.RUNTIME["channel_errors"], {"feishu": "HTTP 400"})
            finally:
                server.STATE_FILE = original
                server.RUNTIME["channel_tests"] = original_tests
                server.RUNTIME["channel_errors"] = original_errors

    def test_log_pagination_and_csv_export(self):
        with tempfile.TemporaryDirectory() as directory:
            original = server.LOG_FILE
            try:
                server.LOG_FILE = Path(directory) / "events.log"
                rows = [
                    {"time": f"2026-07-17T00:00:{index:02d}+00:00", "kind": "event", "message": f"event-{index}"}
                    for index in range(45)
                ]
                server.LOG_FILE.write_text("\n".join(json.dumps(row, ensure_ascii=False) for row in rows) + "\n", encoding="utf-8")
                page = server.paged_logs(2, 20)
                self.assertEqual(page["total"], 45)
                self.assertEqual(page["pages"], 3)
                self.assertEqual(len(page["items"]), 20)
                self.assertEqual(page["items"][0]["message"], "event-24")
                exported = server.logs_csv()
                self.assertTrue(exported.startswith("时间,事件\n"))
                self.assertIn("[event] event-44", exported)
            finally:
                server.LOG_FILE = original

    def test_detects_factory_and_compatible_usb_ids(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            device = root / "3-3"
            device.mkdir()
            (device / "idVendor").write_text("2ca3\n", encoding="utf-8")
            (device / "idProduct").write_text("4006\n", encoding="utf-8")
            self.assertEqual(server.detect_ig830_usb(root), {"present": True, "id": "2ca3:4006", "mode": "factory"})
            (device / "idVendor").write_text("2c7c\n", encoding="utf-8")
            (device / "idProduct").write_text("0125\n", encoding="utf-8")
            self.assertEqual(server.detect_ig830_usb(root), {"present": True, "id": "2c7c:0125", "mode": "compatible"})

    def test_parse_and_preserve_usb_config(self):
        raw = '\r\n+QCFG: "usbcfg",0x2CA3,0x4006,1,1,1,1,1,0,0\r\nOK\r\n'
        parsed = server.parse_usb_config(raw)
        self.assertEqual(parsed["vid"], 0x2CA3)
        self.assertEqual(parsed["pid"], 0x4006)
        self.assertEqual(parsed["tail"], [1, 1, 1, 1, 1, 0, 0])
        self.assertEqual(server.usb_config_command(parsed, 0x2C7C, 0x0125), 'AT+QCFG="usbcfg",0x2C7C,0x0125,1,1,1,1,1,0,0')

    def test_rejects_unsafe_usb_config(self):
        with self.assertRaises(ValueError):
            server.parse_usb_config('+QCFG: "usbcfg",0x2CA3,0x4006,9,1')

    def test_sqlite_message_and_delivery_flow(self):
        with tempfile.TemporaryDirectory() as directory:
            db = Storage(Path(directory) / "test.db")
            sms = {"index": 1, "sender": "10086", "message": "hello", "received_at": "now"}
            message_id = db.store_message("fingerprint", sms)
            db.enqueue(message_id, ["wechat", "telegram"])
            due = db.due_deliveries()
            self.assertEqual({x["channel"] for x in due}, {"wechat", "telegram"})
            db.delivery_result(due[0]["id"], True)
            stats = db.stats()
            self.assertEqual(stats["messages"], 1)
            self.assertEqual(stats["deliveries"]["success"], 1)

    def test_telegram_forward_is_mapped_for_safe_reply(self):
        with tempfile.TemporaryDirectory() as directory:
            db = Storage(Path(directory) / "test.db")
            message_id = db.store_message("reply-source", {"index": 3, "sender": "10086", "message": "余额提醒", "received_at": "now"})
            cfg = dict(server.DEFAULTS, telegram_enabled=True, telegram_bot_token="token", telegram_chat_id="123", telegram_reply_enabled=True)
            response = {"status": 200, "body": json.dumps({"ok": True, "result": {"message_id": 456}})}
            with mock.patch.object(server, "DB", db), mock.patch.object(server, "post_json", return_value=response) as post:
                server.send_channel("telegram", cfg, {"sender": "10086", "message": "余额提醒", "received_at": "now", "_stored_message_id": message_id})
            self.assertEqual(db.telegram_reply_target("123", 456)["sender"], "10086")
            payload = post.call_args.args[1]
            self.assertTrue(payload["reply_markup"]["force_reply"])

    def test_telegram_reply_requires_matching_chat_and_quoted_message(self):
        with tempfile.TemporaryDirectory() as directory:
            db = Storage(Path(directory) / "test.db")
            message_id = db.store_message("reply-auth", {"index": 4, "sender": "+8613800000000", "message": "验证码", "received_at": "now"})
            db.link_telegram_message("123", 456, message_id)
            cfg = dict(server.DEFAULTS, telegram_reply_enabled=True, telegram_chat_id="123")
            update = {"update_id": 9, "message": {"message_id": 10, "text": "收到，谢谢", "chat": {"id": 123, "type": "private"}, "from": {"id": 88, "is_bot": False}, "reply_to_message": {"message_id": 456}}}
            request = server.telegram_reply_request(update, cfg, db)
            self.assertEqual(request["target"]["sender"], "+8613800000000")
            self.assertIsNone(server.telegram_reply_request({**update, "message": {**update["message"], "chat": {"id": 999, "type": "private"}}}, cfg, db))
            self.assertIsNone(server.telegram_reply_request({**update, "message": {key: value for key, value in update["message"].items() if key != "reply_to_message"}}, cfg, db))

    def test_telegram_reply_is_claimed_once_before_sms_send(self):
        with tempfile.TemporaryDirectory() as directory:
            db = Storage(Path(directory) / "test.db")
            message_id = db.store_message("reply-once", {"index": 5, "sender": "10086", "message": "查询", "received_at": "now"})
            db.link_telegram_message("123", 456, message_id)
            cfg = dict(server.DEFAULTS, telegram_reply_enabled=True, telegram_chat_id="123")
            update = {"update_id": 11, "message": {"message_id": 12, "text": "回复内容", "chat": {"id": 123, "type": "private"}, "from": {"id": 88, "is_bot": False}, "reply_to_message": {"message_id": 456}}}
            sent = []
            def fake_sender(recipient, body, confirm, remote):
                sent.append((recipient, body, remote))
                return {"sent_at": "now"}
            with mock.patch.object(server, "telegram_bot_notice"):
                self.assertTrue(server.handle_telegram_reply(update, cfg, db, fake_sender))
                self.assertFalse(server.handle_telegram_reply(update, cfg, db, fake_sender))
            self.assertEqual(sent, [("10086", "回复内容", "telegram:123")])

    def test_migrates_stored_ucs2_message_body(self):
        with tempfile.TemporaryDirectory() as directory:
            db = Storage(Path(directory) / "test.db")
            encoded = "4F60597DFF0C9A8C8BC17801662F0031003200330034"
            db.store_message("encoded", {"index": 1, "sender": "10086", "message": encoded, "received_at": "now"})
            self.assertEqual(db.transform_message_bodies(server.decode_modem_text), 1)
            self.assertEqual(db.list_messages()["items"][0]["body"], "你好，验证码是1234")
            self.assertEqual(db.transform_message_bodies(server.decode_modem_text), 0)

    def test_message_list_sorts_by_received_time_in_both_directions(self):
        with tempfile.TemporaryDirectory() as directory:
            db = Storage(Path(directory) / "test.db")
            db.store_message("newer-first", {"index": 1, "sender": "10010", "message": "beta", "received_at": "26/07/18,01:09:24+32"})
            db.store_message("older-second", {"index": 2, "sender": "10086", "message": "alpha", "received_at": "26/07/17,23:45:16+32"})
            self.assertEqual([row["body"] for row in db.list_messages(order="desc")["items"]], ["beta", "alpha"])
            self.assertEqual([row["body"] for row in db.list_messages(order="asc")["items"]], ["alpha", "beta"])
            self.assertEqual([row["sender"] for row in db.list_messages(order="asc", sort_by="sender")["items"]], ["10010", "10086"])
            self.assertEqual([row["body"] for row in db.list_messages(order="asc", sort_by="body")["items"]], ["alpha", "beta"])

    def test_message_list_sorts_by_delivery_status(self):
        with tempfile.TemporaryDirectory() as directory:
            db = Storage(Path(directory) / "test.db")
            none_id = db.store_message("none", {"index": 1, "sender": "1", "message": "none", "received_at": "26/07/18,01:00:00+32"})
            failed_id = db.store_message("failed", {"index": 2, "sender": "2", "message": "failed", "received_at": "26/07/18,01:01:00+32"})
            pending_id = db.store_message("pending", {"index": 3, "sender": "3", "message": "pending", "received_at": "26/07/18,01:02:00+32"})
            success_id = db.store_message("success", {"index": 4, "sender": "4", "message": "success", "received_at": "26/07/18,01:03:00+32"})
            self.assertTrue(none_id)
            for message_id in (failed_id, pending_id, success_id):
                db.enqueue(message_id, ["telegram"])
            deliveries = {row["message_id"]: row for row in db.due_deliveries()}
            db.delivery_result(deliveries[failed_id]["id"], False, "failed")
            db.delivery_result(deliveries[success_id]["id"], True)
            self.assertEqual(
                [row["body"] for row in db.list_messages(order="asc", sort_by="status")["items"]],
                ["none", "failed", "pending", "success"],
            )
            self.assertEqual(
                [row["body"] for row in db.list_messages(order="desc", sort_by="status")["items"]],
                ["success", "pending", "failed", "none"],
            )

    def test_deduplicates_same_physical_message_and_keeps_success(self):
        with tempfile.TemporaryDirectory() as directory:
            db = Storage(Path(directory) / "test.db")
            sms = {"index": 2, "sender": "10086", "message": "hello", "received_at": "same-time"}
            first_id = db.store_message("raw-fingerprint", sms)
            second_id = db.store_message("decoded-fingerprint", sms)
            db.enqueue(first_id, ["telegram"])
            db.enqueue(second_id, ["telegram"])
            deliveries = {row["message_id"]: row for row in db.due_deliveries()}
            db.delivery_result(deliveries[first_id]["id"], False, "temporary")
            db.delivery_result(deliveries[second_id]["id"], True)
            self.assertEqual(db.deduplicate_messages(), 1)
            self.assertEqual(db.stats()["messages"], 1)
            self.assertEqual(db.stats()["deliveries"], {"success": 1})

    def test_merges_legacy_fragments_into_complete_pdu_message(self):
        with tempfile.TemporaryDirectory() as directory:
            db = Storage(Path(directory) / "test.db")
            timestamp = "26/07/18,00:43:06+32"
            first = db.store_message("part-1", {"index": 7, "sender": "10086", "message": "长短信前半段", "received_at": timestamp})
            second = db.store_message("part-2", {"index": 8, "sender": "10086", "message": "，后半段。", "received_at": timestamp})
            complete = db.store_message("complete", {"index": 7, "sender": "10086", "message": "长短信前半段，后半段。", "received_at": timestamp})
            db.enqueue(first, ["telegram"])
            delivery = db.due_deliveries()[0]
            db.delivery_result(delivery["id"], True)
            self.assertEqual(db.merge_contained_message_parts(), 2)
            rows = db.list_messages()["items"]
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["id"], complete)
            self.assertEqual(rows[0]["body"], "长短信前半段，后半段。")
            self.assertEqual(rows[0]["deliveries"][0]["status"], "success")


if __name__ == "__main__":
    unittest.main()
