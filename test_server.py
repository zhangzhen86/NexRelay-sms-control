import json
import tempfile
import unittest
from pathlib import Path

import server


class SmsControlTests(unittest.TestCase):
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

    def test_public_config_redacts_auth(self):
        cfg = dict(server.DEFAULTS, auth_value="Bearer secret")
        public = server.public_config(cfg)
        self.assertEqual(public["auth_value"], "")
        self.assertTrue(public["auth_value_set"])


if __name__ == "__main__":
    unittest.main()
