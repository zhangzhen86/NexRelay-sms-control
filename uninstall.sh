#!/usr/bin/env bash
set -euo pipefail
sudo systemctl disable --now ig830-sms-control.service ig830-bind-driver.service 2>/dev/null || true
sudo rm -f /etc/systemd/system/ig830-sms-control.service /etc/systemd/system/ig830-bind-driver.service /usr/local/sbin/ig830-bind-driver
sudo rm -rf /opt/ig830-sms-control
sudo systemctl daemon-reload
echo "程序已卸载。运行数据仍保留在 /var/lib/ig830-sms-control。"
