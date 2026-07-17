#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -eq 0 ]]; then
  echo "请以普通用户运行：./install.sh（脚本会在需要时调用 sudo）" >&2
  exit 1
fi

APP_USER=${USER}
APP_DIR=/opt/ig830-sms-control
DATA_DIR=/var/lib/ig830-sms-control
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

sudo install -d -m 0755 "$APP_DIR"
sudo install -m 0755 "$SCRIPT_DIR/server.py" "$APP_DIR/server.py"
sudo install -d -o "$APP_USER" -g "$APP_USER" -m 0700 "$DATA_DIR"
sudo usermod -aG dialout "$APP_USER"

sudo tee /usr/local/sbin/ig830-bind-driver >/dev/null <<'EOF'
#!/usr/bin/env bash
set -e
modprobe option
if [[ -w /sys/bus/usb-serial/drivers/option1/new_id ]]; then
  printf '2ca3 4006\n' > /sys/bus/usb-serial/drivers/option1/new_id 2>/dev/null || true
fi
EOF
sudo chmod 0755 /usr/local/sbin/ig830-bind-driver

sudo tee /etc/systemd/system/ig830-bind-driver.service >/dev/null <<'EOF'
[Unit]
Description=Bind DJI/Baiwang IG830 to Linux option driver
Before=ig830-sms-control.service
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/ig830-bind-driver
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
EOF

sudo tee /etc/systemd/system/ig830-sms-control.service >/dev/null <<EOF
[Unit]
Description=IG830 SMS Forwarding Control Panel
After=network-online.target ig830-bind-driver.service
Wants=network-online.target
[Service]
Type=simple
User=$APP_USER
Group=$APP_USER
SupplementaryGroups=dialout
WorkingDirectory=$APP_DIR
Environment=IG830_DATA_DIR=$DATA_DIR
ExecStart=/usr/bin/python3 $APP_DIR/server.py
Restart=on-failure
RestartSec=3
UMask=0077
[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now ig830-bind-driver.service ig830-sms-control.service
echo "安装完成：http://$(hostname -I | awk '{print $1}'):8765"
echo "管理令牌：$(sudo cat "$DATA_DIR/admin-token.txt")"
echo "重新登录一次后，dialout 组权限将完全生效。"
