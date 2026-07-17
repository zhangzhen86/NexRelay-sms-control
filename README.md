# NexRelay-sdjoint 短信托管转发功能

面向 DJI/Baiwang IG830 的自托管多通道短信中继平台。提供中文 Web 控制台、设备管理、短信中心、发送方与关键词过滤、失败重试、本地去重、长短信分片合并及安全的 Telegram 反向回复。

> 项目只用于管理你本人合法持有的 SIM 卡和短信。登录密码、Webhook 密钥、短信内容与日志不会提交到 GitHub。

## 功能

- 自动绑定 IG830 的 Linux `option` 串口驱动
- 默认使用 `/dev/ttyUSB2`（可在页面中修改）
- 中文响应式配置页面
- 钉钉、飞书、企业微信、Telegram、PushPlus 微信通知、邮件、Bark、ntfy 与 HTTP-MQTT 桥接
- POST/PUT Webhook 与自定义鉴权请求头
- 发送方白名单、黑名单和关键词规则
- PDU 模式读取中文短信，并根据 UDH 分片信息合并长短信
- 本地去重，按通道记录投递结果并对失败任务退避重试
- 短信中心可人工编写并发送单条中文短信，带号码校验、发送确认、30 秒冷却和脱敏审计
- Telegram 中引用回复已转发的短信，可通过当前 SIM 卡反向发送给原发件人
- 主动发送不支持群发、定时或自动重试，短信正文不会写入平台日志
- 日间/夜间主题、移动端抽屉导航、运行日志、审计日志与脱敏诊断导出
- systemd 后台运行和开机启动
- 无 Python 第三方依赖

## 支持环境

- Ubuntu/Debian Linux，Python 3.10+
- x86_64 或 arm64
- DJI/Baiwang IG830，通过 USB 直通或直接连接服务器
- UTM、PVE 等虚拟化环境需先把 USB 设备直通给 Linux

## 下载与安装

从 Releases 下载最新的 `NexRelay-sms-control-*-linux.tar.gz`：

```bash
tar -xzf NexRelay-sms-control-*-linux.tar.gz
cd NexRelay-sms-control
chmod +x install.sh
./install.sh
```

安装脚本会在需要时请求 `sudo`，完成以下操作：

1. 安装程序到 `/opt/ig830-sms-control`
2. 将运行数据放在 `/var/lib/ig830-sms-control`
3. 把当前用户加入 `dialout` 组
4. 安装 IG830 驱动绑定服务
5. 启动 Web 控制台与短信转发服务

安装完成后访问：

```text
http://你的服务器IP:8765
```

首次登录用户名为 `admin`，终端显示的随机字符串是初始密码。也可在服务器查看：

```bash
sudo cat /var/lib/ig830-sms-control/admin-token.txt
```

## UTM 使用提示

在虚拟机运行时打开 UTM 工具栏的“USB 设备”，将 `Baiwang` 连接给 Ubuntu。Ubuntu 中应能看到：

```bash
lsusb | grep 2ca3:4006
ls -l /dev/ttyUSB*
```

## Webhook 数据格式

收到短信后发送 JSON：

```json
{
  "event": "sms.received",
  "device": "IG830",
  "sender": "+8613800000000",
  "message": "示例短信",
  "received_at": "26/07/17,18:30:00+32",
  "modem_index": 1
}
```

只有 HTTP 2xx 响应才被视为成功。短信只保存一份，平台会按通道记录成功或失败状态；失败任务按退避间隔自动重试，也可以在短信中心手动重试。

## 常用命令

```bash
sudo systemctl status ig830-sms-control
sudo journalctl -u ig830-sms-control -f
sudo systemctl restart ig830-sms-control
```

卸载程序但保留运行数据：

```bash
./uninstall.sh
```

## 安全建议

- 默认端口为 `8765`，建议仅在内网或 VPN 中访问。
- 不要把 `admin-token.txt`、`config.json`、`events.log` 上传到公开仓库；首次登录后应修改用户名和密码。
- Webhook 应优先使用 HTTPS，并设置独立的 Bearer Token。
- 第三方通道的 Token、Webhook 和邮箱授权码均视同密码，截图或求助时应先遮盖。

## 当前硬件说明

IG830 的不同批次可能使用不同 AT 端口。如果 `/dev/ttyUSB2` 无响应，可在页面改为 `/dev/ttyUSB3` 后重试。

“设备管理”中的 USB 兼容模式转换属于高风险高级操作，会永久修改模块的 `AT+QCFG="usbcfg"` 参数。平台会先读取并保存本机出厂参数，只替换 VID/PID，并要求用户分别确认写入和重启。UTM 快照或 Ubuntu 备份无法回滚模块内部参数；请勿把其他设备的参数直接用于本机。

## 许可证

MIT
