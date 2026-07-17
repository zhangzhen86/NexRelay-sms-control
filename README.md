# IG830 SMS Control

面向 DJI/Baiwang IG830（USB ID `2ca3:4006`）的自托管短信接收与 Webhook 转发服务。提供中文 Web 控制台、发送方与关键词过滤、鉴权 Header、失败重试、本地去重及可选的转发后删除。

> 项目只用于管理你本人合法持有的 SIM 卡和短信。管理令牌、Webhook 密钥、短信内容与日志不会提交到 GitHub。

## 功能

- 自动绑定 IG830 的 Linux `option` 串口驱动
- 自动发现并使用 `/dev/ttyUSB2`（页面中可修改）
- 中文响应式配置页面
- POST/PUT Webhook 与自定义鉴权 Header
- 发送方白名单、黑名单和关键词规则
- 本地去重，失败时保留短信供下次重试
- 可选“转发成功后删除模块短信”
- systemd 后台运行和开机启动
- 无 Python 第三方依赖

## 支持环境

- Ubuntu/Debian Linux，Python 3.10+
- x86_64 或 arm64
- DJI/Baiwang IG830，通过 USB 直通或直接连接服务器
- UTM、PVE 等虚拟化环境需先把 USB 设备直通给 Linux

## 下载与安装

从 Releases 下载最新的 `ig830-sms-control-*-linux.tar.gz`：

```bash
tar -xzf ig830-sms-control-*-linux.tar.gz
cd ig830-sms-control
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

终端会显示首次登录所需的随机管理令牌。也可在服务器查看：

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

只有 HTTP 2xx 响应才被视为成功。失败的短信不会加入去重记录，下个轮询周期会重试。

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
- 不要把 `admin-token.txt`、`config.json`、`events.log` 上传到公开仓库。
- Webhook 应优先使用 HTTPS，并设置独立的 Bearer Token。
- 首次测试时不要启用“转发成功后删除”，确认稳定后再开启。

## 当前硬件说明

IG830 的不同批次可能使用不同 AT 端口。如果 `/dev/ttyUSB2` 无响应，可在页面改为 `/dev/ttyUSB3` 后重试。项目不会执行永久修改 USB VID/PID 的 `AT+QCFG="usbcfg"` 命令。

## 许可证

MIT
