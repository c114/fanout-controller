#!/usr/bin/env bash
set -e

echo "=== Fanout Proxy Controller 安装脚本 ==="

if [ "$EUID" -ne 0 ]; then
  echo "请以 root 权限运行此脚本 (sudo bash install.sh)"
  exit 1
fi

if ! command -v go &> /dev/null; then
    echo "[+] 正在安装 Go 语言环境..."
    apt-get update -y && apt-get install -y golang-go || yum install -y golang
fi

echo "[+] 正在编译项目 Go 源码..."
go build -o fanout-controller main.go

mkdir -p /usr/local/bin
cp fanout-controller /usr/local/bin/fanout-controller
chmod +x /usr/local/bin/fanout-controller

echo "[+] 配置 Systemd 后台服务..."
cat <<SERVICE > /etc/systemd/system/fanout.service
[Unit]
Description=Fanout Aggregated Proxy Controller
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/fanout-controller -listen 0.0.0.0:1080 -interval 30
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
SERVICE

systemctl daemon-reload
systemctl enable fanout
systemctl restart fanout

echo "=========================================="
echo "[✓] 安装完成！"
echo "服务状态查看: systemctl status fanout"
echo "查看运行日志: journalctl -u fanout -f -n 50"
echo "SOCKS5 本地代理端口: 1080"
echo "=========================================="