#!/bin/bash

sudo apt update 
sudo apt install  xfce4 xfce4-goodies fonts-wqy-zenhei konsole xserver-xephyr  x11vnc  python3-venv git -y 

sudo x11vnc -storepasswd /etc/x11vnc.pass
loginctl enable-linger
mkdir -p ~/.config/systemd/user

sudo cat > x11vnc.service << EOF
[Unit]
Description=Start x11vnc at boot for display manager
After=multi-user.target display-manager.service

[Service]
Type=simple
ExecStart=/usr/bin/x11vnc -display :0 -auth guess -forever -loop -noxdamage -repeat -rfbauth /etc/x11vnc.pass -rfbport 5900 -listen 127.0.0.1 -shared
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
sudo mv x11vnc.service /etc/systemd/system/x11vnc.service
sudo systemctl daemon-reload
sudo systemctl enable --now x11vnc

git clone https://github.com/novnc/noVNC.git ~/noVNC
cd ~/noVNC
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -sha256 -days 365000 -nodes -subj "/CN=localhost"
sudo cat > ~/.config/systemd/user/novnc.service << EOF
[Unit]
Description=noVNC Web Proxy User Service
After=x11vnc.service

[Service]
Type=simple
ExecStart=%h/noVNC/utils/novnc_proxy --cert %h/noVNC/cert.pem --key %h/noVNC/key.pem --vnc localhost:5900 --listen 6080
Restart=on-failure

[Install]
WantedBy=default.target
EOF
systemctl --user daemon-reload
systemctl --user enable novnc --now 


exit 0
