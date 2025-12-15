#!/bin/bash 

cd ~
FRP_LATEST_VERSION=$(curl -s https://api.github.com/repos/fatedier/frp/releases/latest | grep -Po '"tag_name": "\K([^"]*)')
FRP_ARCHIVE_FILE_NAME="frp_$(python3 -c "print(\"$FRP_LATEST_VERSION\".lower().replace('v',''))")_linux_amd64.tar.gz"
wget https://github.com/fatedier/frp/releases/download/$FRP_LATEST_VERSION/$FRP_ARCHIVE_FILE_NAME
tar -zxvf $FRP_ARCHIVE_FILE_NAME
mv $(python3 -c "print(\"$FRP_ARCHIVE_FILE_NAME\".replace('.tar.gz', ''))") frp
rm $FRP_ARCHIVE_FILE_NAME
FRP_PORT=""
read -p "Choose a port for FRP(server), default by random: "  FRP_PORT
if [ -z "$FRP_PORT" ]; then
    FRP_PORT=$(shuf -i 10240-65535 -n 1)
    echo "Empty port entered. Chosen $FRP_PORT as FRP server port"
fi
FRP_TOKEN=""
read -p "Choose a STRONG authorization token: " FRP_TOKEN
if ! [ ${#FRP_TOKEN} -gt 20 ]; then 
    FRP_TOKEN=$(tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 32)
    echo "Token too weak. Token generated = $FRP_TOKEN"
    sleep 1
fi
cd frp
read -p "Now going to cert.conf to configure openssl cert generation. Press Enter to continue" FRP_TOKEN
cat > cert.conf << EOF
[req]
default_bits = 2048
prompt = no
default_md = sha256
distinguished_name = dn
req_extensions = v3_req

[dn]
CN = *.example.com

[v3_req]
subjectAltName = @alt_names
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment

[alt_names]
DNS.1 = *.example.com
DNS.2 = example.com
DNS.3 = localhost
DNS.4 = 192.168.1.1
IP.1 = 127.0.0.1
EOF
vim cert.conf
openssl genrsa -out cert.key 2048
openssl req -new -x509 -key cert.key -out cert.crt -days 365000 -config cert.conf -extensions v3_req
openssl x509 -in cert.crt -text -noout
cat > frps.toml << EOF
bindPort = $FRP_PORT
auth.method = "token"
auth.token = "$FRP_TOKEN"

[transport.tls]
certFile = "cert.crt"
keyFile  = "cert.key"
EOF
cat > frps.service << EOF 
[Unit]
Description=frp for server Service
After=network.target

[Service]
User=$USER
ExecStart=$HOME/frp/frps -c $HOME/frp/frps.toml
Restart=always
RestartSec=15
WorkingDirectory=$HOME/frp

[Install]
WantedBy=multi-user.target
EOF
sudo mv frps.service /etc/systemd/system/frps.service
sudo systemctl daemon-reload && sudo systemctl enable --now frps 
cat cert.crt
FRP_TOKEN=""
echo "FRP installed. Displaying systemctl service status. Hit q to exit"
sleep 2
sudo systemctl status frps 


cd ~

exit 0