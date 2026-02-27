#!/bin/bash
cd ~
mkdir -p ~/vaultwarden
sudo apt install certbot nginx python3-certbot-nginx -y
VAULTWARDEN_ADMIN_TOKEN=$(openssl rand -base64 48)
echo "VaultWarden admin token: $VAULTWARDEN_ADMIN_TOKEN"
read -p "Choose a port for VaultWarden, default by random: "  VAULTWARDEN_PORT
if [ -z "$VAULTWARDEN_PORT" ]; then
    VAULTWARDEN_PORT=$(shuf -i 10240-65535 -n 1)
    echo "Empty port entered. Chosen $VAULTWARDEN_PORT as VaultWarden server port"
    sleep .3
fi
read -p "What is the hostname for VaultWarden (such as vault.example.top): "  VAULTWARDEN_DOMAIN
read -p "If you want to deploy VaultWarden with a base url (such as \`/vault\`), enter here: "  VAULTWARDEN_URLPATH
if [ -z "$VAULTWARDEN_URLPATH" ]; then
    VAULTWARDEN_URLPATH="/"
fi
read -p "Do you want to apply for a certificate for the domain using certbot now? (Enter Y)" OPTION
if [ "$OPTION" = "Y" ]; then
    sudo certbot certonly -d $VAULTWARDEN_DOMAIN
fi
sudo docker run -d \
    --name vaultwarden \
    -p 127.0.0.1:$VAULTWARDEN_PORT:80 \
    -v ~/vaultwarden:/data \
    -e DOMAIN="https://$VAULTWARDEN_DOMAIN$VAULTWARDEN_URLPATH" \
    -e ADMIN_TOKEN="$VAULTWARDEN_ADMIN_TOKEN" \
    --restart unless-stopped \
    vaultwarden/server:latest
sleep 2
sudo docker logs --tail 6 vaultwarden


VAULTWARDEN_AUTHELIA_FLAG="#"
read -p "Do you want to enable authelia for the VaultWarden admin panel? (Enter Y)" OPTION
if [ "$OPTION" = "Y" ]; then
    VAULTWARDEN_AUTHELIA_FLAG=""
    read -p "What is the domain of authelia auth portal?" AUTHELIA_DOMAIN
fi

cat > $VAULTWARDEN_DOMAIN << EOF
# /etc/nginx/sites-available/$VAULTWARDEN_DOMAIN
server {
    listen 80;
    server_name $VAULTWARDEN_DOMAIN;
    return 301 https://\$server_name\$request_uri;
}

server {
    listen 443 ssl;
    server_name $VAULTWARDEN_DOMAIN;
    
    client_max_body_size 2G;

    ssl_certificate /etc/letsencrypt/live/$VAULTWARDEN_DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$VAULTWARDEN_DOMAIN/privkey.pem;
    
    $VAULTWARDEN_AUTHELIA_FLAG include /etc/nginx/snippets/authelia.conf;

    location $VAULTWARDEN_URLPATH {
        proxy_pass http://127.0.0.1:$VAULTWARDEN_PORT;
        proxy_set_header Host \$http_host;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;

        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_buffering off;
    }
    location $VAULTWARDEN_URLPATH/admin {
        $VAULTWARDEN_AUTHELIA_FLAG auth_request /authelia-verify;  # Call the internal authelia authentication endpoint
        ## If the verification returns a 401/403 error, redirect to the Authelia login page.
        $VAULTWARDEN_AUTHELIA_FLAG error_page 403 =302 https://$AUTHELIA_DOMAIN/403?button=Logout&rd=https://$AUTHELIA_DOMAIN/logout?rd=https://$AUTHELIA_DOMAIN/?rd=\$scheme://\$http_host\$request_uri;
        $VAULTWARDEN_AUTHELIA_FLAG error_page 401 =302 https://$AUTHELIA_DOMAIN/?rd=\$scheme://\$http_host\$request_uri;

        ## After successful auth, set the user header info and proxy to the actual backend app
        $VAULTWARDEN_AUTHELIA_FLAG auth_request_set \$user \$upstream_http_remote_user;
        $VAULTWARDEN_AUTHELIA_FLAG auth_request_set \$groups \$upstream_http_remote_groups;
        $VAULTWARDEN_AUTHELIA_FLAG proxy_set_header Remote-User \$user;
        $VAULTWARDEN_AUTHELIA_FLAG proxy_set_header Remote-Groups \$groups;

        proxy_pass http://127.0.0.1:$VAULTWARDEN_PORT;
        proxy_set_header Host \$http_host;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;

        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_buffering off;
    }
}
EOF
read -p "A nginx config is created at $HOME/$VAULTWARDEN_DOMAIN. Do you want move to nginx and enable? (Enter Y)" OPTION
if [ "$OPTION" = "Y" ]; then
    sudo mv $VAULTWARDEN_DOMAIN /etc/nginx/sites-available/$VAULTWARDEN_DOMAIN
    sudo ln -s /etc/nginx/sites-available/$VAULTWARDEN_DOMAIN /etc/nginx/sites-enabled
    sudo nginx -t
done
echo "VaultWarden admin token is: $VAULTWARDEN_ADMIN_TOKEN, go to $VAULTWARDEN_DOMAIN$VAULTWARDEN_URLPATH/admin to set up."
exit 0
