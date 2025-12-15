#!/bin/bash

read -p "Do you want to configure nginx sites? (Enter Y)" OPTION
if [ "$OPTION" = "Y" ]; then
    sudo apt install certbot nginx python3-certbot-nginx -y
    read -p "Which port does authelia listen to (if authelia is not installed, just hit ENTER): " AUTHELIA_PORT
    if ! [ -z "$AUTHELIA_PORT" ]; then
        read -p "What is the authelia auth domain (such as authelia.example.top): " AUTHELIA_DOMAIN
    fi
fi
while [ "$OPTION" = "Y" ]; do
    read -p "What is the target server service domain: " NGINX_SERVICE_DOMAIN
    read -p "What is the port the target service listen to: " NGINX_SERVICE_PORT
    NGINX_SERVICE_AUTHELIA_FLAG="#"
    if ! [ -z "$AUTHELIA_PORT" ]; then
        read -p "Is authelia auth required for this service? (Enter Y) " OPTION
        if [ "$OPTION" = "Y" ]; then
            NGINX_SERVICE_AUTHELIA_FLAG=""
            echo "(You need to change corresponding access_control in authelia config)" && sleep 1
        fi
    fi
    echo "Do you want to request a certificate for service domain using letsencrypt certbot now? (Enter Y)"
    read -p "The config assumes a valid cert for $NGINX_SERVICE_DOMAIN exists regardless. (Y): " OPTION
    if [ "$OPTION" = "Y" ]; then
        sudo certbot certonly -d $NGINX_SERVICE_DOMAIN
    fi
    cat > $NGINX_SERVICE_DOMAIN << EOF
server {
    listen 80;
    server_name $NGINX_SERVICE_DOMAIN;

    return 301 https://\$host:8443\$request_uri;
}

server {
    listen 443 ssl;
    server_name $NGINX_SERVICE_DOMAIN;

    ssl_certificate /etc/letsencrypt/live/$NGINX_SERVICE_DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$NGINX_SERVICE_DOMAIN/privkey.pem;

    $NGINX_SERVICE_AUTHELIA_FLAG include /etc/nginx/snippets/authelia.conf;

    location / {
        
        
        $NGINX_SERVICE_AUTHELIA_FLAG auth_request /authelia-verify;  # Call the internal authelia authentication endpoint
        ## If the verification returns a 401/403 error, redirect to the Authelia login page.
        $NGINX_SERVICE_AUTHELIA_FLAG error_page 401 403 =302 https://$AUTHELIA_DOMAIN/?rd=\$scheme://\$http_host\$request_uri;

        ## After successful auth, set the user header info and proxy to the actual backend app
        $NGINX_SERVICE_AUTHELIA_FLAG auth_request_set \$user \$upstream_http_remote_user;
        $NGINX_SERVICE_AUTHELIA_FLAG auth_request_set \$groups \$upstream_http_remote_groups;
        $NGINX_SERVICE_AUTHELIA_FLAG proxy_set_header Remote-User \$user;
        $NGINX_SERVICE_AUTHELIA_FLAG proxy_set_header Remote-Groups \$groups;

        proxy_pass http://localhost:$AUTHELIA_PORT; 
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr; #localhost ;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme; #https;  # 告知后端使用了 HTTPS
        client_max_body_size 20G;
        #proxy_set_header Origin \$scheme://\$host;    # 移除端口号
        #proxy_cookie_path / "/; Max-Age=3600; Path=/; Secure; HttpOnly";

        # WebSocket 支持
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_buffering off;
    }

    # static webpage
    #location / {
    #    root /var/www/html;
    #    index index.html;
    #    try_files \$uri \$uri/ =404;
    #}
}
EOF
    sudo mv $NGINX_SERVICE_DOMAIN /etc/nginx/sites-available/$NGINX_SERVICE_DOMAIN
    read -p "Is this site ok for enable now? (Enter Y) " OPTION
    if [ "$OPTION" = "Y" ]; then
        sudo ln -s /etc/nginx/sites-available/$NGINX_SERVICE_DOMAIN /etc/nginx/sites-enabled
    fi
    sudo nginx -t
    read -p "Do you want to configure another site? (Enter Y) " OPTION
done
echo "The following sites are configured at /etc/nginx/sites-available: "
ls /etc/nginx/sites-available
echo "Among them, below are enabled at /etc/nginx/sites-enabled: "
ls /etc/nginx/sites-enabled
read -p "Press ENTER to continue..." OPTION
sudo nginx -t
read -p "Is nginx configuration ok? (Enter Y)" OPTION
if [ "$OPTION" = "Y" ]; then
    sudo systemctl restart nginx && sudo systemctl status nginx  && sleep 1 
fi


exit 0
