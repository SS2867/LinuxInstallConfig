#!/bin/bash

read -p "Do you want to configure nginx sites? (Enter Y)" OPTION
if [ "$OPTION" = "Y" ]; then
    sudo apt install certbot nginx python3-certbot-nginx apache2-utils -y
    read -p "Which port does authelia listen to (if authelia is not installed, just hit ENTER): " AUTHELIA_PORT
    if ! [ -z "$AUTHELIA_PORT" ]; then
        read -p "What is the authelia auth domain (such as authelia.example.top): " AUTHELIA_HOST_DOMAIN
        read -p "What is the authelia base domain (such as example.top): " AUTHELIA_BASE_DOMAIN
        read -p "What is the authelia auth path (such as authelia, don't end with '/'): /" AUTHELIA_PATH
        AUTHELIA_PATH="/$AUTHELIA_PATH"; if ! [[ "$AUTHELIA_PATH" = */ ]]; then AUTHELIA_PATH="$AUTHELIA_PATH/"; fi
    else
        read -p "Setup a global nginx htpasswd basic auth file? (Enter Y)" OPTION
        sudo touch /etc/nginx/.htpasswd
        while [ "$OPTION" = "Y" ]; do 
            read -p "username: " NGINX_AUTH_USERNAME
            sudo htpasswd -B /etc/nginx/.htpasswd $NGINX_AUTH_USERNAME
            read -p "Add another user? (Enter Y)" OPTION
        done
        OPTION="Y"
    fi

fi
while [ "$OPTION" = "Y" ]; do
    read -p "What is the target server service domain: " NGINX_SERVICE_DOMAIN
    if [ "$NGINX_SERVICE_DOMAIN" = "default" ]; then NGINX_DEFAULT_FLAG="default_server"; else NGINX_DEFAULT_FLAG=""; fi
    NGINX_SERVICE_AUTHELIA_FLAG="#"; NGINX_SERVICE_BASICAUTH_FLAG="#"; 
    if ! [ -z "$AUTHELIA_PORT" ]; then
        read -p "Set up an authelia reverse proxy under this domain? (Enter Y) " OPTION
        if [ "$OPTION" = "Y" ]; then 
            AUTHELIA_DOMAIN="\$http_host"
            AUTHELIA_SERVICE_NGINX_CONFIG="
    location $AUTHELIA_PATH {
        proxy_pass http://127.0.0.1:$AUTHELIA_PORT;
        proxy_set_header Host \$http_host;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
    location ${AUTHELIA_PATH}403 {
        root /etc/nginx/sites-available/AccessDenied;
        try_files /AccessDenied.html /AccessDenied.html;
        sub_filter 'example.com google.com trusted.site' '$AUTHELIA_BASE_DOMAIN';
        sub_filter_once off; 
        #sub_filter_types text/html;
	    autoindex off;
    }"
        else AUTHELIA_DOMAIN="$AUTHELIA_HOST_DOMAIN"; fi
    fi
    NGINX_SERVICE_CERT_PATH=/
    echo "Do you want to request a certificate for service domain using letsencrypt certbot now? (Enter Y)"
    echo "Or do you want to generate a self-signed certificate for service domain? (Enter S)"
    read -p "The config assumes a valid cert for $NGINX_SERVICE_DOMAIN exists regardless. (Y/S/else): " OPTION
    if [ "$OPTION" = "Y" ]; then sudo certbot certonly -d $NGINX_SERVICE_DOMAIN; NGINX_SERVICE_CERT_PATH=/etc/letsencrypt/live/$NGINX_SERVICE_DOMAIN; fi
    if [ "$OPTION" = "S" ]; then 
        NGINX_SERVICE_CERT_PATH=/etc/nginx/sites-available/certs/$NGINX_SERVICE_DOMAIN; sudo mkdir -p $NGINX_SERVICE_CERT_PATH
        sudo openssl req -x509 -newkey rsa:4096 -keyout $NGINX_SERVICE_CERT_PATH/privkey.pem -out $NGINX_SERVICE_CERT_PATH/fullchain.pem -sha256 -days 365000 -nodes -subj "/CN=localhost"; 
    fi

    read -p "What is the backend the target service listen to (such as http://localhost:9876, https://localhost:12345/): " NGINX_SERVICE_BACKEND
    read -p "What is the location matching strategy (such as \`/\` \`= /404\` \`^~ /login/\`): " NGINX_SERVICE_LOCATION
    if ! [ -z "$AUTHELIA_PORT" ]; then
        read -p "Is authelia auth required for this service? (Enter Y) " OPTION
        if [ "$OPTION" = "Y" ]; then NGINX_SERVICE_AUTHELIA_FLAG=""; fi
    fi
    if [ "$NGINX_SERVICE_AUTHELIA_FLAG" = "#" ]; then
        read -p "Is basic auth required for this service? (Enter Y) " OPTION
        if [ "$OPTION" = "Y" ]; then NGINX_SERVICE_BASICAUTH_FLAG=""; fi
    fi
    NGINX_SERVICE_REMOVE_CORS_CSP_CONFIG="
        # remove CORS (Cross-Origin Resource Sharing) constraint and CSP (Content Security Policy)
        add_header 'Access-Control-Allow-Origin' '*' always;
        add_header 'Access-Control-Allow-Methods' 'GET, POST, PUT, DELETE, OPTIONS' always;
        add_header 'Access-Control-Allow-Headers' 'DNT,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Range,Authorization' always;
        add_header 'Access-Control-Expose-Headers' 'Content-Length,Content-Range' always;
        if (\$request_method = OPTIONS) {
            add_header 'Access-Control-Allow-Origin' '*' always;
            add_header 'Access-Control-Allow-Methods' 'GET, POST, PUT, DELETE, OPTIONS' always;
            add_header 'Access-Control-Allow-Headers' 'DNT,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Range,Authorization' always;
            add_header 'Access-Control-Max-Age' 1728000; # 预检缓存 20 天
            add_header 'Content-Type' 'text/plain; charset=utf-8' always;
            add_header 'Content-Length' 0 always;
            return 204;
        }
        # Content Security Policy (CSP header)
        proxy_hide_header Content-Security-Policy;
        add_header Content-Security-Policy '';"
    NGINX_SERVICE_REMOVE_CORS_CSP_FLAG="#"
    NGINX_SERVICE_NO_CORS_CSP_CONTENT=""
    echo "Do you want to forcely remove CORS (Cross-Origin Resource Sharing) constraint and "
    read -p "CSP (Content Security Policy) for this service? (Enter Y) " OPTION
    if [ "$OPTION" = "Y" ]; then
        NGINX_SERVICE_REMOVE_CORS_CSP_FLAG=""
        NGINX_SERVICE_NO_CORS_CSP_CONTENT="$NGINX_SERVICE_REMOVE_CORS_CSP_CONFIG"
    fi
    cat > $NGINX_SERVICE_DOMAIN << EOF
server {
    listen 80 $NGINX_DEFAULT_FLAG;
    server_name $NGINX_SERVICE_DOMAIN;

    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl $NGINX_DEFAULT_FLAG;
    server_name $NGINX_SERVICE_DOMAIN;
    http2 on;

    ssl_certificate $NGINX_SERVICE_CERT_PATH/fullchain.pem;
    ssl_certificate_key $NGINX_SERVICE_CERT_PATH/privkey.pem;

    $NGINX_SERVICE_AUTHELIA_FLAG include /etc/nginx/snippets/authelia.conf;

    $NGINX_SERVICE_AUTHELIA_FLAG location @error {
    $NGINX_SERVICE_AUTHELIA_FLAG    internal;  
    $NGINX_SERVICE_AUTHELIA_FLAG    if (\$authelia-failed = "403") {return 302 https://${AUTHELIA_DOMAIN}${AUTHELIA_PATH}403?button=Logout&rd=https://${AUTHELIA_DOMAIN}${AUTHELIA_PATH}logout?rd=https://${AUTHELIA_DOMAIN}${AUTHELIA_PATH}?rd=\$scheme://\$http_host\$request_uri; }
    $NGINX_SERVICE_AUTHELIA_FLAG    if (\$authelia-failed = "401") {return 302 https://${AUTHELIA_DOMAIN}${AUTHELIA_PATH}/?rd=\$scheme://\$http_host\$request_uri; }
    $NGINX_SERVICE_AUTHELIA_FLAG    if (\$status = 401) {return 401;}
    $NGINX_SERVICE_AUTHELIA_FLAG    if (\$status = 403) {return 403;}
    $NGINX_SERVICE_AUTHELIA_FLAG }
    $AUTHELIA_SERVICE_NGINX_CONFIG

    location $NGINX_SERVICE_LOCATION {
        $NGINX_SERVICE_AUTHELIA_FLAG auth_request /authelia-verify; error_page 403 401 = @error;  # Call the internal authelia auth endpoint
        $NGINX_SERVICE_BASICAUTH_FLAG auth_basic "Please login"; auth_basic_user_file /etc/nginx/.htpasswd ;

        proxy_pass $NGINX_SERVICE_BACKEND; 
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr; #localhost ;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme; #https;  # 告知后端使用了 HTTPS
        client_max_body_size 5G;

        $NGINX_SERVICE_NO_CORS_CSP_CONTENT

        # WebSocket 
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_buffering off;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }

    # static webpage
    #location / {
    #    root /var/www/html;
    #    index index.html;
    #    try_files \$uri \$uri/ =404;
    #}
EOF
    read -p "Enter service port if you want to block direct port access (that bypasses nginx) via iptables in /etc/rc.local: " NGINX_SERVICE_PORT
    if ! [ -z "$NGINX_SERVICE_PORT" ]; then 
        sudo sed -i "/^exit 0$/i \\
iptables -A INPUT ! -i lo -p tcp --dport $NGINX_SERVICE_PORT -j DROP" /etc/rc.local
    fi
    read -p "Add another service/location for this site? (Enter Y) " OPTION
    while [ "$OPTION" = "Y" ]; do
        read -p "What is the backend the target service listen to (such as http://localhost:9876, https://localhost:12345/): " NGINX_SERVICE_BACKEND
        read -p "What is the location matching strategy (such as \`/\` \`= /404\` \`^~ /login/\`): " NGINX_SERVICE_LOCATION
        NGINX_SERVICE_AUTHELIA_FLAG="#"; NGINX_SERVICE_BASICAUTH_FLAG="#";
        if ! [ -z "$AUTHELIA_PORT" ]; then
            read -p "Is authelia auth required for this service? (Enter Y) " OPTION
            if [ "$OPTION" = "Y" ]; then NGINX_SERVICE_AUTHELIA_FLAG=""; fi
        fi
        if [ "$NGINX_SERVICE_AUTHELIA_FLAG" = "#" ]; then
            read -p "Is basic auth required for this service? (Enter Y) " OPTION
            if [ "$OPTION" = "Y" ]; then NGINX_SERVICE_BASICAUTH_FLAG=""; fi
        fi
        NGINX_SERVICE_REMOVE_CORS_CSP_FLAG="#"
        NGINX_SERVICE_NO_CORS_CSP_CONTENT=""
        echo "Do you want to forcely remove CORS (Cross-Origin Resource Sharing) constraint and "
        read -p "CSP (Content Security Policy) for this service? (Enter Y) " OPTION
        if [ "$OPTION" = "Y" ]; then
            NGINX_SERVICE_REMOVE_CORS_CSP_FLAG=""
            NGINX_SERVICE_NO_CORS_CSP_CONTENT="$NGINX_SERVICE_REMOVE_CORS_CSP_CONFIG"
        fi
        cat >> $NGINX_SERVICE_DOMAIN << EOF
    location $NGINX_SERVICE_LOCATION {
        $NGINX_SERVICE_AUTHELIA_FLAG auth_request /authelia-verify; error_page 403 401 = @error;  # Call the internal authelia auth endpoint
        $NGINX_SERVICE_BASICAUTH_FLAG auth_basic "Please login"; auth_basic_user_file /etc/nginx/.htpasswd ;

        proxy_pass $NGINX_SERVICE_BACKEND; 
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr; #localhost ;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme; #https;  # 告知后端使用了 HTTPS
        client_max_body_size 5G;

        $NGINX_SERVICE_NO_CORS_CSP_CONTENT

        # WebSocket 
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_buffering off;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }
EOF
        read -p "Enter service port if you want to block direct port access (that bypasses nginx) via iptables in /etc/rc.local: " NGINX_SERVICE_PORT
        if ! [ -z "$NGINX_SERVICE_PORT" ]; then 
            sudo sed -i "/^exit 0$/i \\
iptables -A INPUT ! -i lo -p tcp --dport $NGINX_SERVICE_PORT -j DROP" /etc/rc.local
        fi
        read -p "Add another service/location for this site? (Enter Y) " OPTION
    done
    cat >> $NGINX_SERVICE_DOMAIN << EOF
    
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
