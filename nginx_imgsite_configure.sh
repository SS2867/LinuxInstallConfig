#!/bin/bash

read -p "Do you want to configure nginx imaging sites? (Enter Y)" OPTION
if [ "$OPTION" = "Y" ]; then
    sudo apt install certbot nginx python3-certbot-nginx -y
    sudo mkdir -p /etc/nginx/sites-available/imgsites/
    read -p "Which port does authelia listen to (if authelia is not installed, just hit ENTER): " AUTHELIA_PORT
    if ! [ -z "$AUTHELIA_PORT" ]; then
        read -p "What is the authelia auth domain (such as authelia.example.top): " AUTHELIA_DOMAIN
    fi
fi
while [ "$OPTION" = "Y" ]; do
    read -p "What is the domain client will be visiting: " NGINX_SERVICE_DOMAIN
    read -p "What is the target website's hostname to be mirrored: " NGINX_SERVICE_SITE_HOSTNAME
    NGINX_SERVICE_AUTHELIA_FLAG="#"
    if ! [ -z "$AUTHELIA_PORT" ]; then
        read -p "Is authelia auth required for this service? (Enter Y) " OPTION
        if [ "$OPTION" = "Y" ]; then
            NGINX_SERVICE_AUTHELIA_FLAG=""
            echo "(You need to change corresponding access_control in authelia config)" && sleep 1
        fi
    fi
    NGINX_SERVICE_REMOVE_CORS_CSP_FLAG="#"
    #echo "Do you want to forcely remove CORS (Cross-Origin Resource Sharing) constraint and "
    #read -p "CSP (Content Security Policy) for this service? (Enter Y) " OPTION
    OPTION="Y"
    if [ "$OPTION" = "Y" ]; then
        NGINX_SERVICE_REMOVE_CORS_CSP_FLAG=""
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

    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl;
    server_name $NGINX_SERVICE_DOMAIN;

    ssl_certificate /etc/letsencrypt/live/$NGINX_SERVICE_DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$NGINX_SERVICE_DOMAIN/privkey.pem;

    $NGINX_SERVICE_AUTHELIA_FLAG include /etc/nginx/snippets/authelia.conf;

    location @error {
        internal;  
        if (\$authelia-failed = "403") {
            return 302 https://$AUTHELIA_DOMAIN/logout?rd=https://$AUTHELIA_DOMAIN/?rd=\$scheme://\$http_host\$request_uri;
        }
        if (\$authelia-failed = "401") {
            return 302 https://$AUTHELIA_DOMAIN/?rd=\$scheme://\$http_host\$request_uri;
        }
        if (\$status = 401) {return 401; }
        if (\$status = 403) {return 403; }
    }

    location / {
        
        
        $NGINX_SERVICE_AUTHELIA_FLAG auth_request /authelia-verify;  # Call the internal authelia authentication endpoint
        ## If the verification returns a 401/403 error, redirect to the Authelia login page.
        $NGINX_SERVICE_AUTHELIA_FLAG error_page 403 401 =@error;

        ## After successful auth, set the user header info and proxy to the actual backend app
        $NGINX_SERVICE_AUTHELIA_FLAG auth_request_set \$user \$upstream_http_remote_user;
        $NGINX_SERVICE_AUTHELIA_FLAG auth_request_set \$groups \$upstream_http_remote_groups;
        $NGINX_SERVICE_AUTHELIA_FLAG proxy_set_header Remote-User \$user;
        $NGINX_SERVICE_AUTHELIA_FLAG proxy_set_header Remote-Groups \$groups;

        proxy_pass https://$NGINX_SERVICE_SITE_HOSTNAME; 
    	proxy_set_header Host $NGINX_SERVICE_SITE_HOSTNAME;
        proxy_set_header Referer "";
    	proxy_set_header X-Real-IP localhost;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme; #https;  # 告知后端使用了 HTTPS
        client_max_body_size 20G;
        #proxy_set_header Origin \$scheme://\$host;    # 移除端口号
        #proxy_cookie_path / "/; Max-Age=3600; Path=/; Secure; HttpOnly";

        # remove CORS (Cross-Origin Resource Sharing) constraint and CSP (Content Security Policy)
        $NGINX_SERVICE_REMOVE_CORS_CSP_FLAG add_header 'Access-Control-Allow-Origin' '*' always;
        $NGINX_SERVICE_REMOVE_CORS_CSP_FLAG add_header 'Access-Control-Allow-Methods' 'GET, POST, PUT, DELETE, OPTIONS' always;
        $NGINX_SERVICE_REMOVE_CORS_CSP_FLAG add_header 'Access-Control-Allow-Headers' 'DNT,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Range,Authorization' always;
        $NGINX_SERVICE_REMOVE_CORS_CSP_FLAG add_header 'Access-Control-Expose-Headers' 'Content-Length,Content-Range' always;
        $NGINX_SERVICE_REMOVE_CORS_CSP_FLAG if (\$request_method = OPTIONS) {
        $NGINX_SERVICE_REMOVE_CORS_CSP_FLAG    add_header 'Access-Control-Allow-Origin' '*' always;
        $NGINX_SERVICE_REMOVE_CORS_CSP_FLAG    add_header 'Access-Control-Allow-Methods' 'GET, POST, PUT, DELETE, OPTIONS' always;
        $NGINX_SERVICE_REMOVE_CORS_CSP_FLAG    add_header 'Access-Control-Allow-Headers' 'DNT,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Range,Authorization' always;
        $NGINX_SERVICE_REMOVE_CORS_CSP_FLAG    add_header 'Access-Control-Max-Age' 1728000; # 预检缓存 20 天
        $NGINX_SERVICE_REMOVE_CORS_CSP_FLAG    add_header 'Content-Type' 'text/plain; charset=utf-8' always;
        $NGINX_SERVICE_REMOVE_CORS_CSP_FLAG    add_header 'Content-Length' 0 always;
        $NGINX_SERVICE_REMOVE_CORS_CSP_FLAG    return 204;
        $NGINX_SERVICE_REMOVE_CORS_CSP_FLAG }
        # Content Security Policy (CSP header)
        $NGINX_SERVICE_REMOVE_CORS_CSP_FLAG proxy_hide_header Content-Security-Policy;
        $NGINX_SERVICE_REMOVE_CORS_CSP_FLAG add_header Content-Security-Policy "";


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
    sudo mv $NGINX_SERVICE_DOMAIN /etc/nginx/sites-available/imgsites/$NGINX_SERVICE_DOMAIN
    read -p "Is this site ok for enable now? (Enter Y) " OPTION
    if [ "$OPTION" = "Y" ]; then
        sudo ln -s /etc/nginx/sites-available/imgsites/$NGINX_SERVICE_DOMAIN /etc/nginx/sites-enabled
    fi
    
    sudo nginx -t
    read -p "Do you want to configure another site? (Enter Y) " OPTION
done
echo "The following sites images are configured at /etc/nginx/sites-available/imgsites: "
ls /etc/nginx/sites-available/imgsites
echo "Among them, below are enabled at /etc/nginx/sites-enabled: "
ls /etc/nginx/sites-enabled
read -p "Press ENTER to continue..." OPTION
sudo nginx -t
read -p "Is nginx configuration ok? (Enter Y)" OPTION
if [ "$OPTION" = "Y" ]; then
    sudo systemctl restart nginx && sudo systemctl status nginx  && sleep 1 
fi


exit 0
