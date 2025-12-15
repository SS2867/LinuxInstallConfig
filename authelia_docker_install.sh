#!/bin/bash
cd ~
mkdir -p ~/authelia/config
sudo apt install certbot nginx python3-certbot-nginx -y
read -p "Create your username: " AUTHELIA_USERNAME
echo "Create your user password"
sudo docker run --rm -it authelia/authelia:latest authelia crypto hash generate argon2
echo "What is the hash value displayed above? (\$argon2id\$v=...UvQ)"
read -p "(Just copy, no need for char escape)" AUTHELIA_PASSWORD_HASH
AUTHELIA_PASSWORD_HASH=$(python3 -c "print(\"$AUTHELIA_PASSWORD_HASH\".replace(\"Digest\", \"\").replace(\":\", \"\").replace(\" \", \"\"))")
sudo cat > ~/authelia/config/users_database.yml << EOF
# authelia/users_database.yml
users:
  $AUTHELIA_USERNAME:
    displayname: "$AUTHELIA_USERNAME"
    password: "$AUTHELIA_PASSWORD_HASH"
    email: "juser@example.com"
    groups:
      - admins
EOF
cat ~/authelia/config/users_database.yml
read -p "Choose a port for authelia, default by random: "  AUTHELIA_PORT
if [ -z "$AUTHELIA_PORT" ]; then
    AUTHELIA_PORT=$(shuf -i 10240-65535 -n 1)
    echo "Empty port entered. Chosen $AUTHELIA_PORT as authelia server port"
    sleep .3
fi
read -p "What is the domain of authelia auth portal (such as authelia.example.top): "  AUTHELIA_DOMAIN
sudo certbot certonly -d $AUTHELIA_DOMAIN
cat > ~/authelia/config/configuration.yml << EOF
# authelia/config/configuration.yml

##    - the default location of this file is assumed to be configuration.yml unless otherwise noted
##    - when using docker the container expects this by default to be at /config/configuration.yml
##    - the default location where this file is loaded from can be overridden with the X_AUTHELIA_CONFIG env var

## Cert dir specifies where Authelia will load trusted cert (public portion) from in addition to sys cert store
## They should be in base64 format, and have one of the following extensions: *.cer, *.crt, *.pem.
# certificates_directory: '/config/certificates/'

theme: 'light'  ## The theme to display: light, dark, grey, auto.

## default 2FA method for new users and for when a user with preferred method configured disabled. 
default_2fa_method: 'totp'    ## Options are totp, webauthn, mobile_push. Must be a method that is enabled.

## Server Configuration
server:
  ## The address for the Main server to listen on in the address common syntax.
  ## Formats:  [<scheme>://]<hostname>[:<port>][/<path>]    [<scheme>://][hostname]:<port>[/<path>]
  ## Scheme must be {tcp,tcp4,tcp6,unix,fd}. Default by unix if addr is absolute path else tcp. default port 9091.
  ## If the path is specified this configures the router to handle both the / path and the configured path.
  address: 'tcp://:$AUTHELIA_PORT/'

  ## Set the path on disk to Authelia assets. Useful to allow overriding of specific static assets.
  # asset_path: '/config/assets/'

  ## Disables writing the health check vars to /app/.healthcheck.env which makes healthcheck.sh return exit code 0.
  ## This is disabled by default if either /app/.healthcheck.env or /app/healthcheck.sh do not exist.
  # disable_healthcheck: false

  
## Log Configuration
log:
  level: 'info'   ## Level of verbosity for logs: info, debug, trace.
  format: 'text'    ## Format the logs are written as: json, text.
  # file_path: '/config/authelia.log'        ## File path where the logs will be written. to stdout if not set.
  # keep_stdout: false           ## Whether to also log to stdout when a log_file_path is defined

## Telemetry Configuration
# telemetry:
  # metrics:
    # enabled: false

    ## The address for the Metrics server to listen on in the address common syntax. default port is '9959'.
    # address: 'tcp://:9959/metrics'   ## If the path is not specified it defaults to /metrics.

    # buffers:                   ## Metrics Server Buffers configuration.
      # read: 4096        
      # write: 4096
    # timeouts:           ## Metrics Server Timeouts configuration.
      # read: '6 seconds'
      # write: '6 seconds'
      # idle: '30 seconds'

## TOTP Configuration
totp:
  disable: false
  issuer: 'test.example.top' 
  # algorithm: 'SHA1'         ## https://www.authelia.com/c/totp#algorithm
  digits: 8   ## Must be 6 or 8. Change only affects new TOTP seeds. https://www.authelia.com/c/totp#digits
  # period: 30
  skew: 2   ## allowed epoch deviations 
  # secret_size: 32         ## Default is 32 and is sufficient in most use cases, minimum is 20.
  # allowed_algorithms:      ## The allowed algorithms for a user to pick from.
  # - 'SHA1' 
  # allowed_digits:     ## The allowed digits for a user to pick from.
  # - 6
 # allowed_periods:       ## The allowed periods for a user to pick from.
  # - 30
  # disable_reuse_security_policy: false    ## enable = prevents replays of one-time password code values

## WebAuthn Configuration
# webauthn:
  # disable: false
  # enable_passkey_login: false
  # display_name: 'Authelia'

  ## Conveyance preference controls if we collect the attestation statement including the AAGUID from the device.
  # attestation_conveyance_preference: 'indirect'   ## Options are none, indirect, direct.
  # timeout: '60 seconds'
  
  # filtering:
    # prohibit_backup_eligibility: false 
    # permitted_aaguids: []   ## Permitted AAGUID's. If configured specifically only allows the listed AAGUID's.
    # prohibited_aaguids: []   ## If configured prohibits the use of specific AAGUID's

  ## Selection Criteria controls the preferences for registration.
  # selection_criteria:
    ## The attachment preference. 'cross-platform' for dedicated authenticators, or 'platform' for embedded authrs
    # attachment: 'cross-platform' 
    # discoverability: 'discouraged'  ## discoverability preference. 'discouraged', 'preferred', or 'required'.
    ## User verification controls if the user must make a gesture or action to confirm they are present.
    # user_verification: 'preferred'      ## Options are required, preferred, discouraged.

  ## Metadata Service validation via MDS3.
  # metadata:
    # enabled: false        ## Enable the metadata fetch behaviour. 
    # cache_policy: 'strict'      ## Configure the Cache Policy for the Metadata Service.
    ## Enable Validation of Trust Anchor. Generally should be enabled if using the metadata. It ensures the 
    ## attestation cert presented by the authr is valid against the MDS3 cert that issued the attestation cert.
    # validate_trust_anchor: true

    ## Enable Entry Validation. This ensures the MDS3 contains the metadata entry. If not enabled attestation cert
    ## which are not formally registered will be skipped. This may potentially exclude some virtual authenticators.
    # validate_entry: true

    ## Enabling this allows attestation certificates with a zero AAGUID to pass validation. 
    # validate_entry_permit_zero_aaguid: false  ## important if use non-conformant authenticators like Apple ID.
    
    # validate_status: true  ## Enable Validation of the Authenticator Status.

    ## List of statuses which are considered permitted when validating an authr's metadata. Generally recommended
    ## that this is not configured as any other status the authenticator's metadata has will result in an
    # validate_status_permitted: ~     ## error. This option is ineffectual if validate_status is false.

    ## List of statuses that should be prohibited when validating an authenticator's metadata. Generally it is
    ## recommended that this is not configured as there are safe defaults. This option is ineffectual if 
    # validate_status_prohibited: ~      ## validate_status is false, or validate_status_permitted has values.

## Duo Push API Configuration
# duo_api:
  # disable: false
  # hostname: 'api-123456789.example.com'
  # integration_key: 'ABCDEF'
  # secret_key: '1234567890abcdefghifjkl'   ## can also be set using a secret: https://www.authelia.com/c/secrets
  # enable_self_enrollment: false

## Identity Validation Configuration (This configuration tunes the identity validation flows.)
identity_validation:
  reset_password:
    # jwt_lifespan: '5 minutes'  ## Allowed time before JWT is generated and when used in duration common syntax. 
    # jwt_algorithm: 'HS256'   ## The algorithm used for the Reset Password JWT. 
    jwt_secret: '$(head -c 32 /dev/urandom | base64 | tr -d '\n=')'      ## The secret key used to sign and verify the JWT.
  
  # elevated_session:     ## Elevated Session flows. Adjusts the flow which require elevated sessions
    # code_lifespan: '5 minutes'    ## Maximum allowed lifetime after the One-Time Code is generated
    # elevation_lifespan: '10 minutes' 
    # characters: 8
    # require_second_factor: false   ## In addition to OTP, requires a 2FA. 
    # skip_second_factor: false  ## Skips the elevation OTP requirement if the user has performed 2FA.

## Definitions  (used in other areas as reference points to reduce duplication.)
# definitions:
  # user_attributes:   ## The user attribute definitions.
    # definition_name:    ## The name of the definition.
      # expression: ''       ## The common expression language expression for this definition.
  # network:           ## The network definitions.
    # internal:        ## The name of the definition followed by the list of CIDR network addr in this definition.
      # - '10.10.0.0/16'
      # - '172.16.0.0/12'
      # - '192.168.2.0/24'
    # VPN:
      # - '10.9.0.0/16'

## Authentication Backend Provider Configuration
## Used for verifying user passwords and retrieve info such as email address and groups users belong to.
## The available providers are: file, ldap. You must use only one of these providers.
authentication_backend:
  # password_change:
    # disable: false
  password_reset:
    disable: true
    # custom_url: '' ## Ext reset password url that redirects user to ext reset portal. This disables the int reset.

  ## Time to wait before we refresh data from the auth backend in the duration common syntax. To disable, set to
  ## 'disable', this will slightly reduce security. Because for Authelia, users always belong to groups they belonged 
## to at login even if they have been removed from them in LDAP. To force update on every request you can set 
## this to '0' or 'always'. Refresh Interval docs: https://www.authelia.com/c/1fa#refresh-interval
  # refresh_interval: '5 minutes'

  ##
  ## LDAP (Authentication Provider)
  ## ………………..
 


  ## File (Authentication Provider)
  ## highly recommend to leave default values. Read before change: https://www.authelia.com/r/passwords#tuning
  ## Important: Kubernetes (or HA) users must read https://www.authelia.com/t/statelessness
  file:
    path: '/config/users_database.yml'
    watch: false
    search:
      email: false
      case_insensitive: false
    password:
      algorithm: 'argon2'
      argon2:
        variant: 'argon2id'
        iterations: 3
        memory: 65536
        parallelism: 4
        key_length: 32
        salt_length: 16
      scrypt:
        variant: 'scrypt'
        iterations: 16
        block_size: 8
        parallelism: 1
        key_length: 32
        salt_length: 16
      pbkdf2:
        variant: 'sha512'
        iterations: 310000
        salt_length: 16
      sha2crypt:
        variant: 'sha512'
        iterations: 50000
        salt_length: 16
      bcrypt:
        variant: 'standard'
        cost: 12

## Password Policy Configuration.
# password_policy:
  # standard:       ## The standard policy allows you to tune individual settings manually.
    # enabled: false
    # min_length: 8
    # max_length: 0
    # require_uppercase: true
    # require_lowercase: true
    # require_number: true
    # require_special: true
  # zxcvbn:  ## zxcvbn is a well known and used password strength algorithm. It does not have tunable settings.
    # enabled: false
    # min_score: 3      ## Configures the minimum score allowed.

## Privacy Policy Configuration  (for displaying the privacy policy link and drawer)
# privacy_policy:
  # enabled: false  ## Enables the display of the privacy policy using the policy_url.
  # require_user_acceptance: false
# policy_url: ''   ## must be https


## Access Control Configuration
## One can use the wildcard * to match any subdomain. It must stand at the beginning. (example: *.example.com)
## Definition: A 'rule' is an object with the following keys: 'domain', 'subject', 'policy' and 'resources'.
## - 'domain' defines which domain or set of domains the rule applies to.
## - 'subject' defines the subject to apply authorizations to. Optional and matching any user if not provided. 
##    If provided, param represents either a user 'user:<username>' or a group 'group:<groupname>'.
## - 'policy' is the policy to apply to resources. It must be either 'bypass', 'one_factor', 'two_factor' or 'deny'.
## - 'resources' is a list of regex that matches a set of resources to apply the policy to. This parameter
##   is optional and matches any resource if not provided.
## Note: the order of the rules is important. The first policy matching (domain, resource, subject) applies.
access_control:
  default_policy: 'two_factor'
  rules:
    - domain: 'test.example.top'
      resources:
        - "^/css/.*"
        - "^/favicon.ico"
        - "^/api/health$"
      policy: 'bypass'
    - domain: 'test.example.top'
      policy: 'two_factor'
      
    - domain: '$AUTHELIA_DOMAIN'
      policy: 'one_factor'

   
    
    #   networks:  ## Network based rule, if not provided any network matches.
        # - 'internal'
        # - 'VPN'
        # - '192.168.1.0/24'
        # - '10.0.0.1'

    # - domain: 'mx2.mail.example.com'  ## Rules applied to 'admins' group
    #   subject: 'group:admins'
    #   policy: 'deny'
    
    # - domain: 'dev.example.com'  ## Rules applied to user 'john'
    #   resources:
        # - '^/users/john/.*$'
    #   subject: 'user:john'
    #   policy: 'two_factor'

## Session Provider Configuration (The session cookies identify the user once logged in.)
## The available providers are: memory, redis. Memory is the provider unless redis is defined.
session:
  secret: '$(head -c 32 /dev/urandom | base64 | tr -d '\n=')=' ## to encrypt session data. only used with Redis [Sentinel].

  cookies:  ## Cookies configure the list of allowed cookie domains for sessions to be created on.
    -
      name: 'authelia_session' ## The name of the session cookie. 
      domain: 'example.top'  ## The domain to protect. the Authelia portal must also be in that domain.
      authelia_url: 'https://$AUTHELIA_DOMAIN/authelia'  ## Required. portal URI to redirect users to 
      default_redirection_url: 'https://$AUTHELIA_DOMAIN'
      # same_site: 'lax'    ## none, lax, or strict.  https://www.authelia.com/c/session#same_site
 
      # inactivity: '5 minutes'
      # expiration: '1 hour'
      remember_me: '1 month'
  
  # name: 'authelia_session'  ## Cookie Session Domain default 'name' value.
  # same_site: 'lax'   ## Cookie Session Domain default 'same_site' value. 
  inactivity: '60m'  ## Cookie Session Domain default 'inactivity' value.
  expiration: '12h'
  # remember_me: '1M'

  ## Redis Provider
  ## Important: Kubernetes (or HA) users must read https://www.authelia.com/t/statelessness
  ##  …………


## Regulation Configuration
regulation:
  # modes:
    # - 'user'
  max_retries: 10
  find_time: '2 minutes'
  ban_time: '2 minutes'

## Storage Provider Configuration
## The available providers are: local, mysql, postgres. You must use one and only one of these providers.
storage:
  encryption_key: '$(head -c 64 /dev/urandom | base64 | tr -d '\n=')'

  
  ## Local (Storage Provider) stores data in SQLite3 DB. only recommended for lightweight non-stateful installations.
  ## Important: Kubernetes (or HA) users must read https://www.authelia.com/t/statelessness
  local:
    path: '/config/db.sqlite3'      ## Path to the SQLite3 Database.

  ##
  ## MySQL / MariaDB (Storage Provider)
  ## ……..
  
## Notification Provider (when users require a password reset, a WebAuthn registration or a TOTP registration)
## The available providers are: filesystem, smtp. You must use only one of these providers.
notifier:
  # disable_startup_check: false  ## You can disable the notifier startup check by setting this to true.
  
  ## File System (Notification Provider)
  filesystem:
    filename: '/config/notification.txt'

  
  ## SMTP (Notification Provider)
  ## Use a SMTP server for sending notifications. Authelia uses the PLAIN or LOGIN methods to authenticate.
  # smtp:
    # address: 'smtp://127.0.0.1:25'   ## The address of the SMTP server to connect to in the address common syntax.
    # timeout: '5 seconds'  ## The connection timeout in the duration common syntax.
    
    # username: 'test' ## The username used for SMTP authentication.
    # password: 'password'   ## The password used for SMTP auth. Can also https://www.authelia.com/c/secrets


    ## …………….

##
## Identity Providers
##
# identity_providers:

  ##...........
EOF
echo "Now you will go inside ~/authelia/config/configuration.yml to further configure and check,"
echo "especially totp, authentication_backend, access_control, session, regulation, storage, notifier."  
read -p "You can back and go inside again. Hit ENTER to continue" OPTION
while ! [ "$OPTION" = "Y" ]; do
    vim ~/authelia/config/configuration.yml
    read -p "Have you finished configuration? (Enter Y)" OPTION
done
read -p "Is everything ok to install and launch authelia docker now? (Enter Y)" OPTION
if [ "$OPTION" = "Y" ]; then
    sudo docker run -d \
        --name authelia \
        -p $AUTHELIA_PORT:$AUTHELIA_PORT \
        -v ~/authelia/config:/config \
        --restart unless-stopped \
        authelia/authelia:latest
    sleep 2
    sudo docker logs --tail 6 authelia
    read -p "Is authelia running properly? (Enter Y)" OPTION
    while ! [ "$OPTION" = "Y" ]; do 
        sudo vim ~/authelia/config/configuration.yml
        sudo docker restart authelia
        sleep 2
        sudo docker logs --tail 6 authelia
        read -p "Is authelia running properly? (Enter Y)" OPTION
    done
fi
cat > authelia.conf << EOF
# /etc/nginx/snippets/authelia.conf
## 发送给 Authelia 的请求
set \$upstream_authelia http://127.0.0.1:$AUTHELIA_PORT;

## 位置块，用于将未认证的请求转发至 Authelia
location /authelia-verify {
    internal; # 这是一个内部位置，外部无法直接访问
    proxy_pass \$upstream_authelia/api/verify;

    # 传递必要的原始请求信息给 Authelia
    proxy_set_header Content-Length "";
    proxy_set_header X-Original-URL \$scheme://\$http_host\$request_uri;
    proxy_set_header X-Forwarded-Method \$request_method;
    proxy_set_header X-Forwarded-Proto \$scheme;
    proxy_set_header X-Forwarded-Host \$http_host;
    proxy_set_header X-Forwarded-Uri \$request_uri;
    proxy_set_header X-Forwarded-For \$remote_addr;
    # 确保不将请求体传递给验证端点
    proxy_pass_request_body off;
}
EOF
sudo mv authelia.conf /etc/nginx/snippets/authelia.conf
cat > $AUTHELIA_DOMAIN << EOF
# /etc/nginx/sites-available/$AUTHELIA_DOMAIN
server {
    listen 80;
    server_name $AUTHELIA_DOMAIN;
    return 301 https://\$server_name\$request_uri;
}

server {
    listen 443 ssl;
    server_name $AUTHELIA_DOMAIN;

    ssl_certificate /etc/letsencrypt/live/$AUTHELIA_DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$AUTHELIA_DOMAIN/privkey.pem;
    # ... 其他SSL优化配置（如协议、加密套件）建议参考 Mozilla SSL 配置生成器

    location / {
        # 直接代理到 Authelia 容器
        proxy_pass http://127.0.0.1:9091;
        proxy_set_header Host \$http_host;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF
sudo mv $AUTHELIA_DOMAIN /etc/nginx/sites-available/$AUTHELIA_DOMAIN
sudo ln -s /etc/nginx/sites-available/$AUTHELIA_DOMAIN /etc/nginx/sites-enabled
sudo nginx -t
read -p "Is nginx configuration ok? (Enter Y)" OPTION
if [ "$OPTION" = "Y" ]; then
    sudo systemctl restart nginx && sudo systemctl status nginx  && sleep 1 
fi


exit 0
