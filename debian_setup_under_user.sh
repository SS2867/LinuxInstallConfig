#!/bin/bash

# === install Apps ====
echo "in user $USER"

cd $HOME

NOPASSWD=""
read -p "Disable sudo password auth requirement for user $USER? (Enter anything to disable, otherwise leave blank and hit enter) " NOPASSWD
if ! [ -z "$NOPASSWD" ]; then
    echo "$USER ALL=(ALL) NOPASSWD:ALL" | sudo tee -a /etc/sudoers.d/nopasswd
fi
echo "%sudo ALL=(ALL) NOPASSWD: /sbin/shutdown" | sudo tee -a /etc/sudoers.d/nopasswd  && sudo chmod 0440 /etc/sudoers.d/nopasswd

sudo iptables -P INPUT ACCEPT

SSH_AUTHORIZED_KEYS=""
read -p "SSH Authorized Keys for login: " SSH_AUTHORIZED_KEYS  
if ! [ -z "$SSH_AUTHORIZED_KEYS" ]; then
    mkdir -p ~/.ssh && touch ~/.ssh/authorized_keys
    echo -e "$SSH_AUTHORIZED_KEYS\n" >> ~/.ssh/authorized_keys
    read -p "Do you want to ban SSH password login? (Enter Y if so): " OPTION
    if [ "$OPTION" = "Y" ]; then
        sudo sed -i 's/^#\?PasswordAuthentication\s\+.*$/PasswordAuthentication no/' /etc/ssh/sshd_config
    fi
    sleep 2
fi
echo -e "\nssh-keygen -lf /etc/ssh/ssh_host_key.pub\nssh-keygen -lf /etc/ssh/ssh_host_rsa_key.pub\n" >> ~/.bashrc

wget https://raw.githubusercontent.com/SS2867/LinuxInstallConfig/refs/heads/main/sources.list
sudo cat ./sources.list | sudo tee -a /etc/apt/sources.list # config required
rm sources.list

sudo fallocate -l 2G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
sudo cp /etc/fstab /etc/fstab.bak
echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab


#read -p "Do you want to install google chrome now? (Enter Y to install, or leave a installation script)" OPTION
#if [ "$OPTION" = "Y" ]; then
wget -N https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb 
sudo apt install ./google-chrome-stable_current_amd64.deb  -y
rm google-chrome-stable_current_amd64.deb 
echo '{ "ExtensionManifestV2Availability": 2 }' | sudo tee /etc/opt/chrome/policies/managed/policy.json /etc/chromium/policies/managed/policy.json

install_chrome_extension () {
  preferences_dir_path="$HOME/.config/google-chrome/Extensions/"
  pref_file_path="$preferences_dir_path/$1.json"
  upd_url="https://clients2.google.com/service/update2/crx"
  mkdir -p "$preferences_dir_path"
  echo "{" > "$pref_file_path"
  echo "  \"external_update_url\": \"$upd_url\"" >> "$pref_file_path"
  echo "}" >> "$pref_file_path"
  echo Added \""$pref_file_path"\" ["$2"]
}
#install_chrome_extension "ndcooeababalnlpkfedmmbbbgkljhpjf" "StriptCat"
#install_chrome_extension "anmidgajdonkgmmilbccfefkfieajakd" "save pinned tabs"
#install_chrome_extension "dbepggeogbaibhgnhhndojpepiihcmeb" "vimium"
#else
#    echo -e "#! /bin/bash\nwget -N https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb \nsudo apt install ./google-chrome-stable_current_amd64.deb -y \nrm ./google-chrome-stable_current_amd64.deb \nexit 0\n" > ./google-chrome-install.sh
#    chmod +x ./google-chrome-install.sh
#fi


sudo apt update -y
sudo apt full-upgrade -y
sudo apt install tmux certbot nginx python3-certbot-nginx vim htop nethogs xfce4 xfce4-goodies fonts-wqy-zenhei konsole xserver-xephyr fail2ban tightvncserver simplescreenrecorder vlc ffmpeg winff rsyslog iptables -y
#sudo apt install   sddm-theme-debian-breeze kde-config-sddm kde-plasma-desktop 

sudo update-alternatives --set x-terminal-emulator /usr/bin/konsole


sudo systemctl enable rsyslog
sudo systemctl start rsyslog
sudo systemctl enable fail2ban
sudo systemctl start fail2ban
sudo fail2ban-client start
sudo cp  /etc/fail2ban/fail2ban.conf /etc/fail2ban/fail2ban.local
sudo cp  /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
sudo sed -i '/^\[sshd\]/,/^$/ { 
    /^$/!d 
    a\
[sshd]\
bantime.increment = true\
bantime.rndtime = 600\
bantime.maxtime = 86400\
bantime.factor = 1\
bantime.multipliers = 1 1 6 12 24 32 64\
bantime = 3600\
findtime = 3600\
maxretry = 10
}' /etc/fail2ban/jail.local
sudo fail2ban-client status sshd
sudo systemctl reload fail2ban

sudo sed -i 's/^.*MaxAuthTries.*$/MaxAuthTries 2/' /etc/ssh/sshd_config
sudo systemctl reload sshd
sudo sed -i '$a \
net.ipv4.tcp_max_syn_backlog = 4096\
net.ipv4.tcp_syn_retries = 2\
net.ipv4.tcp_synack_retries = 2\
net.ipv4.tcp_syncookies = 1\
net.ipv4.tcp_mem = 32768\
net.ipv4.tcp_rmem = 32768\
net.ipv4.tcp_wmem = 32768' /etc/sysctl.conf
sudo sysctl -p

if [ ! -f /etc/rc.local ]; then
    sudo sh -c 'printf "%s\n" "#!/bin/bash" "" "exit 0" > /etc/rc.local'
    sudo chmod +x /etc/rc.local
    sudo systemctl enable rc-local
fi

#sudo bash -c 'echo -e "#! /bin/sh\n\nsystemctl stop xrdp\n\nshutdown -c\nshutdown -r +10080 \"Scheduled 168h system reboot.\"\n\n\n\n\nexit 0" > /etc/rc.local'
read -p "Do you want to enable 72h periodic auto reboot? (Enter Y)" OPTION
if [ "$OPTION" = "Y" ]; then
    sudo bash -c 'echo -e "#!/bin/bash\n\nsudo shutdown -c\nsudo shutdown -r +4320 \"Scheduled 72h system reboot.\"\nwall \"72h system reboot schedule reset\"\n\n\n" > /etc/profile.d/reboot_schedule.sh'
    sudo chmod +x /etc/profile.d/reboot_schedule.sh
    sudo sed -i "/^exit 0$/i \\
shutdown -c\\
shutdown -r +4320 \"Scheduled 72h system reboot.\"" /etc/rc.local

fi


sudo ufw disable
#wget http://www.inetbase.com/scripts/ddos/install.sh
#chmod 0700 install.sh
#./install.sh
#vim /usr/local/ddos/ddos.conf


# jupyterlab 
read -p "Do you want to install a persistent open jupyterlab service? (Enter Y)"  OPTION
if [ "$OPTION" = "Y" ]; then
    sudo apt install python3-pip -y
    python3 -m pip -q install jupyterlab notebook jupyterlab-lsp python-lsp-server[all] ipykernel
    python3 -m pip -q install jupyterlab notebook jupyterlab-lsp python-lsp-server[all] ipykernel --break-system-packages
    echo "Set a password for jupyterlab login. Must be at least 12 characters."
    while ! [ ${#JUPYTERLAB_PASSWORD} -gt 12 ]; do
        JUPYTERLAB_PASSWORD=$(python3 -c "from getpass import getpass as g; a,b=g(),g(\"Repeat: \"); print(a if a==b else \"\")")
    done
    echo "Password length: ${#JUPYTERLAB_PASSWORD}"
    JUPYTERLAB_PASSWORD_HASH=$(python3 -c "from jupyter_server.auth import passwd; print(passwd(\"$JUPYTERLAB_PASSWORD\"))")
    read -p "Choose a port for jupyterlab, default by random: "  JUPYTERLAB_PORT
    if [ -z "$JUPYTERLAB_PORT" ]; then
        JUPYTERLAB_PORT=$(shuf -i 10240-65535 -n 1)
        echo "Empty port entered. Chosen $JUPYTERLAB_PORT as jupyterlab server port" && sleep 2
    fi
    cat > jupyterlab.service << EOF
[Unit]
Description=JupyterLab Trigger Service
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=/
ExecStart=nohup python3 -m jupyterlab --port $JUPYTERLAB_PORT  --PasswordIdentityProvider.hashed_password="$JUPYTERLAB_PASSWORD_HASH" --ContentsManager.allow_hidden=True --ServerApp.allow_remote_access=True --ip="0.0.0.0" --no-browser  

[Install]
WantedBy=multi-user.target
EOF
    echo "Jupyterlab systemctl service file (jupyterlab.service) created. Enabling"
    cat jupyterlab.service
    sudo mv jupyterlab.service /etc/systemd/system/jupyterlab.service
    sudo systemctl daemon-reload && sudo systemctl enable --now jupyterlab.service
    sleep 2 && sudo systemctl status jupyterlab.service
fi

# =======download and install scripts==========
cd $HOME

mkdir -p scripts && cd scripts
wget -N https://raw.githubusercontent.com/SS2867/LinuxInstallConfig/refs/heads/main/v2ray.sh
chmod +x v2ray.sh
#sudo ./v2ray.sh

# frp server
wget -N https://raw.githubusercontent.com/SS2867/LinuxInstallConfig/refs/heads/main/frps_install.sh
chmod +x frps_install.sh
read -p "Install and configure FRP server? (Enter Y)" OPTION
if [ "$OPTION" = "Y" ]; then
    ./frps_install.sh
fi

# rclone
wget -N https://raw.githubusercontent.com/SS2867/LinuxInstallConfig/refs/heads/main/rclone_install.sh
chmod +x rclone_install.sh
read -p "Install and configure rclone services? (Enter Y)" OPTION
if [ "$OPTION" = "Y" ]; then
    ./rclone_install.sh
fi

# miniconda 
bash -c 'echo -e "#! /bin/bash\nwget -N https://repo.anaconda.com/miniconda/Miniconda3-latest-Linux-x86_64.sh\nchmod +x Miniconda3-latest-Linux-x86_64.sh\n./Miniconda3-latest-Linux-x86_64.sh\nrm ./Miniconda3-latest-Linux-x86_64.sh\nexit 0\n" > ./miniconda-install.sh'
chmod +x miniconda-install.sh
read -p "Install miniconda? (Enter Y)" OPTION
if [ "$OPTION" = "Y" ]; then
    ./miniconda-install.sh
    echo "Enter miniconda install path (such as /home/user/miniconda3) if you want to use \"conda-activate\" as short-command for activating conda base. "
    read -p "Otherwise, directly hit ENTER: " MINICONDA_PATH
    if ! [ -z "$MINICONDA_PATH" ]; then
        echo -e "\nalias conda-activate=\"source $MINICONDA_PATH/bin/activate\"\n" >> ~/.bashrc
    fi
fi

# ffmpeg BtbN
read -p "Configure ffmpeg BtbN build version? (Enter Y)" OPTION
if [ "$OPTION" = "Y" ]; then
    wget https://github.com/BtbN/FFmpeg-Builds/releases/download/latest/ffmpeg-master-latest-linux64-gpl.tar.xz
    mkdir -p ~/ffmpeg/
    tar -xf ffmpeg-master-latest-linux64-gpl.tar.xz -C ~/ffmpeg/
    rm ffmpeg-master-latest-linux64-gpl.tar.xz
    echo -e '\nalias ffmpegbtbn="~/ffmpeg/ffmpeg-master-latest-linux64-gpl/bin/ffmpeg"  \nalias ffprobebtbn="~/ffmpeg/ffmpeg-master-latest-linux64-gpl/bin/ffprobe" ' >> ~/.bashrc
fi

# docker 
read -p "Do you want to install docker & portainer? (Enter Y)" OPTION
if [ "$OPTION" = "Y" ]; then
    sudo apt-get update
    sudo apt-get install ca-certificates curl -y
    sudo install -m 0755 -d /etc/apt/keyrings
    sudo curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
    sudo chmod a+r /etc/apt/keyrings/docker.asc

    # Add the repository to Apt sources:
    echo \
      "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian \
      $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
      sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
    sudo apt-get update

    sudo apt-get install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin -y

    # portainer
    sudo docker run -d -p 127.0.0.1:52612:9443 --name portainer --restart=always -v /var/run/docker.sock:/var/run/docker.sock -v portainer_data:/data portainer/portainer-ce:lts #--trusted-origins test.top
    
    
fi


# authelia
wget -N https://raw.githubusercontent.com/SS2867/LinuxInstallConfig/refs/heads/main/authelia_docker_install.sh
chmod +x authelia_docker_install.sh
read -p "Do you want to install authelia (in docker)? (Enter Y)" OPTION
if [ "$OPTION" = "Y" ]; then
    ./authelia_docker_install.sh
fi

# nginx configure
wget -N https://raw.githubusercontent.com/SS2867/LinuxInstallConfig/refs/heads/main/nginx_configure.sh
chmod +x nginx_configure.sh
./nginx_configure.sh





wget -N https://raw.githubusercontent.com/SS2867/LinuxInstallConfig/refs/heads/main/x-ui-install.sh
chmod +x x-ui-install.sh
#sudo ./x-ui-install.sh

bash -c 'echo -e "#! /bin/bash\nwget -N https://zoom.us/client/latest/zoom_amd64.deb\nsudo apt install -y ./zoom_amd64.deb\nrm ./zoom_amd64.deb\nexit 0\n" > ./zoom-install.sh'
chmod +x zoom-install.sh


#wget -N https://raw.githubusercontent.com/SS2867/LinuxInstallConfig/refs/heads/main/jupyter_sh_encrypted
wget -N https://raw.githubusercontent.com/SS2867/LinuxInstallConfig/refs/heads/main/Encryptor2.py
#python3 -c 'import Encryptor2; a="".join(open("jupyter_sh_encrypted").readlines()); open("jupyter.sh", "w").write(Encryptor2.decrypt_text(a, "nicai", valid_text_chars=Encryptor2.PRINTABLE_ASCII + "\n"))'
#rm jupyter_sh_encrypted
#chmod +x jupyter.sh

cd $HOME

#wget https://raw.githubusercontent.com/SS2867/LinuxInstallConfig/refs/heads/main/xrdp-installer-1.4.2.sh
#sudo chmod +x xrdp-installer-1.4.2.sh
#./xrdp-installer-1.4.2.sh -c -s
sudo apt install xrdp -y
sudo systemctl unmask xrdp
sudo systemctl disable xrdp
sudo systemctl stop xrdp
sudo sed -i "/^exit 0$/i \\
systemctl stop xrdp" /etc/rc.local
#sudo systemctl status xrdp
#sudo systemctl status xrdp-daemon
#sudo systemctl restart xrdp
#sudo systemctl status xrdp


# === config ====
sudo timedatectl set-timezone Asia/Shanghai

cd $HOME
mkdir .ssr  # SimpleScreenRecorder
wget -N https://raw.githubusercontent.com/SS2867/LinuxInstallConfig/refs/heads/main/settings.conf
mv settings.conf ./.ssr/settings.conf

mkdir .config
sudo bash -c 'echo -e "[Default Applications]\ntext/html=google-chrome.desktop\n" > .config/mimeapps.list'



# === clean ===
sudo apt autoremove -y
sudo apt clean -y

#sudo swapoff /swapfile
#sudo rm /swapfile
#echo -e "#!/bin/bash\n\nsudo fallocate -l 1G /swapfile\nsudo chmod 600 /swapfile\nsudo mkswap /swapfile\nsudo swapon /swapfile\nsudo cp /etc/fstab /etc/fstab.bak\necho '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab\n\nrm -- "$0"\n\nexit 0" > ~/enable_swap.sh
#chmod +x ~/enable_swap.sh
#(echo "@reboot $HOME/my_script.sh") | crontab -


read -p "Finished. Poweroff now? (Enter Y to poweroff)" OPTION
if [ "$OPTION" = "Y" ]; then
    sudo poweroff
fi

exit 0
