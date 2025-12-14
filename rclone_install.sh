#!/bin/bash

sudo apt install fuse3 zip -y
sudo -v ; curl https://rclone.org/install.sh | sudo bash
RCLONE_CONFIG_FINISHED=""
while ! [ "$RCLONE_CONFIG_FINISHED" = "Y" ]; do
    rclone config
    read -p "Have you finished configuring rclone accounts? (Enter Y)" RCLONE_CONFIG_FINISHED
done
sudo sed -i 's/^#user_allow_other/user_allow_other/' /etc/fuse.conf

cd ~
SYSTEMD_DIR="/etc/systemd/system"
RCLONE_TARGET_FILE="rclone_mount.target"
mkdir -p extdrives && cd extdrives
BASE_MOUNT_DIR="$HOME/extdrives"

echo "Now lets configure systemd for configured cloud accounts auto mount services, and enable them --"
read -p "Input cloud drive account identifier (Hit ENTER if no more to add):" CLOUD_NAME

while ! [ -z "$CLOUD_NAME" ]; do 
    # 构造服务文件名和挂载点路径
    SERVICE_FILE_NAME="rclone_mount_${CLOUD_NAME}.service"
    #SERVICE_FILE_PATH="$SYSTEMD_DIR/$SERVICE_FILE_NAME"
    MOUNT_POINT="$BASE_MOUNT_DIR/$CLOUD_NAME"
    mkdir -p $MOUNT_POINT

    # 2. 生成并写入 Systemd 服务文件
    echo "Generating: $SERVICE_FILE_NAME"
    cat << EOF > "$SERVICE_FILE_NAME"
[Unit]
Description=rclone mount Service for ${CLOUD_NAME}
PartOf=rclone_mount.target

[Service]
User=$USER
ExecStart=rclone mount ${CLOUD_NAME}:/ ${MOUNT_POINT} --allow-other --vfs-cache-mode writes --vfs-cache-max-age 30m --dir-cache-time 10s --poll-interval 10s
Restart=always
RestartSec=30

[Install]
WantedBy=multi-user.target
EOF
    sudo mv $SERVICE_FILE_NAME $SYSTEMD_DIR/$SERVICE_FILE_NAME
    echo "Moved $SERVICE_FILE_NAME to $SYSTEMD_DIR/$SERVICE_FILE_NAME."

    # 3. 更新 rclone_mount.target 文件
    if [ ! -f "$RCLONE_TARGET_FILE" ]; then
        cat <<EOF > "$RCLONE_TARGET_FILE"
[Unit]
Description=Rclone Mounting
After=network.target local-fs.target dbus.service
Wants=${SERVICE_FILE_NAME}

[Install]
WantedBy=multi-user.target
EOF
        echo "$RCLONE_TARGET_FILE has been created with $SERVICE_FILE_NAME included"
    else
        # 检查服务是否已在 Wants= 列表中
        if ! grep -q "Wants=.*\\b${SERVICE_FILE_NAME}\\b" "$RCLONE_TARGET_FILE"; then
            # 如果 Wants= 行存在，则追加。如果不存在，则在 [Unit] 部分的 After= 行后添加 Wants= 行。
            if grep -q "^Wants=" "$RCLONE_TARGET_FILE"; then
                sed -i "/^Wants=/ s/$/ ${SERVICE_FILE_NAME}/" "$RCLONE_TARGET_FILE"
                echo "Added ${SERVICE_FILE_NAME} to Wants= list of $RCLONE_TARGET_FILE."
            else # 如果 Wants= 行不存在，则在 After= 行后添加
                sed -i "/^After=/aWants=${SERVICE_FILE_NAME}" "$RCLONE_TARGET_FILE"
                echo "Added ${SERVICE_FILE_NAME} to After= list of $RCLONE_TARGET_FILE."
            fi
        else
            echo "${SERVICE_FILE_NAME} already exists in $RCLONE_TARGET_FILE and .target file is not updated."
        fi
    fi
    echo ""
    read -p "Input cloud drive account identifier (Hit ENTER if no more to add):" CLOUD_NAME
done

sudo mv $RCLONE_TARGET_FILE $SYSTEMD_DIR/$RCLONE_TARGET_FILE

echo "== Below are the files in $SYSTEMD_DIR : "
ls -a $SYSTEMD_DIR
echo "== Among them, rclone related are: "
ls -ahl $SYSTEMD_DIR | grep rclone
echo "--------------------"
echo "Enabling and launching rclone_mount.target"
sudo systemctl daemon-reload
sudo systemctl enable --now rclone_mount.target
sleep 2
sudo systemctl status rclone_mount.target

exit 0
