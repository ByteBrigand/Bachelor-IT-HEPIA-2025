#!/bin/bash

set -euxo

INFO_DIR="/info"
HOSTNAME_FILE="${INFO_DIR}/hostname"
USERNAME_FILE="${INFO_DIR}/username"
CONTAINER_IP_FILE="${INFO_DIR}/container_ip"
NUMBER_HOST_FILE="${INFO_DIR}/number_host"
NUMBER_USER_FILE="${INFO_DIR}/number_user"
CONTAINER_IPS_FILE="${INFO_DIR}/container_ips"
ENTRYPOINT_DONE="/tmp/entrypoint_done"
WIREGUARD_CONF="${INFO_DIR}/wg1.conf"
WIREGUARD_DEST="/etc/wireguard/wg1.conf"
SSH_HOST_KEY_DIR="/etc/ssh"
CUTTLEFISH_CERT_DIR="/etc/cuttlefish-common/operator/cert"
CUTTLEFISH_RUN_DIR="/run/cuttlefish"


if [ -f "$ENTRYPOINT_DONE" ]; then
    echo "Already ran entrypoint.sh"
    exit 0
fi

#chown -R root:root /boot /bin /etc /home /lib /media /mnt /opt /run /sbin /srv /tmp /usr /var
#find /boot /bin /etc /home /lib /media /mnt /opt /run /sbin /srv /tmp /usr /var -type d -exec chmod g+s {} \;
chown root:root /root

#chown root:root -R /run
chown root:root /run/sshd
chown root:root /etc/wireguard
chown root:root -R /etc/ssh
chown root:root -R /usr/local/sbin
chown root:root -R /usr/local/bin
chown root:root -R /usr/bin
chown root:root -R /usr/sbin
chown root:root /etc/sudo.conf
chown root:root /etc/sudoers
chown root:root -R /etc/sudoers.d
chown root:root -R /etc/passwd
chown root:root -R /etc/group
chmod u+s /usr/bin/sudo

chown root:shadow /etc/shadow
chown root:shadow /etc/gshadow

chmod 640 /etc/shadow
chmod 640 /etc/gshadow
chmod 644 /etc/passwd
chmod 644 /etc/group

chmod u+s /usr/bin/sudo

/usr/local/sbin/setup-network.sh



if [ -f "$USERNAME_FILE" ]; then
    USERNAME=$(cat "$USERNAME_FILE")
    echo "Found username: $USERNAME"
else
    echo "Error: $USERNAME_FILE file not found"
    exit 1
fi


# Set bash as default shell for root
chsh -s /bin/bash root


if ! id "${USERNAME}" &>/dev/null; then
    useradd -m -d "/home/${USERNAME}" -s /bin/bash "${USERNAME}"
    echo "umask 022" >> "/home/${USERNAME}/.profile"
    echo "umask 022" >> "/home/${USERNAME}/.bashrc"

    # Add Android NDK environment variables if they don't exist
    if ! grep -q "NDK_DIR=" "/home/${USERNAME}/.bashrc"; then
        cat >> "/home/${USERNAME}/.bashrc" << 'EOF'

# Android NDK environment variables
export NDK_DIR=/opt/android-ndk
export TOOLCHAIN_DIR="$NDK_DIR/toolchains/llvm/prebuilt/linux-aarch64"
EOF
    fi

    # Only add aliases if they don't already exist
    if ! grep -q "alias ghidra=" "/home/${USERNAME}/.bashrc" && \
       ! grep -q "alias jadx=" "/home/${USERNAME}/.bashrc" && \
       ! grep -q "alias jadx-gui=" "/home/${USERNAME}/.bashrc"; then
        cat >> "/home/${USERNAME}/.bashrc" << 'EOF'

# Java tool aliases
alias ghidraRun='JAVA_HOME=/usr/lib/jvm/jdk-21.* /opt/ghidra/ghidraRun'
alias analyzeHeadless='JAVA_HOME=/usr/lib/jvm/jdk-21.* /opt/ghidra/support/analyzeHeadless'
alias jadx='JAVA_HOME=/usr/lib/jvm/java-17-openjdk-arm64 jadx'
alias jadx-gui='JAVA_HOME=/usr/lib/jvm/java-17-openjdk-arm64 jadx-gui'
EOF
    fi

    chmod 2770 "/home/${USERNAME}"
    touch "/home/${USERNAME}/.bash_history"
    chown -R "${USERNAME}:${USERNAME}" "/home/${USERNAME}"
    chown "${USERNAME}:${USERNAME}" "/home/${USERNAME}/.bash_history"
    if ! grep -q '^sudo:' /etc/group; then
        groupadd sudo
    fi
    usermod -aG sudo "${USERNAME}"
fi

# Add Android NDK environment variables to root's bashrc if they don't exist
if ! grep -q "NDK_DIR=" "/root/.bashrc"; then
    cat >> "/root/.bashrc" << 'EOF'

# Android NDK environment variables
export NDK_DIR=/opt/android-ndk
export TOOLCHAIN_DIR="$NDK_DIR/toolchains/llvm/prebuilt/linux-aarch64"
EOF
fi

# Only add aliases to root's bashrc if they don't already exist
if ! grep -q "alias ghidra=" "/root/.bashrc" && \
   ! grep -q "alias jadx=" "/root/.bashrc" && \
   ! grep -q "alias jadx-gui=" "/root/.bashrc"; then
    cat >> "/root/.bashrc" << 'EOF'

# Java tool aliases
alias ghidraRun='JAVA_HOME=/usr/lib/jvm/jdk-21.* /opt/ghidra/ghidraRun'
alias analyzeHeadless='JAVA_HOME=/usr/lib/jvm/jdk-21.* /opt/ghidra/support/analyzeHeadless'
alias jadx='JAVA_HOME=/usr/lib/jvm/java-17-openjdk-arm64 jadx'
alias jadx-gui='JAVA_HOME=/usr/lib/jvm/java-17-openjdk-arm64 jadx-gui'
EOF
fi




if [ -f "$HOSTNAME_FILE" ]; then
    HOSTNAME=$(cat "$HOSTNAME_FILE")
    if [ -n "$HOSTNAME" ]; then
        echo "$HOSTNAME" > /etc/hostname
        echo "Hostname set to: $HOSTNAME"
    else
        echo "Error: Hostname file is empty"
        exit 1
    fi
else
    echo "Error: Hostname file not found at $HOSTNAME_FILE"
    exit 1
fi

# Generate random passwords
USER_PASS=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 20 | head -n 1)
ROOT_PASS=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 20 | head -n 1)

# Set passwords
echo "${USERNAME}:${USER_PASS}" | chpasswd
echo "User password set for ${USERNAME}"
echo "root:${ROOT_PASS}" | chpasswd
echo "Root password set"

# Add user to sudoers with NOPASSWD
echo "${USERNAME} ALL=(ALL) NOPASSWD: ALL" | (sudo tee /etc/sudoers.d/${USERNAME}) > /dev/null
chmod 440 /etc/sudoers.d/${USERNAME}


# Generate keys if they don't exist
if [ ! -f "${SSH_HOST_KEY_DIR}/ssh_host_rsa_key" ]; then
    echo "SSH host keys not found. Generating new ones..."
    ssh-keygen -A # if we did this in Containerfile, all the containers would have the same host keys
fi

# Copy and rename ed25519 keys if they exist in /info
if ls ${INFO_DIR}/ssh_host* >/dev/null 2>&1; then
    rm -f ${SSH_HOST_KEY_DIR}/ssh_host_ed25519_*
    
    cp ${INFO_DIR}/ssh_host_*_key ${SSH_HOST_KEY_DIR}/ssh_host_ed25519_key
    cp ${INFO_DIR}/ssh_host_*_key.pub ${SSH_HOST_KEY_DIR}/ssh_host_ed25519_key.pub
    cp ${INFO_DIR}/ssh_host_*_key-cert.pub ${SSH_HOST_KEY_DIR}/ssh_host_ed25519_key-cert.pub

    # Fix permissions for all SSH keys
    chmod 600 ${SSH_HOST_KEY_DIR}/ssh_host_*_key
    chmod 644 ${SSH_HOST_KEY_DIR}/ssh_host_*_key.pub
    chmod 644 ${SSH_HOST_KEY_DIR}/ssh_host_*_key-cert.pub
    
    echo "SSH ed25519 host keys copied, renamed, and permissions set"
else
    echo "No SSH host keys found in $INFO_DIR/"
fi

# Copy WireGuard config if it exists
if [ -f "$WIREGUARD_CONF" ]; then
    cp "$WIREGUARD_CONF" "$WIREGUARD_DEST"
    chmod 600 "$WIREGUARD_DEST"
    echo "WireGuard config copied and permissions set"
else
    echo "No WireGuard config found at $WIREGUARD_CONF"
fi

# Generate TLS certificates for the operator
# We run this in entrypoint to have different certificates for each container
if [ ! -f "${CUTTLEFISH_CERT_DIR}/cert.pem" ]; then
    openssl req -newkey rsa:1024 \
        -x509 \
        -sha256 \
        -days 360 \
        -nodes \
        -out "${CUTTLEFISH_CERT_DIR}/cert.pem" \
        -keyout "${CUTTLEFISH_CERT_DIR}/key.pem" \
        -subj "/C=US" \
        2>/dev/null
fi


chown -R root:cvdnetwork "$CUTTLEFISH_CERT_DIR"
chown -R root:cvdnetwork "$CUTTLEFISH_RUN_DIR"
chmod 640 "${CUTTLEFISH_CERT_DIR}/key.pem"
chmod 644 "${CUTTLEFISH_CERT_DIR}/cert.pem"


if ! wg show wg1 >/dev/null 2>&1; then
    echo "Starting Wireguard..."
    wg-quick up wg1
fi





# MOTD
required_files=(
    "$CONTAINER_IP_FILE"
    "$USERNAME_FILE"
    "$NUMBER_HOST_FILE"
    "$NUMBER_USER_FILE"
    "$CONTAINER_IPS_FILE"
)
missing_files=0
for file in "${required_files[@]}"; do
    if [ ! -f "$file" ]; then
        echo "Error: Required file $file not found"
        missing_files=1
    elif [ ! -s "$file" ]; then
        echo "Error: Required file $file is empty"
        missing_files=1
    fi
done

if [ $missing_files -eq 1 ]; then
    echo "Error: Cannot generate MOTD due to missing or empty files"
    exit 1
fi

# If all files exist and are not empty, read their contents
CONTAINER_IP=$(cat "$CONTAINER_IP_FILE")
USERNAME=$(cat "$USERNAME_FILE")
NUMBER_HOST=$(cat "$NUMBER_HOST_FILE")
NUMBER_USER=$(cat "$NUMBER_USER_FILE")
OTHER_CONTAINERS=$(cat "$CONTAINER_IPS_FILE")

cat > /etc/motd << EOF
╭───────────────────────────────────────────────────╮
│           Android Fuzzing Lab Environment         │
╰───────────────────────────────────────────────────╯

Welcome to Container ${NUMBER_HOST}-${NUMBER_USER} on host ${HOSTNAME}
Current user: ${USERNAME}
Container IP: ${CONTAINER_IP}

Containers in the network:
${OTHER_CONTAINERS}

-----------------------------------------------------
    If you find a bug please notify the sysadmin
    to receive a bonus to your grades. Good luck!
-----------------------------------------------------
EOF









# adb sync service
# Start adb sync in background
chmod +x /usr/local/bin/adb-sync.sh
nohup /usr/local/bin/adb-sync.sh >/dev/null 2>&1 &


# adb master afl monitor service
chmod +x /usr/local/bin/adb-master-afl-monitor.sh
nohup /usr/local/bin/adb-master-afl-monitor.sh >/dev/null 2>&1 &


# Src nat for Android Cuttlefish
iptables -t nat -A POSTROUTING -s 192.168.0.0/16 -j MASQUERADE




touch /tmp/entrypoint_done

echo "Starting SSH server..."
exec /usr/sbin/sshd -D
