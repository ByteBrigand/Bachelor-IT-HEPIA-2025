#!/bin/bash

#=================================================================================
# rpi-write-and-customize.sh
#
# Description:
#   Acts as the main provisioning script. It calls ssh-host-key-create.sh to
#   generate and sign keys, then writes images and applies all customizations.
#
#
# Parameters:
#   1. Main Disk Device         (e.g., /dev/sda)
#   2. USB Boot Device          (e.g., /dev/sdb)
#   3. Path to usb.img
#   4. Path to main.img
#   5. Path to rpi_luks.key
#   6. Hostname                 (lowercase)
#   7. IP Address in CIDR
#   8. Gateway IP Address
#   9. Path to CA Private Key   (e.g., /path/to/ca/ssh_host_ca_key)
#  10. Path to CA Public Key    (e.g., /path/to/ca/ssh_host_ca_key.pub)
#  11. Root Password
#
# Example:
#   sudo ./rpi-write-and-customize.sh \
#     /dev/sda /dev/sdb \
#     ./rpi_images/usb.img ./rpi_images/main.img ./rpi_images/rpi_luks.key \
#     mypi 192.168.1.100/24 192.168.1.1 \
#     /path/to/ca_private_key /path/to/ca_public_key.pub \
#     "MySecureRootPassword123"
#
#=================================================================================

set -e

# --- Parameter Validation ---
if [ "$#" -ne 11 ]; then
    echo "Usage: $0 <main_disk> <usb_disk> <usb_img> <main_img> <luks_key> <hostname> <ip/cidr> <gateway> <ca_priv_key> <ca_pub_key> <root_pass>"
    exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
  echo "This script must be run as root." >&2
  exit 1
fi

# --- Assign Parameters to Variables ---
maindisk=$1;
usbdisk=$2;
usb_img=$3;
main_img=$4;
luks_keyfile=$5;
hostname=$6
ip_cidr=$7;
gateway=$8;
ca_priv_key_path=$9;
ca_pub_key_path=${10};
rootpass=${11}
ip_address=$(echo "$ip_cidr" | cut -d'/' -f1)

# --- Dependency Checks ---
readonly HELPER_SCRIPT="ssh-host-key-create.sh"
if ! command -v "$HELPER_SCRIPT" &> /dev/null; then
    echo "Error: Helper script '$HELPER_SCRIPT' not found in your PATH." >&2
    echo "Please ensure it is installed and executable (e.g., in /usr/local/bin)." >&2
    exit 1
fi

for f in "$usb_img" "$main_img" "$luks_keyfile" "$ca_priv_key_path" "$ca_pub_key_path"; do
    if [ ! -f "$f" ]; then echo "Error: Required file not found at '$f'" >&2; exit 1; fi
done

# --- Setup ---
readonly MOUNT_ROOT="/mnt/rpi_root_$$"
readonly MOUNT_BOOT="/mnt/rpi_boot_$$"
readonly HOST_KEYS_DIR=$(mktemp -d) # Temp dir for keys
mkdir -p "$MOUNT_ROOT" "$MOUNT_BOOT"

# --- Call Helper Script to Generate and Sign Keys ---
echo "Calling helper script '$HELPER_SCRIPT' to generate and sign SSH host key..."
"$HELPER_SCRIPT" "$ca_priv_key_path" "$hostname" "$ip_address" "$HOST_KEYS_DIR"

# --- Write Images to Devices ---
echo "Writing images..."
dd if="$usb_img" of="$usbdisk" bs=4M status=progress oflag=sync
dd if="$main_img" of="$maindisk" bs=4M status=progress oflag=sync
partprobe "$usbdisk"; partprobe "$maindisk"; sleep 1

# --- Repair GPT to use the full disk space ---
echo "Repairing GPT on both disks to utilize all available space..."
sgdisk -e "$usbdisk"
sgdisk -e "$maindisk"
partprobe "$usbdisk"; partprobe "$maindisk"; sleep 1

# --- Mount Devices and Resize ---
echo "Unlocking disks..."
main_part=$(blkid -L encrypted-root);
boot_part=$(blkid -L RPI-BOOT)

if [ -z "$main_part" ] || [ -z "$boot_part" ]; then
    echo "Error: Could not find partitions by label 'encrypted-root' or 'RPI-BOOT'." >&2
    echo "Labels might not be set correctly in the source images, or udev needs more time." >&2
    exit 1
fi

cryptsetup luksOpen "$main_part" "rpi_encrypted_root_$$" --key-file "$luks_keyfile"

# --- Repair partitions ---
echo "Repairing partitions"


# --- Resize Partition, LUKS Volume, and Filesystem to Fill Disk ---
echo "Resizing partition and filesystem to fill the entire disk..."
parted -s "$maindisk" resizepart 1 100%
partprobe "$maindisk"
cryptsetup resize "rpi_encrypted_root_$$" --key-file "$luks_keyfile"
echo "Running filesystem check before resize..."
e2fsck -f "/dev/mapper/rpi_encrypted_root_$$"
echo "Filesystem check complete. Now resizing..."
resize2fs "/dev/mapper/rpi_encrypted_root_$$"
echo "Resize complete."

echo "Resize complete."

# --- Mount Filesystems ---
mount "/dev/mapper/rpi_encrypted_root_$$" "$MOUNT_ROOT"
mount "$boot_part" "$MOUNT_BOOT"
echo "Devices mounted."

# --- Apply Customizations ---
echo "Applying customizations..."
# 1. Hostname
echo "$hostname" > "$MOUNT_ROOT/etc/hostname"
echo "$ip_address $hostname" >> "$MOUNT_ROOT/etc/hosts"

# 2. Network
echo "Configuring static IP: $ip_cidr..."
mkdir -p "$MOUNT_ROOT/etc/NetworkManager/system-connections"
cat > "$MOUNT_ROOT/etc/NetworkManager/system-connections/eth0.nmconnection" << EOF
[connection]
id=eth0
type=ethernet
interface-name=eth0
[ethernet]
[ipv4]
method=manual
addresses=$ip_cidr
gateway=$gateway
[ipv6]
method=disabled
EOF
chmod 600 "$MOUNT_ROOT/etc/NetworkManager/system-connections/eth0.nmconnection"
rm -f "$MOUNT_ROOT/etc/systemd/system/multi-user.target.wants/dhcpcd.service"
ln -sf /lib/systemd/system/NetworkManager.service "$MOUNT_ROOT/etc/systemd/system/multi-user.target.wants/NetworkManager.service"
echo "net.ipv4.conf.all.src_valid_mark=1" >> $MOUNT_ROOT/etc/sysctl.conf
echo "net.ipv4.ip_forward=1" >> $MOUNT_ROOT/etc/sysctl.conf

# 3. Root Password and systemuser
# By creating a second user through userconf.txt, we get rid of the prompt asking to create a user on boot (which would allow anyone with physical access to create a user) and we also get rid of other nasty messages
echo "Setting root password and systemuser..."
encrypted_pass=$(echo "$rootpass" | openssl passwd -6 -stdin)
sed -i "s|^root:[^:]*|root:${encrypted_pass}|" "$MOUNT_ROOT/etc/shadow"
echo "systemuser:${encrypted_pass}" > "$MOUNT_BOOT/userconf.txt"
chmod 440 "$MOUNT_BOOT/userconf.txt"

if [ ! -f "$MOUNT_BOOT/userconf.txt" ]; then
    echo "Error: userconf.txt not found in $MOUNT_BOOT ! *************************"
fi

# 4. SSH Configuration (using keys from helper script)
echo "Configuring SSH with Certificate Authority and signed host keys..."
mkdir -p "$MOUNT_ROOT/etc/ssh"
cp "$HOST_KEYS_DIR/ssh_host_ed25519_key" "$MOUNT_ROOT/etc/ssh/"
cp "$HOST_KEYS_DIR/ssh_host_ed25519_key.pub" "$MOUNT_ROOT/etc/ssh/"
cp "$HOST_KEYS_DIR/ssh_host_ed25519_key-cert.pub" "$MOUNT_ROOT/etc/ssh/"
cp "$ca_pub_key_path" "$MOUNT_ROOT/etc/ssh/ca.pub"

sed -i '/#---START RPI-IMAGER CUSTOM CONFIG---#/,/#---END RPI-IMAGER CUSTOM CONFIG---#/d' "$MOUNT_ROOT/etc/ssh/sshd_config"
cat >> "$MOUNT_ROOT/etc/ssh/sshd_config" << EOF
#---START RPI-IMAGER CUSTOM CONFIG---#
TrustedUserCAKeys /etc/ssh/ca.pub
PermitRootLogin prohibit-password
HostKey /etc/ssh/ssh_host_ed25519_key
HostCertificate /etc/ssh/ssh_host_ed25519_key-cert.pub
#---END RPI-IMAGER CUSTOM CONFIG---#
EOF
chmod 600 "$MOUNT_ROOT/etc/ssh/ssh_host_ed25519_key"
chmod 644 "$MOUNT_ROOT/etc/ssh/ssh_host_ed25519_key.pub" "$MOUNT_ROOT/etc/ssh/ssh_host_ed25519_key-cert.pub" "$MOUNT_ROOT/etc/ssh/ca.pub"

# --- Final Sync ---
sync
echo "Customization complete. Unmounting devices..."

# --- Cleanup ---
echo "Performing cleanup..."
umount -l "$MOUNT_ROOT" || true
umount -l "$MOUNT_BOOT" || true
cryptsetup luksClose "rpi_encrypted_root_$$" || true
rm -rf "$MOUNT_ROOT" "$MOUNT_BOOT" "$HOST_KEYS_DIR"
echo "Cleanup complete."
