#!/bin/bash

#=================================================================================
# rpi-create-encrypted-images.sh
#
# Description:
#   Creates a pair of disk images for a Raspberry Pi with a full-disk encrypted
#   root filesystem unlocked via an embedded keyfile (passwordless boot).
#
#   This script prepares the generic images. A second script is used to write
#   these images to physical devices and apply host-specific customizations.
#
# Parameters:
#   1. Output Directory:    The directory where usb.img, main.img, and the
#                           LUKS keyfile will be saved.
#   2. Main Image Size:     (Optional) The size of the main encrypted disk
#                           image, e.g., "8G", "30G". Defaults to "15G".
#   3. Path to LUKS Key:    (Optional) Path to an existing LUKS keyfile. If
#                           not provided, a new one will be generated.
#
# Example (Generate new key):
#   sudo ./rpi-create-encrypted-images.sh ./rpi_images 4G
#
# Example (Use existing key):
#   sudo ./rpi-create-encrypted-images.sh ./rpi_images 4G /path/to/my.key
#
#=================================================================================

set -e

# --- Configuration ---
readonly IMAGE_URL="https://downloads.raspberrypi.com/raspios_lite_arm64/images/raspios_lite_arm64-2025-05-13/2025-05-13-raspios-bookworm-arm64-lite.img.xz"
readonly BOOT_IMG_SIZE="512M"
readonly LUKS_MAP_NAME="rpi_encrypted_root"

# --- Parameter Validation ---
if [ "$#" -lt 1 ] || [ "$#" -gt 3 ]; then
    echo "Usage: $0 <output_directory> [main_image_size] [path_to_luks_key]"
    echo "Example: $0 ./rpi_images 4G"
    exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
  echo "This script must be run as root." >&2
  exit 1
fi

readonly OUTPUT_DIR=$1
readonly MAIN_IMG_SIZE=${2:-15G}
readonly PROVIDED_KEY_PATH=$3
readonly IMAGE_DOWNLOAD_DIR="/tmp"

# --- Dependency Checks ---
echo "Checking required dependencies..."
for cmd in qemu-aarch64-static sgdisk parted cryptsetup truncate xz losetup wget rsync; do
    if ! command -v "$cmd" &> /dev/null; then
        echo >&2 "Error: Required command '$cmd' not found."
        exit 1
    fi
done

# --- Setup ---
echo "Setting up directories and temporary environment..."
mkdir -p "$OUTPUT_DIR"
readonly MOUNT_ROOT="/mnt/rpi_root_$$"
readonly MOUNT_BOOT="/mnt/rpi_boot_$$"
readonly MOUNT_SRC_ROOT="/mnt/rpi_src_root_$$"
readonly MOUNT_SRC_BOOT="/mnt/rpi_src_boot_$$"
mkdir -p "$MOUNT_ROOT" "$MOUNT_BOOT" "$MOUNT_SRC_ROOT" "$MOUNT_SRC_BOOT"

# --- Cleanup Function ---
cleanup() {
    echo "Performing cleanup..."
    umount "$MOUNT_ROOT/boot/firmware" || true
    umount "$MOUNT_ROOT/boot" || true
    umount "$MOUNT_ROOT/proc" || true
    umount "$MOUNT_ROOT/sys" || true
    umount "$MOUNT_ROOT/dev/pts" || true
    umount "$MOUNT_ROOT/dev" || true
    umount "$MOUNT_ROOT" || true
    umount "$MOUNT_BOOT" || true
    umount "$MOUNT_SRC_ROOT" || true
    umount "$MOUNT_SRC_BOOT" || true

    if [ -n "$main_loop" ]; then cryptsetup luksClose "$LUKS_MAP_NAME" || true; fi
    if [ -n "$main_loop" ]; then losetup -d "$main_loop" || true; fi
    if [ -n "$usb_loop" ]; then losetup -d "$usb_loop" || true; fi
    if [ -n "$os_loop" ]; then losetup -d "$os_loop" || true; fi

    rm -rf "$MOUNT_ROOT" "$MOUNT_BOOT" "$MOUNT_SRC_ROOT" "$MOUNT_SRC_BOOT"
    echo "Cleanup complete."
}
trap cleanup EXIT

# --- LUKS Keyfile Handling ---
readonly OUTPUT_KEY_PATH="$OUTPUT_DIR/rpi_luks.key"
if [ -n "$PROVIDED_KEY_PATH" ]; then
    if [ ! -f "$PROVIDED_KEY_PATH" ]; then
        echo "Error: Provided LUKS keyfile not found at '$PROVIDED_KEY_PATH'" >&2
        exit 1
    fi
    echo "Using provided LUKS keyfile: $PROVIDED_KEY_PATH"
    cp "$PROVIDED_KEY_PATH" "$OUTPUT_KEY_PATH"
else
    echo "Generating new LUKS keyfile at: $OUTPUT_KEY_PATH"
    openssl rand -base64 32 | tr -dc 'a-zA-Z0-9' > "$OUTPUT_KEY_PATH" # about 256 bits of entropy

fi
chmod 0400 "$OUTPUT_KEY_PATH"

# --- Image Preparation ---
echo "Preparing base system image..."
readonly IMG_XZ_NAME=$(basename "$IMAGE_URL")
readonly IMG_NAME="${IMG_XZ_NAME%.xz}"
readonly IMG_XZ_PATH="$IMAGE_DOWNLOAD_DIR/$IMG_XZ_NAME"
readonly IMG_PATH="$IMAGE_DOWNLOAD_DIR/$IMG_NAME"

if [ ! -f "$IMG_PATH" ]; then
    if [ ! -f "$IMG_XZ_PATH" ]; then
        wget -c -O "$IMG_XZ_PATH" "$IMAGE_URL"
    fi
    echo "Extracting image..."
    xz -d -k "$IMG_XZ_PATH"
fi

# --- Create Target Image Files ---
echo "Creating blank image files..."
readonly USB_IMG_PATH="$OUTPUT_DIR/usb.img"
readonly MAIN_IMG_PATH="$OUTPUT_DIR/main.img"
truncate -s "$BOOT_IMG_SIZE" "$USB_IMG_PATH"
truncate -s "$MAIN_IMG_SIZE" "$MAIN_IMG_PATH"

# --- Setup Loop Devices ---
echo "Setting up loopback devices for image files..."
usb_loop=$(losetup -fP --show "$USB_IMG_PATH")
main_loop=$(losetup -fP --show "$MAIN_IMG_PATH")

# --- Partition USB Image ---
echo "Partitioning and formatting USB image ($usb_loop)..."
parted -s "$usb_loop" mklabel gpt
parted -s -a optimal "$usb_loop" mkpart RPI-BOOT fat32 1MiB 100%
parted -s "$usb_loop" set 1 esp on
sleep 1; partprobe "$usb_loop"
mkfs.fat -F 32 -n "RPI-BOOT" "${usb_loop}p1"

# --- Partition and Encrypt Main Image ---
echo "Partitioning and encrypting main image ($main_loop)..."
sgdisk --clear \
       --new=1:2048:0 --typecode=1:8300 --change-name=1:"encrypted-root" \
       "$main_loop"
sleep 1; partprobe "$main_loop"

echo "Setting up LUKS encryption on ${main_loop}p1 using keyfile..."
cryptsetup -q luksFormat --type luks2 --key-size 256 --label encrypted-root --key-file "$OUTPUT_KEY_PATH" "${main_loop}p1"
cryptsetup luksOpen --key-file "$OUTPUT_KEY_PATH" "${main_loop}p1" "$LUKS_MAP_NAME"

echo "Creating ext4 filesystem on encrypted partition..."
mkfs.ext4 -L "RPI-ROOT" "/dev/mapper/$LUKS_MAP_NAME"

# --- Mount Filesystems ---
echo "Mounting filesystems..."
mount "/dev/mapper/$LUKS_MAP_NAME" "$MOUNT_ROOT"
mount "${usb_loop}p1" "$MOUNT_BOOT"

# --- Copy OS Files ---
echo "Copying OS files from source image..."
os_loop=$(losetup -fP --show "$IMG_PATH")
mount "${os_loop}p1" "$MOUNT_SRC_BOOT"
mount "${os_loop}p2" "$MOUNT_SRC_ROOT"
rsync -ax "$MOUNT_SRC_ROOT/" "$MOUNT_ROOT/"
rsync -ax "$MOUNT_SRC_BOOT/" "$MOUNT_BOOT/"
#mkdir -p "$MOUNT_BOOT/firmware"
#rsync -ax "$MOUNT_SRC_BOOT/" "$MOUNT_BOOT/firmware/"
umount "$MOUNT_SRC_BOOT"; umount "$MOUNT_SRC_ROOT"
losetup -d "$os_loop"; os_loop=""

# --- Configure System for Encrypted Root ---
echo "Configuring fstab, crypttab, initramfs hooks, and boot files..."

# Copy keyfile into the root partition for update-initramfs to use
mkdir -p "$MOUNT_ROOT/crypto"
cp "$OUTPUT_KEY_PATH" "$MOUNT_ROOT/crypto/rpi_luks.key"
chmod 0600 "$MOUNT_ROOT/crypto/rpi_luks.key"

# fstab
cat > "$MOUNT_ROOT/etc/fstab" << EOF
/dev/mapper/$LUKS_MAP_NAME  /               ext4    errors=remount-ro,discard  0  1
LABEL=RPI-BOOT                  /boot/firmware  vfat    defaults           0  2
EOF

# crypttab
# This tells initramfs how to unlock the root partition, 
# it will look for the key according to KEYFILE_PATTERN (on root partition) and copy it into the specified location in crypttab to the initramfs
# if key is at /etc/cc.key on root partition, KEYFILE_PATTERN=/etc/*.key and crypttab has /aa/bb.key, update-initramfs will copy /etc/cc.key and place it at /aa/bb.key in the initramfs
# in this case we use /crypto/rpi_luks.key on both root partition and initramfs simply for consistency
# discard option allows SSD trimming
cat > "$MOUNT_ROOT/etc/crypttab" << EOF
$LUKS_MAP_NAME LABEL=encrypted-root /crypto/rpi_luks.key luks,discard
EOF

# cmdline.txt
echo "console=serial0,115200 console=tty1 root=/dev/mapper/$LUKS_MAP_NAME rootwait cfg80211.ieee80211_regdom=CH" > "$MOUNT_BOOT/cmdline.txt"

# config.txt
cat > "$MOUNT_BOOT/config.txt" << EOF
display_auto_detect=1
auto_initramfs=1
dtoverlay=vc4-kms-v3d
max_framebuffers=2
disable_fw_kms_setup=1
arm_64bit=1
disable_overscan=1
arm_boost=1
[all]
EOF

# Create initramfs hooks and configs
mkdir -p "$MOUNT_ROOT/etc/initramfs-tools/conf.d/"
echo "CRYPTSETUP=y" > "$MOUNT_ROOT/etc/initramfs-tools/conf.d/cryptsetup"

mkdir -p "$MOUNT_ROOT/etc/cryptsetup-initramfs"
echo 'KEYFILE_PATTERN="/crypto/rpi_luks.key"' > "$MOUNT_ROOT/etc/cryptsetup-initramfs/conf-hook" # tells update-initramfs where to find the crypto key
echo 'UMASK=0077' >> "$MOUNT_ROOT/etc/initramfs-tools/initramfs.conf"

# Set permissions to prevent accidental modification
chmod 400 "$MOUNT_ROOT/etc/cryptsetup-initramfs/conf-hook"
chmod 400 "$MOUNT_ROOT/etc/initramfs-tools/conf.d/cryptsetup"
chmod 400 "$MOUNT_ROOT/etc/crypttab"
chmod 400 "$MOUNT_ROOT/etc/initramfs-tools/initramfs.conf"

# --- Chroot and Build Initramfs ---
echo "Preparing chroot and applying system configurations..."
cp /usr/bin/qemu-aarch64-static "$MOUNT_ROOT/usr/bin/"
mount --bind /dev "$MOUNT_ROOT/dev"
mount --bind /dev/pts "$MOUNT_ROOT/dev/pts"
mount --bind /sys "$MOUNT_ROOT/sys"
mount -t proc /proc "$MOUNT_ROOT/proc"

mkdir -p "$MOUNT_ROOT/boot/firmware"
mount --bind "$MOUNT_BOOT" "$MOUNT_ROOT/boot/firmware"

chroot "$MOUNT_ROOT" /usr/bin/qemu-aarch64-static /bin/bash <<CHROOT_SCRIPT
set -e

echo "Configuring locales..."
echo "de_CH.UTF-8 UTF-8" >> /etc/locale.gen
echo "en_US.UTF-8 UTF-8" >> /etc/locale.gen
echo "LANG=en_US.UTF-8" > /etc/default/locale
echo "LC_ALL=en_US.UTF-8" >> /etc/default/locale
locale-gen
update-locale LANG=en_US.UTF-8 LC_ALL=en_US.UTF-8

echo "Enabling ssh..."
systemctl enable ssh

echo "Disabling first-boot services..."
systemctl disable regenerate_ssh_host_keys.service
#systemctl disable userconfig.service

echo "Installing required packages..."
apt-get install -y -o Dpkg::Options::="--force-confold" cryptsetup cryptsetup-initramfs initramfs-tools

echo "Updating initramfs..."
update-initramfs -u -k all
CHROOT_SCRIPT

echo "System configuration inside chroot complete."


# --- Final Sync ---
sync
echo "Image creation successful!"
echo "Images and keyfile are located in: $OUTPUT_DIR"
echo "  - USB Boot Image:       $USB_IMG_PATH"
echo "  - Main Encrypted Image: $MAIN_IMG_PATH"
echo "  - LUKS Keyfile:         $OUTPUT_KEY_PATH"