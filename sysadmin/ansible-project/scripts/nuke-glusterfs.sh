#!/bin/bash
# This script completely removes GlusterFS and all its data from a node.
# It is designed to be called by an Ansible playbook.

set -euox

# Stop all gluster volumes first
echo "--> Stopping all GlusterFS volumes..."
for volume in $(gluster volume list 2>/dev/null); do
    echo "Stopping volume: $volume"
    gluster --mode=script volume stop $volume force || true
    gluster --mode=script volume delete $volume || true
done

# Stop all services and kill processes
echo "--> Stopping and disabling GlusterFS services..."
systemctl stop glusterd || true
systemctl disable glusterd || true
killall glusterfs glusterfsd glusterd || true

# Unmount any gluster mounts to prevent busy errors
echo "--> Force unmounting potential GlusterFS mounts..."
# Remove from fstab first to prevent auto-remount
sed -i '/glusterfs/d' /etc/fstab

# Unmount all gluster mounts
grep -v '^#' /etc/mtab | grep glusterfs | while read -r line; do
    mount_point=$(echo "$line" | awk '{print $2}')
    echo "Unmounting: $mount_point"
    umount -fl "$mount_point" 2>/dev/null || true
done

# Specific unmounts for known paths
umount -fl /mnt/shared || true
umount -fl /data/glusterfs/shared || true

# Purge packages
echo "--> Purging all GlusterFS packages..."
apt-get remove --purge -y glusterfs-server glusterfs-client glusterfs-common glusterd*
apt-get autoremove --purge -y

# Delete all data and configuration directories
echo "--> Deleting all GlusterFS data and configuration..."
rm -rf /var/lib/glusterd
rm -rf /etc/glusterfs
rm -rf /var/log/glusterfs
rm -rf /var/run/gluster
rm -rf /mnt/shared      # Deletes the mount point
#rm -rf /data/glusterfs  # Deletes the parent brick directory - commented out for safety

# Remove any remaining configuration files
find /etc -name '*gluster*' -exec rm -rf {} + 2>/dev/null || true

# Clean package cache
apt-get clean

echo "--> GlusterFS has been successfully nuked from this system."

# Uncomment these lines if you want to automatically reinstall GlusterFS
#echo "--> Reinstalling GlusterFS..."
#apt update
#apt install -y glusterfs-common --reinstall
#apt install -y glusterfs-server --reinstall
#apt install -y glusterfs-client --reinstall