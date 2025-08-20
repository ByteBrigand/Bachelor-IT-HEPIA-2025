# Raspberry Pi 5 Cluster Deployment Guide

## Certificate Authority

Make sure to read `pki/README.md` first.
Generate a SSH CA on the management workstation.
Make a backup of the private key.

## Prepare Inventory and Users
Edit `inventory.yml` and `vars/main.yml` with the right information.
Start by defining all the usernames in `vars/main.yml`.
Then prepare the inventory along with all wireguard ports for each user.
Hostnames are supposed to be rpi[nn] where nn is the host number. For host 1, it's rpi01.

## Deploying the RPi 5 cluster

### Hardware Requirements
- minimum 4x Raspberry PI 5 (each with 4 cores and 16 GB RAM)
- external SSD of minimum 128 GB for each Pi
- external USB drive of minimum 1 GB for each Pi
- workstation with Debian or Ubuntu for administration

The main partition will encrypted and located on the SSD. The USB drive will contain the boot partition and the LUKS keys necessary for unlocking the main partition. Once booted, you can remove the USB drive and keep it safe. All drives share the same encryption key, allowing any RPi to boot with any USB drive. The encryption key is saved in the initramfs during image creation. A copy is placed on the root drive at `/crypto` to allow updating the initramfs.
The benefit of this setup, running with the boot partition removed, is that it makes evil maid attacks much more difficult.

### Labeling Hardware

Label every Raspberry Pi and their SSDs with hostname and IP, optionally including contact information.

### Creating Master Images
Use the following command to create the master images:
```bash
./rpi-create-encrypted-images.sh rpi_images 4G
```

The script will download Raspberry Pi 5 images, hardcoded in the script to 2025-05-13, modify them and create the following images:
- `rpi_images/usb.img` will contain the boot partition and `initramfs`, which contains the LUKS key.
- `rpi_images/main.img` will contain the main encrypted partition.

### Imaging the Drives
1. Attach an SSD and its corresponding USB drive to your workstation.
2. Use `lsblk` to check where the drives are mounted on `/dev`.
3. If the partitions were mounted by the OS, unmount them with `umount`.
4. Image the drives using the following command:
```bash
./rpi-write-and-customize.sh <main_disk> <usb_disk> <usb_img> <main_img> <luks_key> <hostname> <ip/cidr> <gateway> <ca_priv_key> <ca_pub_key> <root_pass>
```
Example:
```bash
./rpi-write-and-customize.sh /dev/sdb /dev/sdc ./rpi_images/usb.img ./rpi_images/main.img ./rpi_images/rpi_luks.key "rpi03" "10.222.1.23/24" "10.222.1.1" ~/.ssh/ca ~/.ssh/ca.pub supersecret
```

### Booting and Initializing the RPi 5
Put the SSD drive and USB drive into the RPi 5 and boot it. If you see the recovery screen, simply boot it again. The first boot takes about 2 minutes.
It may look stuck looking for the root drive, give it a minute.

You should be able to connect as user `root` and it should not ask to confirm the host. If you are asked for a password, abort, wait a few seconds and try again.
Once you confirm that it logs in without asking for password, it is ready for Ansible.

## Ansible Setup and Execution
Copy `ca.pub` into the `cuttlefish-container` directory.

Install ansible:
```bash
pip install ansible
ansible-galaxy collection install gluster.gluster
```

Install required packages:
```bash
sudo apt install package yq, wireguard-tools, openssh-client
```


### Setup secrets

Create a password for the Ansible vault:
```bash
echo "supersecretpassword" > ~/.vault_pass
chmod 600 ~/.vault_pass
echo "export ANSIBLE_VAULT_PASSWORD_FILE=~/.vault_pass" >> ~/.profile
export ANSIBLE_VAULT_PASSWORD_FILE=~/.vault_pass
```

If you want to test things out, execute `scripts/generate-all-secrets.sh` to generate all the needed keys and certificates. For production, see the scripts in the pki folder.
The script generates these secrets:
- Wireguard configurations for hosts in `secrets/wg_configs/[host]_wg0.conf`
- Wireguard configurations for containers in `secrets/wg_configs/[host]_[user]-wg1.conf`
- Wireguard configurations for users in `secrets/wg_configs/[user]_client-wg1.conf`
- Container Host SSH private keys in `secrets/ssh_keys/ssh_host_[user]_key`
- Container Host SSH public keys in `secrets/ssh_keys/ssh_host_[user]_key.pub`
- Container Host SSH public signed keys in `secrets/ssh_keys/ssh_host_[user]_key-cert.pub`
- User private keys in `secrets/ssh_keys/id_ed25519_[user]`
- User public keys in `secrets/ssh_keys/id_ed25519_[user].pub`
- User public signed keys in `secrets/ssh_keys/id_ed25519_[user]-cert.pub`


By default the firewall is set to deny users all outbound connections except to their own containers. WAN is accessible from their containers through a Wireguard tunnel where the user acts as gateway. Users must be able to connect to their container's Wireguard port. Containers must be able to connect to each other's Wireguard port. These firewall rules are defined in `tasks/system.yml`.
The Ansible playbook will create a full Wireguard mesh between hosts. GlusterFS peers will communicate through the Wireguard VPN.

Run the Ansible playbook:
```bash
ansible-playbook -i inventory.yml playbook.yml --tags all_tasks
```

If GlusterFS fails at creating the shared volume, reboot all hosts and retry.

### Distributing secrets to users
Distribute the secrets to their recipients in a safe manner. You'll find them in the secrets directory.
Clients need to place the following in their `~/.ssh/` directory:
- `secrets/ssh_keys/id_ed25519_[user]`
- `secrets/ssh_keys/id_ed25519_[user].pub`
- `secrets/ssh_keys/id_ed25519_[user]-cert.pub`
- `ca.pub`
Clients should place `secrets/wg_configs/[user]_client-wg1.conf` in `/etc/wireguard/wg1.conf` and activate the tunnel with:
```bash
wg-quick up wg1
```
They may need to modify the endpoint in their Wireguard configuration file and the Sysadmin may need to do some routing and port forwards to make it available to external users.
The Wireguard port is calculated as: 5[host number][user number], to allow access of every container on every host, from one single public IP. Example for host 1 and user 1 : 50101.

IPv6 is not yet implemented.