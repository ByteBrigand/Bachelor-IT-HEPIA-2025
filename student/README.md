# Student Environment Setup Guide

## Initial Setup

1. If you don't receive an ed25519 key pair, create an ed25519 key pair and send the public key to your professor/sysadmin for signing. You can use the following command to create a key pair:
```bash
ssh-keygen -t ed25519
```

2. After receiving your signed key, place it alongside your private key.
3. Place the received `ca.pub` key in `~/.ssh/ca.pub` and run:
```bash
echo "@cert-authority * $(cat ~/.ssh/ca.pub)" >> ~/.ssh/known_hosts
```


## Credentials and Configuration

You will receive a `[user]_client-wg1.conf` file containing WireGuard IPs of all containers.
You may need to edit endpoints and ports if you are not in the cluster network.

## Establishing Connection

1. Install required package:
```bash
sudo apt install wireguard-tools  # or equivalent for your distribution
```

2. Configure WireGuard:
Place `[user]_client-wg1.conf` into `/etc/wireguard/wg1.conf` and start the tunnel:
```bash
cp *client-wg1.conf /etc/wireguard/wg1.conf
sudo wg-quick up wg1
```

3. Test connectivity:
```bash
ping 10.10.5.1 # First ping may take up to 30 seconds
ping 10.10.5.2
ping 10.10.5.3
```

4. Connect via SSH:
```bash
ssh [username]@10.10.5.1
```

Note: Container IPs are sequential in wg1 (e.g., for 4 nodes: 10.10.5.1 through 10.10.5.4)

## Access and Privileges

- SSH should connect without host verification or password prompts
- Elevate privileges using `sudo`:
```bash
sudo su
```

## Network Interfaces

Check for created interfaces:
```bash
ip a
```

Expected interfaces (initially down, activated by Cuttlefish when VMs launch):
- cvd-ebr
- cvd-wbr
- cvd-etap-01
- cvd-mtap-01
- cvd-wtap-01
- cvd-wifiap-01

## Storage

- `/shared`: GlusterFS-backed directory shared across all containers
  - Not suitable for high IOPS operations
  - Compress (tar.gz) directories with many files before copying to reduce IOPS load
- `/root` and `/shared`: Semi-persistent storage
- All other directories: Temporary storage, cleared on container restart

**Important:** These machines can be wiped at any time without notice. There are no backups. If you have any important data, immediately copy it to your own workstation. Do not rely on the cluster for data storage.
An automated script may delete one random file from both `/root` and `/shared` directories every week-end.

## WireGuard Gateway Masquerading

When connecting to a container that's isolated from the internet, your workstation needs to act as its gateway. This means:
- All container's outbound traffic goes through your workstation first
- Your workstation forwards and masquerades this traffic to the internet
- Return traffic comes back to your workstation, which forwards it back to the container

This setup doubles bandwidth usage (download to you, then upload to container), but it provides easier system administration and logging control.

### IP forwarding

Enable IP forwarding (required for all firewall solutions):

1. Enable immediately:
```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
```

2. Make it persistent:
```bash
echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
sysctl -p
```

### NFTables (Modern Recommended Method)

1. Check if nftables is installed:
```bash
which nft
```

2. Install if needed:
- Debian/Ubuntu: `apt install nftables`
- Fedora: `dnf install nftables`
- Arch: `pacman -S nftables`

3. Configure masquerading:
```bash
nft 'add table ip nat'
nft 'add chain ip nat POSTROUTING { type nat hook postrouting priority 100; policy accept; }'
nft 'add rule ip nat POSTROUTING ip saddr 10.10.5.0/24 counter masquerade'

Save configuration
```bash
nft list ruleset > /etc/nftables.conf
```

4. Enable and start service:
```bash
systemctl enable nftables
systemctl start nftables
```

### IPTables (Legacy Method)

1. Check if iptables is installed:
```bash
which iptables
```

2. Configure masquerading on your computer:
```bash
iptables -t nat -A POSTROUTING -s 10.10.5.0/24 -j MASQUERADE
```

3. Save rules (method varies by distribution):
- Debian/Ubuntu: `iptables-save > /etc/iptables/rules.v4`
- Other: `iptables-save > /etc/iptables.rules`

### UFW (Ubuntu/Debian Simple Firewall)

1. Reset UFW:
```bash
ufw --force reset
```

2. Configure forwarding:
```bash
echo 'net/ipv4/ip_forward=1' | sudo tee -a /etc/ufw/sysctl.conf
```

3. Configure masquerading:
To edit `/etc/default/ufw` run:
```bash
sed -i 's/DEFAULT_FORWARD_POLICY="DROP"/DEFAULT_FORWARD_POLICY="ACCEPT"/' /etc/default/ufw
```

To edit `/etc/ufw/before.rules` run:
```bash
cat << 'EOF' >> /etc/ufw/before.rules
*nat
:POSTROUTING ACCEPT [0:0]
-A POSTROUTING -s 10.10.5.0/24 -j MASQUERADE
COMMIT
EOF
```

4. Enable UFW:
```bash
ufw --force enable
```

### Verification

Test connectivity from a container:
```bash
ping 9.9.9.9
curl ifconfig.me
```

## Building AOSP (optional)
If you decide to build your own AOSP, please find instructions at `https://source.android.com/docs/setup/start` and if you build with `make dist` the files will be in `[aosp_directory]/out/dist/aosp_cf_arm64_only_phone-img-root.zip` and `[aosp_directory]/out/dist/cvd-host_package.tar.gz`
Example:
```bash
sudo apt-get install git-core gnupg flex bison build-essential zip curl zlib1g-dev libc6-dev-i386 x11proto-core-dev libx11-dev lib32z1-dev libgl1-mesa-dev libxml2-utils xsltproc unzip fontconfig
curl -o /usr/local/bin/repo https://storage.googleapis.com/git-repo-downloads/repo
chmod +x /usr/local/bin/repo
mkdir aosp-15-r36
repo init -u https://android.googlesource.com/platform/manifest -b android-15.0.0_r36
repo sync -c -j4
source build/envsetup.sh
lunch aosp_cf_arm64_only_phone-aosp_current-userdebug
make dist -j4
ls -l out/dist/aosp_cf_arm64_only_phone-img-root.zip
ls -l out/dist/cvd-host_package.tar.gz
```
To build that, you'll need at least 8 GB of RAM, 64 GB of SWAP, 400 GB of disk space. Better if you have 64 GB of RAM. You must build on ext4, as the build process does some specific ext4 manipulations. It must be arm64_only or it won't run on the RPi 5.
Building AOSP could take 16 hours! Easier to download prebuilt binaries from `https://ci.android.com`.
Example: Go to `https://ci.android.com/builds/submitted/13263448/aosp_cf_arm64_only_phone-userdebug/latest` and look for `aosp_cf_arm64_only_phone-img-13263448.zip` and `cvd-host_package.tar.gz` then rename to `aosp_cf_arm64_only.zip`



## Ansible Setup

### Prerequisites

1. Install required packages:
```bash
sudo apt install sshpass python3-pip yq
python3 -m pip install ansible # if you run this as root which is not recommended, use a venv, or add --break-system-packages flag
```

### Ansible Project Setup

1. Place the following files in your ansible-project directory:
   - `[username]_client-wg1.conf` - Your WireGuard configuration
   - `aosp_cf_arm64_only.zip` - AOSP binaries renamed
   - `cvd-host_package.tar.gz` - Android Cuttlefish binaries


2. Generate the ansible inventory:
```bash
./create-inventory.sh [username] [path/to/wg1.conf]
```
Note: it will use the wireguard file to generate the inventory.

3. Test connectivity and sudo access:
```bash
ansible-playbook -i inventory.yml test_connectivity.yml
```

4. Deploy the android cuttlefish VM:
```bash
ansible-playbook -i inventory.yml deploy_cuttlefish.yml
```
This will copy `aosp_cf_arm64_only.zip` and `cvd-host_package.tar.gz`, unpack them, start the android cuttlefish VM, and test that fuzzing works on the android VM. It should output that it has found at least one crash.

The ADB sync service runs every 2 minutes and is located at `/usr/local/bin/adb-sync.sh` : it pulls and pushes to/from `/shared/shared_files` on the container and `/sdcard/shared_files` on the android cuttlefish device. It may take up to 5 minutes for a full two-way synchronization.
In case of a conflict, the most recent files are kept. The AFL++ instances will communicate with each other through this shared medium. Logging available at `/var/log/afl-sync.log`.


The service `/usr/local/bin/adb-master-afl-monitor.sh` runs every 2 minutes and will take care of ensuring that a master AFL++ instance is running on the master and that only slaves are running on a slave host. The file `/shared/master` contains the hostname of the current master, checked against `/info/hostname`. Logging available at `/var/log/afl-monitor.log`.

There is a web interface for manipulating the Android screen. It works on Chromium and derivatives and is available at https://[host]:8443, example: https://10.10.5.1:8443
During connection accept the security exception for the SSL certificate and activate the screen. At the time of writing it's a white button with "connect" written on it.

## Analyzing an APK

These tools are provided for APK analysis: JADX, Androguard, Ghidra, Frida and GDB.

An example workflow is given in `example-apk-analysis.sh`.

For debugging manually, GDB is provided in `/usr/local/share/gdb-android.tar.gz`. If you ran `deploy_cuttlefish.yml`, it has been placed in `/data/local/tmp/` with executable paths `/data/local/tmp/gdb-android/gdb` and `/data/local/tmp/gdb-android/gdbserver`.

Function tracing of an APK can be done using Frida. Please refer to this guide: https://frida.re/docs/android/

## Fuzzing

### Black-box fuzzing

Please refer to this guide: https://blog.quarkslab.com/android-greybox-fuzzing-with-afl-frida-mode.html
The frida library should already be on the device if you ran `deploy_cuttlefish.yml`, at `/data/local/tmp/afl-android/lib/afl/afl-frida-trace.so`.

### White-box fuzzing

Two builds of AFL++ are present, one in `/usr/local/{bin,lib/afl,include/afl}` that can be run on the RPi 5, and one built for Android in `/opt/afl-android`, the latter is copied to `/data/local/tmp/afl-android` on the android cuttlefish device when running the `deploy_cuttlefish.yml` playbook.

A script for compiling targets against android is provided in `/usr/local/bin/afl-clang-android` and can be used like so:
```bash
/usr/local/bin/afl-clang-android fuzzme.c -o fuzzme
```
It will produce a binary that can be fuzzed on Android.


An ansible playbook is provided that will copy `fuzzme.c` from your workstation to the hosts, compile it, place it inside `/data/local/tmp/` on the android cuttlefish VM and start fuzzing in distributed fashion, using `/sdcard/shared_files` on the Android device as working directory for AFL++, which is used to synchronize between instances on different hosts.

To start fuzzing:
```bash
ansible-playbook -i inventory.yml start_fuzzing.yml 
```

To stop fuzzing:
```bash
ansible-playbook -i inventory.yml stop_fuzzing.yml 
```

### Monitor progress

You can use the following command on a machine to check distributed fuzzing progress:
```bash
adb shell /data/local/tmp/afl-android/bin/afl-whatsup -d /sdcard/shared_files/output
```