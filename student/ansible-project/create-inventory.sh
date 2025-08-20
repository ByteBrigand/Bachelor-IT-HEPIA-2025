#!/bin/bash

if [ $# -ne 2 ]; then
    echo "Usage: $0 <username> <path/to/wg1.conf"
    echo "Example:"
    echo "$0 user1 /etc/wireguard/wg1.conf"
    echo ""
    echo "Will create inventory.yml in current directory"
    exit 1
fi

USERNAME="$1"
WG_CONF="$2"


# Check WireGuard config
if [ ! -f "$WG_CONF" ]; then
    echo "Error: $WG_CONF is missing"
    exit 1
fi


# Create initial YAML structure
cat > inventory.yml << EOF
all:
  hosts:
EOF

# Extract IPs from AllowedIPs and create inventory entries
grep "AllowedIPs" "$WG_CONF" | while read -r line; do
    # Extract IP without CIDR notation
    IP=$(echo "$line" | awk -F'=' '{print $2}' | tr -d ' ' | cut -d'/' -f1)
    
    # Add host entry with user and sudo configuration
    cat >> inventory.yml << EOF
    wg-$IP:
      ansible_host: $IP
      ansible_user: $USERNAME
      ansible_become: true
      ansible_become_method: sudo
EOF
done

echo "Inventory file created at inventory.yml"