#!/bin/bash

#=================================================================================
# ssh-host-key-create.sh
#
# Description:
#   Generates an SSH host key and signs it with a specified Certificate
#   Authority (CA) private key. This creates a host certificate that allows
#   clients to trust the host without needing to manually verify its fingerprint.
#
# Parameters:
#   1. Path to CA Private Key:   (e.g., /etc/ssh/ca/ssh_host_ca_key)
#   2. Hostname:                 The primary hostname for the certificate.
#   3. IP Address:               The IP address for the certificate.
#   4. Output Directory:         Directory to save the generated key files.
#
# Example:
#   ./ssh-host-key-create.sh \
#     /path/to/my_ca_private_key \
#     mypi 192.168.1.100 \
#     ./temp-host-keys
#
#=================================================================================

set -e

# --- Parameter Validation ---
if [ "$#" -ne 4 ]; then
    echo "Usage: $0 <ca_private_key_path> <hostname> <ip_address> <output_directory>"
    exit 1
fi

readonly CA_PRIV_KEY_PATH=$1
readonly HOSTNAME=$2
readonly IP_ADDRESS=$3
readonly OUTPUT_DIR=$4

# --- Dependency Check ---
if ! command -v ssh-keygen &> /dev/null; then
    echo "Error: ssh-keygen command not found. Please install OpenSSH."
    exit 1
fi

# --- Input Validation ---
if [ ! -f "$CA_PRIV_KEY_PATH" ]; then
    echo "Error: CA private key not found at '$CA_PRIV_KEY_PATH'" >&2
    exit 1
fi

mkdir -p "$OUTPUT_DIR"

# --- Key Generation ---
readonly KEY_PATH="$OUTPUT_DIR/ssh_host_ed25519_key"
echo "Generating new Ed25519 host key..."
# -f specifies file path, -N "" provides an empty passphrase
ssh-keygen -t ed25519 -f "$KEY_PATH" -N "" > /dev/null

# --- Key Signing ---
echo "Signing host public key with CA key..."
# -s: Sign the key with this CA key
# -I: Specify the key's identity (certificate's serial number or identifier)
# -h: Create a host certificate (as opposed to a user certificate)
# -n: Specify the principals (valid hostnames/IPs) for which the cert is valid
ssh-keygen -s "$CA_PRIV_KEY_PATH" \
           -I "${HOSTNAME}_host_key" \
           -h \
           -n "$HOSTNAME,$IP_ADDRESS" \
           "$KEY_PATH.pub"

echo "Host key and certificate successfully created in '$OUTPUT_DIR'."
echo "Files generated:"
echo "  - Private Key: ${KEY_PATH}"
echo "  - Public Key:  ${KEY_PATH}.pub"
echo "  - Certificate: ${KEY_PATH}-cert.pub"