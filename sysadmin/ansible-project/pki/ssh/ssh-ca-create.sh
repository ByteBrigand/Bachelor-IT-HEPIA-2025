#!/bin/bash
set -euo pipefail

if [ "$#" -gt 2 ]; then
    echo "Usage: $0 [ca_directory] [common_name]" >&2
    echo "Example: $0" >&2
    echo "Example: $0 ~/.ssh/ca" >&2
    echo "Example (default): $0 ~/.ssh/ca 'SSH CA'" >&2
    exit 1
fi


CA_DIR="${1:-$HOME/.ssh}"
COMMON_NAME="${2:-SSH CA}"

logger -t "ssh-ca-setup" "Executing: $0 $CA_DIR $COMMON_NAME"


CA_KEY="${CA_DIR}/ca"
CA_PUB="${CA_DIR}/ca.pub"

# Check if CA already exists
if [ -f "${CA_KEY}" ]; then
    echo "CA key already exists at ${CA_KEY}" >&2
    exit 1
fi

# Create CA directory if it doesn't exist
mkdir -p "${CA_DIR}"

# Generate CA key pair
ssh-keygen -t ed25519 -f "${CA_KEY}" -C "${COMMON_NAME}" -N ""

# Secure the CA key
chmod 600 "${CA_KEY}"
chmod 644 "${CA_PUB}"

logger -t "ssh-ca-setup" "Successfully created CA at ${CA_KEY}"

echo "CA created successfully:"
echo "Private key: ${CA_KEY}"
echo "Public key: ${CA_PUB}"
echo
echo "Server-side Instructions:"
echo "1. Copy the CA public key to /etc/ssh/ca.pub"
echo
echo "2. Add the following line to /etc/ssh/sshd_config:"
echo "   TrustedUserCAKeys /etc/ssh/ca.pub"
echo
echo "3. Restart sshd:"
echo "   systemctl restart sshd"
echo
echo "Client-side Instructions:"
echo "1. Copy the CA public key to ~/.ssh/ca.pub"
echo
echo "2. Add the CA to known_hosts. Choose one of:"
echo "   # Trust CA for all hosts:"
echo "   echo \"@cert-authority * \$(cat ~/.ssh/ca.pub)\" >> ~/.ssh/known_hosts"
echo
echo "   # Trust CA only for specific domain:"
echo "   echo \"@cert-authority *.example.com \$(cat ~/.ssh/ca.pub)\" >> ~/.ssh/known_hosts"
