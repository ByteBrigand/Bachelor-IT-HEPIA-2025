#!/bin/bash
set -euo pipefail

# Check if ssh-user-key-sign.sh exists in the same directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SIGN_SCRIPT="${SCRIPT_DIR}/ssh-user-key-sign.sh"

if [ ! -f "${SIGN_SCRIPT}" ]; then
    echo "Error: ssh-user-key-sign.sh not found in ${SCRIPT_DIR}" >&2
    exit 1
fi

# Function to clean up temporary files
cleanup() {
    rm -f "${TEMP_DIR}"/*
    rmdir "${TEMP_DIR}"
}

# Create temporary directory
TEMP_DIR=$(mktemp -d)
trap cleanup EXIT

# Prompt for CA key path
read -p "Enter path to CA key [~/.ssh/ca]: " CA_KEY
CA_KEY=${CA_KEY:-~/.ssh/ca}
CA_KEY="${CA_KEY/#\~/$HOME}"

if [ ! -f "${CA_KEY}" ]; then
    echo "Error: CA key not found at ${CA_KEY}" >&2
    exit 1
fi

# Prompt for mode selection
echo "Select mode:"
echo "1) Single key"
echo "2) Batch processing"
read -p "Enter choice [1]: " MODE
MODE=${MODE:-1}

case "${MODE}" in
    1)
        # Single key mode
        read -p "Enter principal (username): " PRINCIPAL
        
        echo "Paste the public key (then press Ctrl+D):"
        TEMP_PUBKEY="${TEMP_DIR}/id_ed25519.pub"
        cat > "${TEMP_PUBKEY}"
        
        # Verify the public key format
        if ! grep -q "^ssh-" "${TEMP_PUBKEY}"; then
            echo "Error: Invalid public key format. Key must start with 'ssh-'" >&2
            cat "${TEMP_PUBKEY}"
            exit 1
        fi
        
        read -p "Save certificate to file? [y/N]: " SAVE_TO_FILE
        
        if [[ "${SAVE_TO_FILE,,}" == "y" ]]; then
            read -p "Enter output path: " OUTPUT_PATH
            # Run the sign script with output path
            if ! "${SIGN_SCRIPT}" "${CA_KEY}" "${TEMP_PUBKEY}" "${PRINCIPAL}" "${OUTPUT_PATH}"; then
                echo "Error: Certificate signing failed" >&2
                exit 1
            fi
            echo -e "\nSaved certificate content:"
            cat "${OUTPUT_PATH}"
        else
            # Just let the script output to terminal
            if ! "${SIGN_SCRIPT}" "${CA_KEY}" "${TEMP_PUBKEY}" "${PRINCIPAL}"; then
                echo "Error: Certificate signing failed" >&2
                exit 1
            fi
        fi
        ;;
        
    2)
        # Batch mode
        echo "Enter path to directory containing public keys"
        echo "Files should be named: id_ed25519_username.pub"
        read -p "Input directory [./keys]: " INPUT_DIR
        INPUT_DIR=${INPUT_DIR:-./keys}
        
        read -p "Output directory [./certs]: " OUTPUT_DIR
        OUTPUT_DIR=${OUTPUT_DIR:-./certs}
        
        # Create directories if they don't exist
        mkdir -p "${INPUT_DIR}" "${OUTPUT_DIR}"
        
        echo "Place public keys in ${INPUT_DIR} and press Enter to continue..."
        read -r
        
        if ! "${SIGN_SCRIPT}" "${CA_KEY}" --batch "${INPUT_DIR}" "${OUTPUT_DIR}"; then
            echo "Error: Batch processing failed" >&2
            exit 1
        fi
        
        # Show all generated certificates
        echo -e "\nGenerated certificates:"
        for cert in "${OUTPUT_DIR}"/*-cert.pub; do
            echo -e "\nFile: $(basename "${cert}")"
            echo "===================="
            cat "${cert}"
            echo "===================="
        done
        ;;
        
    *)
        echo "Invalid choice" >&2
        exit 1
        ;;
esac
