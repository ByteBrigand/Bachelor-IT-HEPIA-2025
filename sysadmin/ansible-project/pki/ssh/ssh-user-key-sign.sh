#!/bin/bash
set -euo pipefail

# set certificate duration in weeks
DURATION=26w

usage() {
    echo "Usage: $0 ca_key [public_key_path] [principal] [output_path]" >&2
    echo "       $0 ca_key --batch [input_directory] [output_directory]" >&2
    echo "Example: $0 ~/.ssh/ca" >&2
    echo "Example: $0 ~/.ssh/ca id_ed25519.pub alice" >&2
    echo "Example: $0 ~/.ssh/ca id_ed25519.pub alice id_ed25519-cert.pub" >&2
    echo "Example: $0 ~/.ssh/ca --batch ./keys ./certs" >&2
    echo
    echo "Single key mode:"
    echo "Ask users to generate a SSH key pair:"
    echo "  ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519 -C \"your.email@example.com\""
    echo "This will create:"
    echo "  - Private key: ~/.ssh/id_ed25519"
    echo "  - Public key:  ~/.ssh/id_ed25519.pub"
    echo "The public key id_ed25519.pub must be provided for signing"
    echo "The public key id_ed25519-cert.pub is returned to the user where they place it at ~/.ssh/id_ed25519-cert.pub"
    echo
    echo "Batch mode:"
    echo "Input files should be named: id_ed25519_username.pub"
    echo "Output files will be named: id_ed25519_username-cert.pub"
    exit 1
}

process_single_key() {
    local CA_KEY="$1"
    local PUBLIC_KEY="$2"
    local PRINCIPAL="$3"
    local OUTPUT_PATH="$4"

    # Get the directory and base name of the public key
    local KEY_DIR=$(dirname "${PUBLIC_KEY}")
    local KEY_BASE=$(basename "${PUBLIC_KEY}" .pub)

    # Sign the public key
    if ! ssh-keygen -s "${CA_KEY}" \
        -I "${PRINCIPAL}" \
        -n "${PRINCIPAL}" \
        -V "+${DURATION}" \
        "${PUBLIC_KEY}"; then
        echo "Error: ssh-keygen failed to sign the key" >&2
        return 1
    fi

    # Get the path of the generated certificate
    local CERT_PATH="${KEY_DIR}/${KEY_BASE}-cert.pub"

    # Handle output
    if [ -n "${OUTPUT_PATH}" ]; then
        # Move to specified output location
        if ! mv "${CERT_PATH}" "${OUTPUT_PATH}"; then
            echo "Error: Failed to move certificate to output location" >&2
            return 1
        fi
        echo "Certificate saved to: ${OUTPUT_PATH}"
    else
        # Output to terminal
        echo -e "\nSigned certificate:"
        echo "===================="
        cat "${CERT_PATH}"
        echo "===================="
    fi
}



process_batch() {
    local CA_KEY="$1"
    local INPUT_DIR="${2:-.}"
    local OUTPUT_DIR="${3:-.}"

    # Create output directory if it doesn't exist
    mkdir -p "${OUTPUT_DIR}"

    # Find all public keys matching the pattern
    find "${INPUT_DIR}" -name "id_ed25519_*.pub" | while read -r pubkey; do
        # Extract username from filename
        local basename=$(basename "${pubkey}")
        local username=${basename#id_ed25519_}
        username=${username%.pub}

        echo "Processing certificate for user: ${username}"

        # Define output path
        local output_cert="${OUTPUT_DIR}/id_ed25519_${username}-cert.pub"

        # Process the key
        process_single_key "${CA_KEY}" "${pubkey}" "${username}" "${output_cert}"

        logger -t "ssh-user-cert" "Successfully completed certificate generation for ${username}"
    done
}

if [ "$#" -lt 1 ]; then
    usage
fi

CA_KEY="$1"

# Check if CA exists
if [ ! -f "${CA_KEY}" ]; then
    echo "CA key not found at ${CA_KEY}" >&2
    exit 1
fi

if [ "$#" -ge 2 ] && [ "$2" = "--batch" ]; then
    # Batch mode
    INPUT_DIR="${3:-.}"
    OUTPUT_DIR="${4:-.}"
    
    logger -t "ssh-user-cert" "Executing batch mode: $0 $CA_KEY --batch $INPUT_DIR $OUTPUT_DIR"
    
    if [ ! -d "${INPUT_DIR}" ]; then
        echo "Input directory not found: ${INPUT_DIR}" >&2
        exit 1
    fi
    
    process_batch "${CA_KEY}" "${INPUT_DIR}" "${OUTPUT_DIR}"
    
    echo
    echo "Batch processing complete. Please ensure to set proper permissions:"
    echo "chmod 644 ${OUTPUT_DIR}/id_ed25519_*-cert.pub"
else
    # Single key mode
    PUBLIC_KEY=""
    PRINCIPAL=""
    OUTPUT_PATH=""

    logger -t "ssh-user-cert" "Executing: $0 $CA_KEY $PUBLIC_KEY $PRINCIPAL $OUTPUT_PATH"

    # Handle public key input
    if [ "$#" -ge 2 ] && [ -n "$2" ]; then
        if [ ! -f "$2" ]; then
            echo "Public key file not found at $2" >&2
            exit 1
        fi
        PUBLIC_KEY="$2"
    else
        echo "Please paste the public key (then press Ctrl+D):"
        PUBLIC_KEY=$(mktemp)
        cat > "${PUBLIC_KEY}"
    fi

    # Handle principal input
    if [ "$#" -ge 3 ] && [ -n "$3" ]; then
        PRINCIPAL="$3"
    else
        read -p "Enter principal (username): " PRINCIPAL
    fi

    # Handle output path
    if [ "$#" -ge 4 ] && [ -n "$4" ]; then
        OUTPUT_PATH="$4"
        OUTPUT_DIR=$(dirname "${OUTPUT_PATH}")
        mkdir -p "${OUTPUT_DIR}"
    fi

    process_single_key "${CA_KEY}" "${PUBLIC_KEY}" "${PRINCIPAL}" "${OUTPUT_PATH}"

    # Cleanup temporary files
    if [ ! "$#" -ge 2 ]; then
        rm -f "${PUBLIC_KEY}"
    fi

    logger -t "ssh-user-cert" "Successfully completed certificate generation for ${PRINCIPAL}"

    echo
    echo "Instructions for ${PRINCIPAL}:"
    echo "1. Place the certificate next to your private key"
    echo "2. Ensure correct permissions:"
    echo "   chmod 600 ~/.ssh/id_ed25519"
    echo "   chmod 644 ~/.ssh/id_ed25519.pub"
    echo "   chmod 644 ~/.ssh/id_ed25519-cert.pub"
fi
