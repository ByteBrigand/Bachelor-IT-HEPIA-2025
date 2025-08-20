#!/bin/bash

#=================================================================================
# generate-all-secrets.sh
#
# Description:
#   A comprehensive script for managing project secrets, operating in two modes.
#   It reads variables from a separate file (e.g., vars/main.yml)
#
# Modes:
#   --mode generate (default)
#     - Generates all secrets from scratch using an inventory and a vars file.
#     - Saves all secrets as individual files in the './secrets' directory.
#     - Creates and encrypts a vault.yml containing all secrets.
#
#   --mode vault-only
#     - Reads existing secret files from the './secrets' directory structure.
#     - Creates and encrypts a new vault.yml based on the found files.
#
# Parameters (generate mode):
#   1. Path to Ansible Inventory: (e.g., inventory.yml)
#   2. Path to Ansible Vars File: (e.g., vars/main.yml)
#   3. Path to SSH CA Private Key: (e.g., ~/.ssh/ca)
#
# Example (Generate):
#   ./scripts/generate-all-secrets.sh inventory.yml vars/main.yml ~/.ssh/ca
#
# Example (Vault Only):
#   ./scripts/generate-all-secrets.sh --mode vault-only
#
#=================================================================================

set -euo pipefail

usage() {
    echo "Usage: $0 [--mode <generate|vault-only>] [inventory.yml] [vars.yml] [ca_key_path]"
    echo ""
    echo "Modes:"
    echo "  generate      (Default) Generate all files and the vault."
    echo "                Requires inventory.yml, vars.yml, and the CA private key."
    echo ""
    echo "  vault-only    Create vault.yml from existing files in ./secrets."
    echo "                Does not require any additional arguments."
    exit 1
}

# --- Parse Mode ---
MODE="generate"
if [ "$#" -gt 0 ]; then
    if [ "$1" == "--mode" ]; then
        if [ -z "$2" ]; then usage; fi
        MODE="$2"
        shift 2
    fi
fi

# =================================================================
# ===== VAULT-ONLY MODE ===========================================
# =================================================================
if [ "$MODE" == "vault-only" ]; then
    echo "Running in 'vault-only' mode..."
    readonly OUTPUT_DIR="./secrets"
    readonly VAULT_FILE="$OUTPUT_DIR/vault.yml"
    readonly SSH_DIR="$OUTPUT_DIR/ssh_keys"
    readonly WG_PRIV_DIR="$OUTPUT_DIR/wg_privkeys"

    if [ ! -d "$OUTPUT_DIR" ]; then
        echo "Error: Directory '$OUTPUT_DIR' not found. Cannot create vault." >&2
        exit 1
    fi

    readonly TEMP_VAULT_FILE=$(mktemp)
    trap 'rm -f "$TEMP_VAULT_FILE"' EXIT
    echo "---" > "$TEMP_VAULT_FILE"
    echo "# Assembled from existing files by generate-all-secrets.sh on $(date)" >> "$TEMP_VAULT_FILE"

    echo "Assembling vault from files in '$OUTPUT_DIR'..."

    # --- Read WireGuard Private Keys ---
    if [ -d "$WG_PRIV_DIR" ]; then
        echo "# WireGuard Private Keys" >> "$TEMP_VAULT_FILE"
        for keyfile in "$WG_PRIV_DIR"/*.key; do
            [ -e "$keyfile" ] || continue
            basename=$(basename "$keyfile" .key)
            if [[ "$basename" == "rpi"* ]]; then
                var_name="vault_wg_private_key_${basename//-/_}"
            elif [[ "$basename" == *"_client" ]]; then
                user=${basename%_client}
                var_name="vault_wg_private_key_${user}"
            elif [[ "$basename" =~ ^([^_]+)_([^_]+)_container$ ]]; then
                host="${BASH_REMATCH[1]}"
                user="${BASH_REMATCH[2]}"
                var_name="vault_wg_private_key_container_${host//-/_}_${user}"
            else
                echo "Warning: Unrecognized WG key file format: $keyfile"
                continue
            fi
            echo "Found WG key: $keyfile -> $var_name"
            echo "${var_name}: \"$(cat "$keyfile")\"" >> "$TEMP_VAULT_FILE"
        done
    fi

    # --- Read SSH Keys ---
    if [ -d "$SSH_DIR" ]; then
        echo "" >> "$TEMP_VAULT_FILE"
        echo "# SSH Keys" >> "$TEMP_VAULT_FILE"
        for keyfile in "$SSH_DIR"/*; do
            [ -e "$keyfile" ] || continue
            filename=$(basename "$keyfile")
            if [[ "$filename" == "ssh_host_"* ]]; then
                user_part=$(echo "$filename" | sed -E 's/ssh_host_([a-zA-Z0-9]+)_key(-cert.pub|.pub)?/\1/')
                type_part=$(echo "$filename" | sed -E 's/.*_key(-cert.pub|.pub)?/\1/')
                suffix=""
                if [[ "$type_part" == ".pub" ]]; then suffix="_pub"; fi
                if [[ "$type_part" == "-cert.pub" ]]; then suffix="_cert"; fi
                var_name="vault_ssh_host_pubkey_${user_part}${suffix}"
                if [[ -z "$suffix" ]]; then var_name="vault_ssh_host_key_${user_part}"; fi
            elif [[ "$filename" == "id_ed25519_"* ]]; then
                user_part=$(echo "$filename" | sed -E 's/id_ed25519_([a-zA-Z0-9]+)(-cert.pub|.pub)?/\1/')
                type_part=$(echo "$filename" | sed -E 's/.*_([a-zA-Z0-9]+)(-cert.pub|.pub)?/\2/')
                suffix=""
                if [[ "$type_part" == ".pub" ]]; then suffix="_pub"; fi
                if [[ "$type_part" == "-cert.pub" ]]; then suffix="_cert"; fi
                var_name="vault_ssh_user_pubkey_${user_part}${suffix}"
                if [[ -z "$suffix" ]]; then var_name="vault_ssh_user_key_${user_part}"; fi
            else
                echo "Warning: Unrecognized SSH key file format: $keyfile"
                continue
            fi
            echo "Found SSH key: $keyfile -> $var_name"
            echo "${var_name}: |" >> "$TEMP_VAULT_FILE"
            sed 's/^/  /' "$keyfile" >> "$TEMP_VAULT_FILE"
        done
    fi

    echo ""
    echo "### Finalizing ###"
    echo "Encrypting assembled secrets into $VAULT_FILE..."
    ansible-vault encrypt --output "$VAULT_FILE" "$TEMP_VAULT_FILE"
    echo "Encryption successful."
    echo "================================================================="
    echo "Success! Vault created from existing files."
    echo "================================================================="
    exit 0
fi

# =================================================================
# ===== GENERATE MODE =============================================
# =================================================================
if [ "$MODE" != "generate" ]; then
    echo "Error: Invalid mode '$MODE'." >&2
    usage
fi

# --- Parameter Validation for Generate Mode ---
if [ "$#" -ne 3 ]; then
    echo "Error: 'generate' mode requires inventory.yml, vars.yml, and the CA private key path." >&2
    usage
fi

readonly INVENTORY_FILE="$1"
readonly VARS_FILE="$2"
readonly CA_KEY="$3"

# --- Define Output Locations ---
readonly OUTPUT_DIR="./secrets"
readonly WG_DIR="$OUTPUT_DIR/wg_configs"
readonly WG_PRIV_DIR="$OUTPUT_DIR/wg_privkeys"
readonly SSH_DIR="$OUTPUT_DIR/ssh_keys"
readonly VAULT_FILE="$OUTPUT_DIR/vault.yml"

# --- Dependency Check ---
for cmd in yq wg ssh-keygen ansible-vault tree; do
    if ! command -v "$cmd" &> /dev/null; then
        echo "Warning: Recommended command '$cmd' is not installed. Output may be limited." >&2
    fi
done

# --- Input File Validation ---
if [ ! -f "$INVENTORY_FILE" ]; then echo "Error: Inventory file not found at '$INVENTORY_FILE'" >&2; exit 1; fi
if [ ! -f "$VARS_FILE" ]; then echo "Error: Vars file not found at '$VARS_FILE'" >&2; exit 1; fi
if [ ! -f "$CA_KEY" ]; then echo "Error: SSH CA private key not found at '$CA_KEY'" >&2; exit 1; fi

# --- Cleanup and Setup ---
echo "Running in 'generate' mode..."
echo "Cleaning up previous run and creating fresh output directories..."
rm -rf "$OUTPUT_DIR"
mkdir -p "$WG_DIR" "$WG_PRIV_DIR" "$SSH_DIR"

# --- Initialize Vault File ---
readonly TEMP_VAULT_FILE=$(mktemp)
trap 'rm -f "$TEMP_VAULT_FILE"' EXIT
echo "---" > "$TEMP_VAULT_FILE"
echo "# Auto-generated by generate-all-secrets.sh on $(date)" >> "$TEMP_VAULT_FILE"

# --- Load Inventory and Vars Data ---
echo "Pre-loading data from inventory and vars files..."
declare -A HOST_IPS WG_ADDRS CONTAINER_ADDRS
declare -A USER_NUMS
readonly WG_PORT=$(yq -r '.wireguard_port' "$VARS_FILE")
readonly WG_INTERFACE=$(yq -r '.wg_if' "$VARS_FILE")
readonly WG_CLIENT_INTERFACE=$(yq -r '.wireguard_if_client' "$VARS_FILE")
readonly WG_USER_ADDRESS=$(yq -r '.wireguard_address_user' "$VARS_FILE")

# Read from INVENTORY_FILE
readonly RPI_NODES=$(yq '.all.children.rpi_nodes.hosts | keys | .[]' "$INVENTORY_FILE")
for host in $RPI_NODES; do
    host_data=$(yq ".all.children.rpi_nodes.hosts.$host" "$INVENTORY_FILE")
    HOST_IPS[$host]=$(echo "$host_data" | yq '.ansible_host')
    WG_ADDRS[$host]=$(echo "$host_data" | yq '.wireguard_address')
    CONTAINER_ADDRS[$host]=$(echo "$host_data" | yq '.wireguard_address_containers')
done

while read -r name number; do
    echo "Found user: $name (number: $number)"
    USER_NUMS[$name]=$number
done < <(yq -r '.users[] | .name + " " + (.number|tostring)' "$VARS_FILE")
readonly USERS_LIST="${!USER_NUMS[@]}"

# --- Generate Secrets ---
echo ""
echo "### Generating All Keys and Certs ###"
declare -A RPI_WG_PRIV RPI_WG_PUB
declare -A USER_WG_CLIENT_PRIV USER_WG_CLIENT_PUB
declare -A USER_WG_CONTAINER_PRIV USER_WG_CONTAINER_PUB

echo "# WireGuard Node Keys" >> "$TEMP_VAULT_FILE"
for host in $RPI_NODES; do
    priv_key=$(wg genkey)
    pub_key=$(echo "$priv_key" | wg pubkey)
    RPI_WG_PRIV[$host]=$priv_key
    RPI_WG_PUB[$host]=$pub_key
    echo "$priv_key" > "$WG_PRIV_DIR/${host}.key"
    echo "vault_wg_private_key_${host//-/_}: \"$priv_key\"" >> "$TEMP_VAULT_FILE"
done

for user in $USERS_LIST; do
    echo "--- Processing secrets for user: $user ---"

    # Client keys
    USER_WG_CLIENT_PRIV[$user]=$(wg genkey)
    USER_WG_CLIENT_PUB[$user]=$(echo "${USER_WG_CLIENT_PRIV[$user]}" | wg pubkey)
    echo "${USER_WG_CLIENT_PRIV[$user]}" > "$WG_PRIV_DIR/${user}_client.key"

    # Container keys
    for host in $RPI_NODES; do
        container_priv=$(wg genkey)
        container_pub=$(echo "$container_priv" | wg pubkey)
        USER_WG_CONTAINER_PRIV["${host}_${user}"]=$container_priv
        USER_WG_CONTAINER_PUB["${host}_${user}"]=$container_pub
        echo "$container_priv" > "$WG_PRIV_DIR/${host}_${user}_container.key"
    done

    # Generate single host key for all user's containers
    host_key_path="$SSH_DIR/ssh_host_${user}_key"
    ssh-keygen -t ed25519 -f "$host_key_path" -N "" -C "host_key_${user}" >/dev/null

    # Collect all container IPs as principals
    principals=""
    for host in $RPI_NODES; do
        container_addr=${CONTAINER_ADDRS[$host]%/*}
        if [ -z "$principals" ]; then
            principals="$container_addr"
        else
            principals="$principals,$container_addr"
        fi
    done
    echo "Signing host key for '$user' with principals: $principals"
    ssh-keygen -s "$CA_KEY" -I "host_key_${user}" -h -n "$principals" "${host_key_path}.pub" >/dev/null

    user_key_path="$SSH_DIR/id_ed25519_${user}"
    ssh-keygen -t ed25519 -f "$user_key_path" -N "" -C "user_${user}" >/dev/null
    echo "Signing user key for '$user' with principal: $user"
    ssh-keygen -s "$CA_KEY" -I "user_${user}" -n "${user}" -V "+52w" "${user_key_path}.pub" >/dev/null

    {
        echo ""
        echo "vault_wg_private_key_${user}: \"${USER_WG_CLIENT_PRIV[$user]}\""
        for host in $RPI_NODES; do
            echo "vault_wg_private_key_container_${host//-/_}_${user}: \"${USER_WG_CONTAINER_PRIV[${host}_${user}]}\""
        done
        echo "vault_ssh_host_key_${user}: |"
        sed 's/^/  /' "$host_key_path"
        echo "vault_ssh_host_pubkey_${user}_pub: |"
        sed 's/^/  /' "${host_key_path}.pub"
        echo "vault_ssh_host_pubkey_${user}_cert: |"
        sed 's/^/  /' "${host_key_path}-cert.pub"
        echo "vault_ssh_user_key_${user}: |"
        sed 's/^/  /' "$user_key_path"
        echo "vault_ssh_user_pubkey_${user}_pub: |"
        sed 's/^/  /' "${user_key_path}.pub"
        echo "vault_ssh_user_pubkey_${user}_cert: |"
        sed 's/^/  /' "${user_key_path}-cert.pub"
    } >> "$TEMP_VAULT_FILE"
done

# --- Generate Wireguard Config Files ---
echo ""
echo "### Generating All WireGuard Configuration Files ###"
for host in $RPI_NODES; do
    host_conf_file="$WG_DIR/${host}_wg0.conf"
    echo "Creating host config: $host_conf_file"

    cat > "$host_conf_file" << EOF
[Interface]
PrivateKey = ${RPI_WG_PRIV[$host]}
Address = ${WG_ADDRS[$host]}
ListenPort = ${WG_PORT}
EOF
    for peer_host in $RPI_NODES; do
        if [ "$host" != "$peer_host" ]; then
            cat >> "$host_conf_file" << EOF

[Peer]
PublicKey = ${RPI_WG_PUB[$peer_host]}
AllowedIPs = ${WG_ADDRS[$peer_host]%/*}/32
Endpoint = ${HOST_IPS[$peer_host]}:${WG_PORT}
PersistentKeepalive = 25
EOF
        fi
    done
done

for user in $USERS_LIST; do
    # Create client config file (wg1.conf)
    client_conf_file="$WG_DIR/${user}_client-wg1.conf"
    echo "Creating client config: $client_conf_file"
    cat > "$client_conf_file" << EOF
[Interface]
PrivateKey = ${USER_WG_CLIENT_PRIV[$user]}
Address = ${WG_USER_ADDRESS}
EOF

    # All containers as peers in client config
    for host in $RPI_NODES; do
        container_addr=$(yq ".all.children.rpi_nodes.hosts.$host.wireguard_address_containers" "$INVENTORY_FILE")
        endpoint=$(yq ".all.children.rpi_nodes.hosts.$host.ansible_host" "$INVENTORY_FILE")
        port=$(yq ".all.children.rpi_nodes.hosts.$host.wg_ports.$user" "$INVENTORY_FILE")
        container_ip=${container_addr%/*} # IP without CIDR

        cat >> "$client_conf_file" << EOF

[Peer]
PublicKey = ${USER_WG_CONTAINER_PUB[${host}_${user}]}
AllowedIPs = ${container_ip}/32
Endpoint = ${endpoint}:${port}
PersistentKeepalive = 25
EOF
    done

    # Create container configs on each host
    for host in $RPI_NODES; do
        container_conf_file="$WG_DIR/${host}_${user}-wg1.conf"
        container_addr=${CONTAINER_ADDRS[$host]}
        user_ip=${WG_USER_ADDRESS%/*}
        echo "Creating container config: $container_conf_file"
        
        # Interface section
        cat > "$container_conf_file" << EOF
[Interface]
PrivateKey = ${USER_WG_CONTAINER_PRIV[${host}_${user}]}
Address = ${container_addr}
ListenPort = ${WG_PORT}

# Client peer
[Peer]
PublicKey = ${USER_WG_CLIENT_PUB[$user]}
AllowedIPs = ${user_ip}/32, 0.0.0.0/0
EOF

        # Add other containers of the same user as peers
        for peer_host in $RPI_NODES; do
            if [ "$host" != "$peer_host" ]; then
                peer_container_addr=${CONTAINER_ADDRS[$peer_host]}
                peer_endpoint=${HOST_IPS[$peer_host]}
                peer_port=$(yq ".all.children.rpi_nodes.hosts.$peer_host.wg_ports.$user" "$INVENTORY_FILE")
                peer_container_ip=${peer_container_addr%/*}

                cat >> "$container_conf_file" << EOF

[Peer]
PublicKey = ${USER_WG_CONTAINER_PUB[${peer_host}_${user}]}
AllowedIPs = ${peer_container_ip}/32
Endpoint = ${peer_endpoint}:${peer_port}
PersistentKeepalive = 25
EOF
            fi
        done
    done
done

# --- Finalize ---
echo ""
echo "### Finalizing ###"
echo "Encrypting all secrets into $VAULT_FILE..."
ansible-vault encrypt --output "$VAULT_FILE" "$TEMP_VAULT_FILE"
echo ""
echo "================================================================="
echo "Success! All files generated in '$OUTPUT_DIR/'"
echo ""
if command -v tree &> /dev/null; then
    tree "$OUTPUT_DIR"
else
    ls -R "$OUTPUT_DIR"
fi
echo "================================================================="