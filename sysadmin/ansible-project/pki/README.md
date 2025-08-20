# Host Certificate Infrastructure - Administrator Guide

## Overview
This system manages certificates for SSH services using ED25519 keys with Certificate Authorities (CAs) for secure host identification and communication. It ensures clients can securely verify host identities when connecting for the first time, eliminating the need for manual fingerprint verification.

## Components
1. SSH Scripts:
   - `ssh-ca-create.sh` - Creates the SSH CA
   - `ssh-host-key-create.sh` - Creates and signs SSH host keys
   - `ssh-user-key-sign.sh` - Signs SSH user keys
   - `ssh-user-key-sign-interactive.sh` - Signs SSH user keys with interactive prompts

## Initial Setup

### SSH Infrastructure
1. Create SSH CA (one-time setup):
```bash
./ssh-ca-create.sh [ca_directory] [common_name]
```
Where ca_directory defaults to ~/.ssh/ca and common_name to "SSH CA".
This creates:
- `ca` - CA private key (PROTECT THIS!)
- `ca.pub` - CA public key

Server-side setup
1. Copy the CA public key to /etc/ssh/ca.pub
2. Add to /etc/ssh/sshd_config:
   ```
   TrustedUserCAKeys /etc/ssh/ca.pub
   ```
3. Restart sshd:
   ```bash
   systemctl restart sshd
   ```

2. For each host that needs an SSH certificate:
```bash
./ssh-host-key-create.sh <ca_private_key_path> <hostname> <ip_address> <output_directory>
```

Example:
```bash
./ssh-host-key-create.sh ~/.ssh/ca myserver.example.com 192.168.1.100 ./host-keys
```

Files produced:
- ssh_host_ed25519_key
- ssh_host_ed25519_key.pub
- ssh_host_ed25519_key-cert.pub

Place them in /etc/ssh/ and add these lines to /etc/ssh/sshd_config:
```
HostKey /etc/ssh/ssh_host_ed25519_key
HostCertificate /etc/ssh/ssh_host_ed25519_key-cert.pub
```

## Client Setup

### CA Key Installation

Provide ca.pub to users and instruct them to:

1. Save the CA public key to `~/.ssh/ca.pub`
2. Add the CA to `~/.ssh/known_hosts` using one of these methods:

For all hosts:
```bash
echo "@cert-authority * $(cat ~/.ssh/ca.pub)" >> ~/.ssh/known_hosts
```

For a specific domain:
```bash
echo "@cert-authority *.example.com $(cat ~/.ssh/ca.pub)" >> ~/.ssh/known_hosts
```

### User Key Generation

Users should generate their SSH keys using:
```bash
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519 -C "your.email@example.com"
```

This creates:
- Private key: ~/.ssh/id_ed25519
- Public key: ~/.ssh/id_ed25519.pub

### User Key Signing

Certificates are valid for 26 weeks from signing.

Three methods are available for signing user keys:

1. Single key mode:
```bash
./ssh-user-key-sign.sh <ca_priv_key> <public_key_path> <principal> [output_path]
```

Example:
```bash
./ssh-user-key-sign.sh ~/.ssh/ca id_ed25519.pub username
```

2. Interactive mode:
```bash
./ssh-user-key-sign-interactive.sh
```
This provides a guided process for signing keys.

3. Batch mode:
```bash
./ssh-user-key-sign.sh <ca_priv_key> --batch [input_directory] [output_directory]
```

For batch mode:
- Input files must be named: `id_ed25519_username.pub`
- Output files will be named: `id_ed25519_username-cert.pub`

Example:
```bash
./ssh-user-key-sign.sh ~/.ssh/ca --batch ./keys ./certs
```

### Post-Signing Setup

Users should:
1. Place the certificate next to their private key
2. Set correct permissions:
```bash
chmod 600 ~/.ssh/id_ed25519
chmod 644 ~/.ssh/id_ed25519.pub
chmod 644 ~/.ssh/id_ed25519-cert.pub
```

## Security Considerations

1. CA Private Key Protection
   - Store the CA private key securely
   - Limit access to authorized administrators only
   - Consider using a hardware security module for production environments

2. Certificate Management
   - Maintain a record of all issued certificates
   - Implement a process for certificate renewal
   - Have a procedure for certificate revocation

3. Access Control
   - When signing a user's public key, they will be able to login as the specified principal to any machine that trusts the CA
   - Carefully control which principals are assigned to users
   - Regularly audit access permissions

## Maintenance

1. Certificate Renewal
   - Host certificates expire after one year
   - User certificates expire after 26 weeks
   - Set up reminders for certificate renewal
   - Plan renewals before expiration to prevent service disruption

2. Logging
   - All key operations are logged using the system logger
   - Monitor logs for unauthorized signing attempts
   - Regular audit of issued certificates is recommended
