# SSH Setup Guide

Complete guides for SSH setup on Windows and Linux environments, covering both client and server configurations.

---

## What's Included

| Guide | Description |
|-------|-------------|
| [Windows SSH Client Setup](#windows-ssh-client-setup) | Connect FROM Windows TO Linux servers |
| [Windows SSH Server Setup](WINDOWS-SSH-SERVER.md) | SSH INTO Windows machines |
| [Linux SSH Server Setup](#linux-ssh-server-setup) | Set up SSH on Linux servers |
| [Key Management Best Practices](#key-management-best-practices) | Naming, organizing, and securing keys |

---

## Windows SSH Client Setup

This guide covers:
- Cleaning up broken `.ssh` folders/keys on Windows
- Generating **separate** SSH keys for each server
- Copying public keys to Linux servers
- Creating SSH config for easy connections (`ssh myserver`)
- Troubleshooting common issues

---

### SSH Basics (Quick Reference)

If you're new to SSH, these are the files and terms that matter most:

- `private key`: Stays on your client computer. Never copy this to a server.
- `public key`: Safe to copy to a server. This is what the server checks.
- `authorized_keys`: The server-side file that lists which public keys are allowed to log in.
- `known_hosts`: The client-side file that remembers trusted server host keys.
- `config`: The client-side file that stores host aliases, usernames, and `IdentityFile` settings.

---

### 1) Clean up the `.ssh` folder (optional)

Sometimes `C:\Users\<user>\.ssh` gets stuck with bad permissions or corrupted files.

```powershell
# Delete problematic "known_hosts.old" if present
cmd /c del /F /Q "%USERPROFILE%\.ssh\known_hosts.old" 2>nul

# Optional: back up old default keys
Rename-Item "$env:USERPROFILE\.ssh\id_ed25519" "id_ed25519.old" -Force -ErrorAction SilentlyContinue
Rename-Item "$env:USERPROFILE\.ssh\id_ed25519.pub" "id_ed25519.pub.old" -Force -ErrorAction SilentlyContinue
```

---

### 2) Create a secure location for keys

Avoid fighting `%USERPROFILE%\.ssh` permissions—use a dedicated folder.

```powershell
# Create keys directory
mkdir C:\Keys 2>nul

# Lock down permissions (only your user)
icacls C:\Keys /inheritance:r
icacls C:\Keys /grant:r "$env:COMPUTERNAME\$env:USERNAME":(OI)(CI)F
```

> **Important**: Keep `C:\Keys` outside OneDrive or other sync folders!

If you move to another Windows PC later, you can reuse this same pattern: create `C:\Keys`, copy in only the keys you need, and then rebuild or copy your SSH config.

---

### 3) Generate separate keypairs (one per server)

Use clear, descriptive names so you don't mix them up.

```powershell
# Web server key
ssh-keygen -t ed25519 -C "yourname@yourpc-webserver" -f C:\Keys\id_ed25519_webserver

# Database server key
ssh-keygen -t ed25519 -C "yourname@yourpc-dbserver" -f C:\Keys\id_ed25519_dbserver

# Home lab key
ssh-keygen -t ed25519 -C "yourname@yourpc-homelab" -f C:\Keys\id_ed25519_homelab
```

**Key naming convention:** `id_ed25519_<purpose>` or `id_ed25519_<servername>`

This creates:
- `C:\Keys\id_ed25519_webserver` (private key)
- `C:\Keys\id_ed25519_webserver.pub` (public key)

> **Important**: If you use a custom key name such as `id_ed25519_homelab`, OpenSSH will not automatically pick it for arbitrary hosts. Either use `ssh -i C:\Keys\id_ed25519_homelab user@host` or add a `Host` entry with `IdentityFile` and `IdentitiesOnly yes` in your SSH config.

> **Never copy the private key to the server**: Only copy the `.pub` file to the remote machine. The private key stays on the client that initiates the SSH connection.

---

### 4) Copy public keys to each server

You'll need to authenticate with password **once** per server.

```powershell
# Copy key to Linux server
type C:\Keys\id_ed25519_webserver.pub | ssh user@server.example.com "umask 077; mkdir -p ~/.ssh && cat >> ~/.ssh/authorized_keys"
```

**On the server**, verify permissions:

```bash
ls -ld ~/.ssh                 # Should show: drwx------
ls -l ~/.ssh/authorized_keys  # Should show: -rw-------

# Fix if needed
chmod 700 ~/.ssh
chmod 600 ~/.ssh/authorized_keys
```

---

### 5) Create your SSH config

Create `%USERPROFILE%\.ssh\config`:

```powershell
@'
# Web Server
Host webserver
  HostName server.example.com
  User deploy
  IdentityFile C:/Keys/id_ed25519_webserver
  IdentitiesOnly yes

# Database Server
Host dbserver
  HostName db.example.com
  User admin
  IdentityFile C:/Keys/id_ed25519_dbserver
  IdentitiesOnly yes

# Home Lab (via IP)
Host homelab
  HostName 192.168.1.100
  User root
  IdentityFile C:/Keys/id_ed25519_homelab
  IdentitiesOnly yes

# Jump host example
Host internal-server
  HostName 10.0.0.50
  User ubuntu
  IdentityFile C:/Keys/id_ed25519_internal
  ProxyJump jumphost
'@ | Set-Content "$env:USERPROFILE\.ssh\config" -Encoding ASCII
```

**To add more hosts later**, use `Add-Content`:

```powershell
@'

Host newserver
  HostName new.example.com
  User admin
  IdentityFile C:/Keys/id_ed25519_newserver
  IdentitiesOnly yes
'@ | Add-Content "$env:USERPROFILE\.ssh\config" -Encoding ASCII
```

If `ssh` or `scp` fails before connecting with an error like `Bad owner or permissions on C:\Users\<user>\.ssh\config`, check the ACL on the config file and remove extra inherited permissions so only your user can access it.

---

### 6) Test connections

These should work **without a password**:

```powershell
ssh webserver
ssh dbserver
ssh homelab
```

Debug if needed:
```powershell
ssh -vvv webserver
```

Show the fully resolved SSH config for a host:
```powershell
ssh -G webserver
```

---

### 7) Setting Up a New Windows Client

Use this checklist when you move to another Windows laptop or desktop:

```powershell
# 1. Confirm the OpenSSH client is installed
ssh -V

# 2. Check whether ssh-agent is available
Get-Service ssh-agent

# 3. Create a dedicated key directory
mkdir C:\Keys 2>nul

# 4. Re-apply secure permissions
icacls C:\Keys /inheritance:r
icacls C:\Keys /grant:r "$env:COMPUTERNAME\$env:USERNAME":(OI)(CI)F
```

Then:

- Copy only the private keys you intentionally want on that client.
- Copy the matching `.pub` files.
- Copy `%USERPROFILE%\.ssh\config` if you want to keep the same host aliases.
- Copy `known_hosts` only if you want to preserve trusted host records from the old machine.
- Test each host with `ssh -G hostname` before the first real login.
- Test each connection with `ssh -v hostname`.

If you use passphrases, start `ssh-agent` and add your keys after copying them:

```powershell
Start-Service ssh-agent
Set-Service -Name ssh-agent -StartupType Automatic
ssh-add C:\Keys\id_ed25519_example
```

---

## Linux SSH Server Setup

### Quick Setup (Ubuntu/Debian)

```bash
# Install OpenSSH Server
sudo apt update && sudo apt install -y openssh-server

# Enable and start
sudo systemctl enable ssh
sudo systemctl start ssh

# Check status
sudo systemctl status ssh
```

### Quick Setup (RHEL/CentOS/Rocky)

```bash
# Install OpenSSH Server
sudo dnf install -y openssh-server

# Enable and start
sudo systemctl enable sshd
sudo systemctl start sshd

# Open firewall
sudo firewall-cmd --permanent --add-service=ssh
sudo firewall-cmd --reload
```

### Add authorized keys

```bash
# Create .ssh directory with correct permissions
mkdir -p ~/.ssh && chmod 700 ~/.ssh

# Add public key (paste your key)
echo "ssh-ed25519 AAAA... user@client" >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
```

### Security Hardening

Edit `/etc/ssh/sshd_config`:

```bash
# Disable password authentication (after keys work!)
PasswordAuthentication no

# Disable root login (use sudo instead)
PermitRootLogin no

# Use only SSH protocol 2
Protocol 2

# Limit authentication attempts
MaxAuthTries 3

# Set idle timeout
ClientAliveInterval 300
ClientAliveCountMax 2
```

Restart SSH:
```bash
sudo systemctl restart sshd
```

---

## Key Management Best Practices

### Naming Convention

Use descriptive names that identify:
- **Purpose/Server**: What the key is for
- **Client**: Where the key lives (optional)

```
id_ed25519_production-web
id_ed25519_staging-db
id_ed25519_homelab-nas
id_ed25519_github
id_ed25519_work-vpn
```

### Key Organization

```
C:\Keys\                          # Windows
├── id_ed25519_production         # Production servers
├── id_ed25519_production.pub
├── id_ed25519_staging            # Staging servers
├── id_ed25519_staging.pub
├── id_ed25519_homelab            # Home lab
├── id_ed25519_homelab.pub
└── id_ed25519_github             # GitHub
    id_ed25519_github.pub

~/.ssh/                           # Linux/Mac
├── config                        # SSH config file
├── id_ed25519_*                  # Keys
└── known_hosts                   # Known hosts
```

### Security Guidelines

1. **Use Ed25519 keys** - More secure and faster than RSA
2. **One key per purpose** - Limits blast radius if compromised
3. **Use passphrases** for sensitive keys (production, etc.)
4. **Never share private keys** - Only copy `.pub` files
5. **Rotate keys periodically** - Annually for high-security environments
6. **Keep backups** - Store encrypted backups of important keys
7. **Use SSH agent** - Avoid typing passphrases repeatedly

### SSH Agent (Windows)

```powershell
# Start SSH Agent
Start-Service ssh-agent
Set-Service -Name ssh-agent -StartupType Automatic

# Add key to agent
ssh-add C:\Keys\id_ed25519_production
```

### SSH Agent (Linux/Mac)

```bash
# Start agent
eval "$(ssh-agent -s)"

# Add key
ssh-add ~/.ssh/id_ed25519_production
```

---

## Troubleshooting

### Common Issues

| Problem | Cause | Solution |
|---------|-------|----------|
| Still asked for password | Key not recognized | Check file permissions, verify key is in `authorized_keys` |
| Permission denied | Wrong key or user | Use `ssh -vvv` to debug, check `IdentityFile` path |
| Connection refused | SSH not running or firewall | Check service status, verify port 22 is open |
| Connection timed out during banner exchange | Port is open, but `sshd` is hung or not responding correctly | Restart `sshd`, check logs, verify the SSH service owns port 22 |
| Host key verification failed | Server changed | Remove old key from `known_hosts` |
| Bad owner or permissions on `config` | Extra ACLs on `%USERPROFILE%\.ssh\config` | Remove inherited or non-user ACL entries from the config file |

### Debug Commands

```powershell
# Verbose connection (shows which keys are tried)
ssh -vvv hostname

# Show the final config values OpenSSH will use
ssh -G hostname

# Check which key is being used
ssh -v hostname 2>&1 | findstr "identity"

# Test specific key
ssh -i C:\Keys\id_ed25519_test user@hostname

# Test whether port 22 is reachable before debugging auth
Test-NetConnection hostname -Port 22

# Remove a stale host key entry cleanly
ssh-keygen -R hostname
```

### Example Troubleshooting Workflow

Use this quick flow when a host should work with a key but still prompts for a password or fails:

```powershell
# 1. Confirm the final SSH config for the host alias
ssh -G myserver

# 2. Confirm port 22 is reachable
Test-NetConnection myserver -Port 22

# 3. Try a key-only login with verbose output
ssh -v -o PreferredAuthentications=publickey `
       -o PasswordAuthentication=no `
       -o KbdInteractiveAuthentication=no `
       -o NumberOfPasswordPrompts=0 `
       myserver
```

How to read the result:

- If `Test-NetConnection` fails, fix DNS, routing, firewall, or the SSH service first.
- If SSH connects but times out during banner exchange, the server accepted TCP but `sshd` is not responding correctly.
- If verbose output shows the wrong `identity file`, fix `IdentityFile` in your SSH config or use `-i`.
- If verbose output shows `Offering public key` and then `Permission denied`, the server rejected the key. Check the remote `authorized_keys` location and permissions.
- If verbose output shows `Authenticated ... using "publickey"`, the key path is working and any remaining issue is after login.

### `known_hosts` Notes

`known_hosts` is your client's record of server identities. It does not contain your private keys.

- If a server is rebuilt or its SSH host key changes, you may see `Host key verification failed`.
- Remove only the stale entry instead of deleting the whole file.
- Use `ssh-keygen -R hostname` or `ssh-keygen -R 192.168.1.10` to clear the old record safely.

### Windows-Specific Issues

See [Windows SSH Server Setup](WINDOWS-SSH-SERVER.md) for:
- Admin vs non-admin account key locations
- Domain Controller configuration
- Firewall troubleshooting
- Permission fixes

---

## Quick Reference

### Generate Key
```bash
ssh-keygen -t ed25519 -C "comment" -f /path/to/keyname
```

### Copy Key to Server
```bash
ssh-copy-id -i ~/.ssh/id_ed25519.pub user@server
# Or manually:
cat ~/.ssh/id_ed25519.pub | ssh user@server "mkdir -p ~/.ssh && cat >> ~/.ssh/authorized_keys"
```

### SSH Config Entry
```
Host nickname
  HostName server.example.com
  User username
  IdentityFile ~/.ssh/id_ed25519_keyname
  IdentitiesOnly yes
```

### Fix Permissions (Linux)
```bash
chmod 700 ~/.ssh
chmod 600 ~/.ssh/authorized_keys
chmod 600 ~/.ssh/id_ed25519
chmod 644 ~/.ssh/id_ed25519.pub
```

### Fix Permissions (Windows)
```powershell
icacls C:\Keys\id_ed25519_keyname /inheritance:r
icacls C:\Keys\id_ed25519_keyname /grant:r "$env:USERNAME":(F)
```

---

## Related Guides

- [Windows SSH Server Setup](WINDOWS-SSH-SERVER.md) - Set up SSH server on Windows
- [Improvements & Roadmap](IMPROVEMENTS.md) - Future tools and enhancements

---

## Contributing

Found an issue or have an improvement? PRs welcome!
