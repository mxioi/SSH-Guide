# Setting Up OpenSSH Server on Windows (Including Domain Controllers)

This guide covers setting up SSH **Server** on Windows Server (including Domain Controllers) so you can SSH **into** your Windows machine.

> **Companion to**: The main README covers Windows → Linux SSH client setup.  
> **This guide**: Covers setting up the SSH server **on** Windows.

---

## Quick Start (TL;DR)

If you just want it working fast:

```powershell
# Run in Administrator PowerShell
cd C:\temp  # Or wherever you cloned this repo

# Install and configure
.\Install-OpenSSH-Server.ps1

# Add your public key
.\Add-SSH-PublicKey.ps1 -PublicKey "ssh-ed25519 AAAA... your-key-here"

# Test
ssh DOMAIN\username@localhost
```

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Installation Options](#installation-options)
3. [Domain Controller Specific Issues](#domain-controller-specific-issues)
4. [Adding Public Keys](#adding-public-keys)
5. [Troubleshooting](#troubleshooting)
6. [Security Hardening](#security-hardening)
7. [Common Errors and Fixes](#common-errors-and-fixes)

---

## Prerequisites

### ⚠️ **CRITICAL: PowerShell vs CMD**

These are **PowerShell** commands, not Command Prompt (CMD) commands!

**How to tell the difference:**
- **PowerShell**: Prompt shows `PS C:\>`
- **CMD**: Prompt shows `C:\>`

**To open PowerShell as Administrator:**
1. Right-click Start button
2. Select "Terminal (Admin)" or "Windows PowerShell (Admin)"
3. Click "Yes" on UAC prompt

**If you're in CMD**, type `powershell` and press Enter.

### System Requirements

- Windows Server 2019+ or Windows 10/11
- Administrator access
- For Domain Controllers: Active Directory module (pre-installed)

---

## Installation Options

### Option 1: Automated Script (Recommended)

```powershell
# Download and run the installation script
.\Install-OpenSSH-Server.ps1
```

**What it does:**
- Installs OpenSSH Server capability
- Configures services (sshd, ssh-agent)
- Creates firewall rule for port 22
- Applies security hardening
- Sets up administrators_authorized_keys with correct permissions

### Option 2: Manual Installation

```powershell
# 1. Install OpenSSH Server
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0

# 2. Start and enable services
Start-Service sshd
Set-Service -Name sshd -StartupType 'Automatic'

Start-Service ssh-agent
Set-Service -Name ssh-agent -StartupType 'Automatic'

# 3. Create firewall rule
New-NetFirewallRule -Name sshd -DisplayName 'OpenSSH-Server-In-TCP' `
    -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22

# 4. Verify
Get-Service sshd, ssh-agent
Get-NetTCPConnection -LocalPort 22 -State Listen
```

---

## Domain Controller Specific Issues

### Issue 1: AllowGroups Configuration

**Problem**: Default sshd_config may have:
```
AllowGroups administrators "openssh users"
```

This **fails** on Domain Controllers because group names need the domain prefix.

**Fix**:
```powershell
# Get your domain name
$domain = (Get-ADDomain).NetBIOSName

# Update sshd_config
$config = Get-Content C:\ProgramData\ssh\sshd_config
$config = $config -replace '^AllowGroups.*', "AllowGroups $domain\Domain` Admins $domain\Administrators administrators"
$config | Set-Content C:\ProgramData\ssh\sshd_config

# Restart service
Restart-Service sshd
```

**Or** comment out AllowGroups entirely (less secure):
```powershell
(Get-Content C:\ProgramData\ssh\sshd_config) -replace '^AllowGroups', '# AllowGroups' | 
    Set-Content C:\ProgramData\ssh\sshd_config
Restart-Service sshd
```

### Issue 2: Domain Account Authentication Format

When connecting to a DC, use domain prefix:

```powershell
# Correct formats:
ssh DOMAIN\username@dc.domain.com
ssh domain\username@192.168.1.10
ssh username@domain@dc.domain.com  # UPN format

# Wrong (will fail):
ssh username@dc.domain.com  # Missing domain prefix
```

### Issue 3: Administrators vs Domain Admins

For Domain Controllers, you typically want **Domain Admins** to have SSH access:

```powershell
# Create SSH access group (recommended approach)
New-ADGroup -Name "SSH-DC-Access" -GroupScope Global -GroupCategory Security `
    -Description "Members can SSH to Domain Controllers"

# Add users
Add-ADGroupMember -Identity "SSH-DC-Access" -Members "username1", "username2"

# Update sshd_config
$domain = (Get-ADDomain).NetBIOSName
Add-Content C:\ProgramData\ssh\sshd_config "`nAllowGroups $domain\SSH-DC-Access"

Restart-Service sshd
```

---

## Adding Public Keys

### For Administrator Accounts

**CRITICAL**: Admin users **must** use the special administrators_authorized_keys file!

```powershell
# 1. Create/verify the file exists
$keyFile = "C:\ProgramData\ssh\administrators_authorized_keys"

# 2. Add your public key (get this from: cat ~/.ssh/id_ed25519.pub on your client)
$publicKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... user@client"
$publicKey | Set-Content $keyFile -Force

# 3. FIX PERMISSIONS (CRITICAL!)
icacls $keyFile /inheritance:r
icacls $keyFile /grant "NT AUTHORITY\SYSTEM:(F)"
icacls $keyFile /grant "BUILTIN\Administrators:(F)"

# 4. Verify permissions (should show ONLY SYSTEM and Administrators)
icacls $keyFile

# 5. Restart SSH service
Restart-Service sshd -Force

# 6. Test
ssh DOMAIN\username@localhost
```

### For Non-Admin Users

```powershell
# 1. Create .ssh directory
$sshDir = "$env:USERPROFILE\.ssh"
New-Item -ItemType Directory -Path $sshDir -Force

# 2. Create authorized_keys
$keyFile = "$sshDir\authorized_keys"
$publicKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... user@client"
$publicKey | Set-Content $keyFile -Force

# 3. Fix permissions
icacls $keyFile /inheritance:r
icacls $keyFile /grant "${env:USERNAME}:(F)"
icacls $keyFile /grant "NT AUTHORITY\SYSTEM:(F)"
icacls $keyFile /grant "BUILTIN\Administrators:(F)"
```

### Using the Helper Script

```powershell
# Easier way:
.\Add-SSH-PublicKey.ps1 -PublicKey "ssh-ed25519 AAAAC3Nza... user@client"

# Or from file:
$key = Get-Content C:\temp\my_key.pub
.\Add-SSH-PublicKey.ps1 -PublicKey $key
```

---

## Troubleshooting

### Run the Diagnostic Script

```powershell
.\Diagnose-SSH-Server.ps1
```

This checks:
- Service status
- Port listening
- File permissions
- Configuration syntax
- Recent SSH logs
- Common misconfigurations

### Common Issues Decision Tree

```
SSH Connection Issue?
├─ "Connection refused"
│  ├─ Service not running → Restart-Service sshd
│  ├─ Port not listening → Check firewall
│  └─ Wrong port → Check sshd_config Port directive
│
├─ "Connection reset" (after host key exchange)
│  ├─ AllowGroups wrong → Fix for domain accounts
│  ├─ User not in allowed group → Add to group
│  └─ Account locked → Check AD account status
│
├─ "Permission denied (publickey)"
│  ├─ Wrong key file location
│  │  ├─ Admin? → Must use C:\ProgramData\ssh\administrators_authorized_keys
│  │  └─ Non-admin? → Use C:\Users\username\.ssh\authorized_keys
│  │
│  ├─ Wrong permissions → Run icacls fix (see above)
│  ├─ Key not in file → Add key and restart service
│  └─ Service not restarted → Restart-Service sshd
│
└─ "Permission denied (password)"
   ├─ Password auth disabled → Edit sshd_config: PasswordAuthentication yes
   ├─ Wrong password → Check account
   └─ Account locked → Unlock in AD Users and Computers
```

### Check SSH Logs

```powershell
# View recent SSH events
Get-WinEvent -LogName 'OpenSSH/Operational' -MaxEvents 20 | 
    Format-List TimeCreated, LevelDisplayName, Message

# Filter for errors
Get-WinEvent -LogName 'OpenSSH/Operational' -MaxEvents 100 | 
    Where-Object LevelDisplayName -match 'Error|Warning' | 
    Format-List TimeCreated, Message

# Watch logs in real-time (run before testing)
Get-WinEvent -LogName 'OpenSSH/Operational' -MaxEvents 1 -Oldest | 
    Select-Object TimeCreated, Message
```

**Common log messages:**
- `"Invalid userfile"` → ACL permissions wrong
- `"bad ownership or modes"` → File permissions wrong
- `"Accepted publickey"` → Success!
- `"Failed password"` → Wrong password or account issue
- `"Connection closed [preauth]"` → AllowGroups rejection

---

## Security Hardening

### Minimal Hardening (Do This)

```powershell
# Edit C:\ProgramData\ssh\sshd_config

# 1. Disable password auth (after keys work!)
PasswordAuthentication no

# 2. Restrict allowed users/groups
AllowGroups DOMAIN\SSH-DC-Access

# 3. Enable verbose logging
LogLevel VERBOSE

# Restart
Restart-Service sshd
```

### Recommended Hardening

Add to `C:\ProgramData\ssh\sshd_config`:

```
# Authentication
PasswordAuthentication no
PubkeyAuthentication yes
PermitRootLogin no
StrictModes yes
MaxAuthTries 3

# Session limits
MaxSessions 5
ClientAliveInterval 300
ClientAliveCountMax 2
LoginGraceTime 30

# Disable unnecessary features
AllowTcpForwarding no
AllowAgentForwarding no
X11Forwarding no
PermitTunnel no

# Logging
LogLevel VERBOSE
SyslogFacility LOCAL0
```

### Advanced Hardening

```powershell
# 1. Change default port (reduces automated attacks)
# Edit sshd_config: Port 2222
# Update firewall rule:
Set-NetFirewallRule -DisplayName "OpenSSH-Server-In-TCP" -LocalPort 2222

# 2. Restrict by IP (if connecting from known IPs only)
New-NetFirewallRule -Name 'sshd-restricted' -DisplayName 'SSH-Restricted-IP' `
    -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22 `
    -RemoteAddress "192.168.1.0/24"

# 3. Enable Windows Firewall logging
Set-NetFirewallProfile -Profile Domain,Public,Private -LogAllowed True -LogBlocked True
```

---

## Common Errors and Fixes

### Error: "Access to the path ... is denied"

**Cause**: File permissions too restrictive  
**Fix**:
```powershell
# If you can't even read the file, run in Admin PowerShell:
takeown /F C:\ProgramData\ssh\administrators_authorized_keys
icacls C:\ProgramData\ssh\administrators_authorized_keys /reset
# Then re-apply correct permissions (see Adding Public Keys section)
```

### Error: "The Try statement is missing its Catch or Finally block"

**Cause**: You ran PowerShell script in CMD  
**Fix**: Type `powershell` first, then run the script

### Error: "Get-Content is not recognized"

**Cause**: You're in CMD, not PowerShell  
**Fix**: See "PowerShell vs CMD" section above

### Error: Connection works with password but not with key

**Checklist**:
```powershell
# 1. Verify key is in correct file
Get-Content C:\ProgramData\ssh\administrators_authorized_keys

# 2. Check permissions (must show ONLY SYSTEM and Administrators)
icacls C:\ProgramData\ssh\administrators_authorized_keys

# 3. Check sshd_config allows pubkey
Select-String -Path C:\ProgramData\ssh\sshd_config -Pattern "PubkeyAuthentication"
# Should show: PubkeyAuthentication yes

# 4. Verify Match Group block exists
Select-String -Path C:\ProgramData\ssh\sshd_config -Pattern "Match Group administrators" -Context 0,2

# 5. Check SSH logs for rejection reason
Get-WinEvent -LogName 'OpenSSH/Operational' -MaxEvents 10 | Format-List

# 6. Restart service
Restart-Service sshd -Force

# 7. Test with verbose client
ssh -vvv DOMAIN\username@server
```

---

## Scripts Included

| Script | Purpose |
|--------|---------|
| `Install-OpenSSH-Server.ps1` | Complete installation and configuration |
| `Add-SSH-PublicKey.ps1` | Add public keys with correct permissions |
| `Diagnose-SSH-Server.ps1` | Comprehensive diagnostics |
| `Fix-SSH-Config.ps1` | Repair corrupted sshd_config |
| `Remove-OpenSSH-Server.ps1` | Clean uninstall |

---

## Quick Reference

```powershell
# Check status
Get-Service sshd

# Restart service
Restart-Service sshd -Force

# Check if listening
Get-NetTCPConnection -LocalPort 22 -State Listen

# View config
Get-Content C:\ProgramData\ssh\sshd_config

# Check logs
Get-WinEvent -LogName 'OpenSSH/Operational' -MaxEvents 10

# Test connection
ssh localhost
ssh DOMAIN\username@localhost

# Add key (admins)
$key | Set-Content C:\ProgramData\ssh\administrators_authorized_keys -Force
icacls C:\ProgramData\ssh\administrators_authorized_keys /inheritance:r
icacls C:\ProgramData\ssh\administrators_authorized_keys /grant "NT AUTHORITY\SYSTEM:(F)"
icacls C:\ProgramData\ssh\administrators_authorized_keys /grant "BUILTIN\Administrators:(F)"
Restart-Service sshd -Force
```

---

## Additional Resources

- [Official Microsoft OpenSSH Documentation](https://docs.microsoft.com/en-us/windows-server/administration/openssh/openssh_overview)
- [OpenSSH Server Configuration](https://www.openssh.com/manual.html)
- [Windows SSH Server Best Practices](https://docs.microsoft.com/en-us/windows-server/administration/openssh/openssh_keymanagement)

---

## Contributing

Found an issue? Have a better way to do something? PRs welcome!

Common improvements needed:
- Additional troubleshooting scenarios
- Security hardening examples
- Integration with enterprise tools (SIEM, monitoring)
- Automated testing scripts

