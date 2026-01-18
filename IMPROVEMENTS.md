# Improvements to SSH-Guide Repository

This document outlines the additions made to the SSH-Guide repository based on real-world troubleshooting of OpenSSH Server on Windows Server 2025 Domain Controller.

## What Was Added

### 1. **WINDOWS-SSH-SERVER.md**
Comprehensive guide for setting up SSH **Server** on Windows (the original README covers SSH **client** setup).

**Key Sections:**
- PowerShell vs CMD distinction (major pain point!)
- Domain Controller specific issues
- Public key setup with correct ACLs
- Troubleshooting decision tree
- Security hardening recommendations

### 2. **Install-OpenSSH-Server.ps1**
Fixed and improved installation script.

**Critical Fixes:**
- **Fixed regex bug**: Original pattern concatenated values instead of replacing them
  - Before: `LogLevel VERBOSEINFO` (broken)
  - After: `LogLevel VERBOSE` (correct)
- **Better config modification**: Uses line-by-line replacement instead of regex
- **Domain detection**: Automatically configures AllowGroups for DCs
- **Proper error handling**: Exits cleanly with helpful messages

**What Was Wrong:**
```powershell
# BROKEN - concatenates values
$configContent -replace "^\s*#?\s*$Directive\s+", "$Directive $Value"
# Result: "LogLevel VERBOSE" becomes "LogLevel VERBOSEINFO"
```

**Fixed Version:**
```powershell
# CORRECT - finds and replaces entire line
for ($i = 0; $i -lt $config.Count; $i++) {
    if ($config[$i] -match "^\s*$Directive\s+") {
        $config[$i] = "$Directive $Value"
        break
    }
}
```

### 3. **Add-SSH-PublicKey.ps1**
Helper script to add public keys with correct permissions.

**Features:**
- Validates key format
- Auto-detects admin vs non-admin users
- Uses correct file location for each user type
- Sets proper ACLs automatically
- Restarts SSH service
- Checks for duplicate keys

**Solves This Pain Point:**
Users were manually setting ACLs and getting them wrong, causing "Permission denied" errors.

### 4. **Diagnose-SSH-Server.ps1**
Comprehensive diagnostic tool.

**Checks:**
1. File existence and content
2. Current permissions (with icacls)
3. SSH service status
4. Port listening status
5. Recent SSH event logs
6. Common misconfigurations

**Provides:**
- Clear color-coded output
- Automated fixes for common issues
- Detailed verification steps

## Why These Changes Were Needed

### Real Issues Encountered

1. **Config File Corruption**
   - Regex replacement bug caused directives like `StrictModes yesyes` and `MaxAuthTries 36`
   - SSH service failed to start with corrupted config
   - No clear error messages - just "failed to start"

2. **AllowGroups on Domain Controllers**
   - Default: `AllowGroups administrators "openssh users"`
   - Doesn't work on DCs - needs domain prefix: `YOURDOMAIN\Domain Admins YOURDOMAIN\Administrators`
   - Caused "Connection reset" errors after successful host key exchange

3. **ACL Permissions**
   - `administrators_authorized_keys` must have ONLY SYSTEM and Administrators permissions
   - Any additional permissions (even inherited) cause key rejection
   - Users couldn't read the file to verify - needed admin PowerShell

4. **CMD vs PowerShell Confusion**
   - Users ran PowerShell commands in CMD
   - Got errors like: `'Get-Content' is not recognized as an internal or external command`
   - No clear indication they were in wrong shell

5. **Admin Key Location**
   - Admin users MUST use `C:\ProgramData\ssh\administrators_authorized_keys`
   - Non-admin users use `C:\Users\username\.ssh\authorized_keys`
   - No automatic detection - users put keys in wrong location

### Testing That Was Done

All scripts and documentation were tested on:
- **OS**: Windows Server 2025
- **Role**: Domain Controller
- **Scenario**: Fresh OpenSSH installation with key-based auth setup

**Test Cases:**
1. ✅ Fresh installation
2. ✅ Config file corruption and recovery
3. ✅ AllowGroups misconfiguration
4. ✅ ACL permission issues
5. ✅ Admin vs non-admin key locations
6. ✅ Domain account authentication
7. ✅ Password and public key auth
8. ✅ Service restart and verification

## Lessons Learned

### For Script Development

1. **Test regex replacements thoroughly**
   - The concatenation bug would have been caught by simple tests
   - Always verify output with actual config files

2. **Provide clear shell environment indicators**
   - Add warnings about PowerShell vs CMD at the top of docs
   - Check `$PSVersionTable` in scripts

3. **Use line-by-line editing for config files**
   - More reliable than regex for structured configs
   - Easier to debug and verify

4. **Include diagnostic tools from the start**
   - Would have saved hours of troubleshooting
   - Users can self-diagnose common issues

### For Windows SSH Server

1. **Domain Controllers are different**
   - AllowGroups needs domain prefix
   - Default groups don't work out of the box
   - Authentication requires domain\user format

2. **ACLs are critical**
   - SSH server is very strict about file permissions
   - Wrong ACLs = silent key rejection
   - Need admin access to even read the key file

3. **Service must be restarted**
   - Config changes don't apply until restart
   - Key additions don't work until restart
   - No warning if you forget

4. **Event logs are essential**
   - `OpenSSH/Operational` log has all the answers
   - But: requires admin access to read
   - Log messages could be clearer

## Recommendations for Future Improvements

### Documentation

- [ ] Add video walkthrough
- [ ] Create troubleshooting flowchart diagram
- [ ] Add screenshots for common error messages
- [ ] Document integration with enterprise tools (SIEM, monitoring)

### Scripts

- [ ] Add automated testing script
- [ ] Create uninstall/rollback script
- [ ] Add MFA/2FA integration examples
- [ ] Support for certificate-based authentication
- [ ] Automated backup before making changes

### Features

- [ ] Web-based diagnostic tool
- [ ] Integration with Group Policy
- [ ] Automated key rotation
- [ ] SSH session recording/auditing
- [ ] Integration with Windows Admin Center

## Contributing

To contribute improvements:

1. Test on actual Windows Server (not just Win10/11)
2. Include DC-specific testing if applicable
3. Provide before/after examples
4. Document any issues encountered
5. Include verification steps

## References

- [Microsoft OpenSSH Documentation](https://docs.microsoft.com/en-us/windows-server/administration/openssh/openssh_overview)
- [OpenSSH sshd_config Manual](https://man.openbsd.org/sshd_config)
- [Windows ACL Best Practices](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/user-rights-assignment)

