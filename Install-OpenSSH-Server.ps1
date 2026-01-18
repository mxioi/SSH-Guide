#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Install and configure OpenSSH Server on Windows Server 2025 Domain Controller
.DESCRIPTION
    Idempotent script to install OpenSSH Server, configure authentication methods,
    set up firewall rules, and apply security hardening suitable for a DC.
.NOTES
    Must be run as Administrator
    Safe to run multiple times
#>

# ============================================================================
# CONFIGURATION VARIABLES - Modify these as needed
# ============================================================================

$SshPort = 22                          # Default SSH port
$AllowPasswordAuth = $true             # Enable password authentication
$AllowPubkeyAuth = $true               # Enable public key authentication
$RestrictToAdGroup = $false            # Set to $true to restrict access to AD group
$SshAccessGroupName = "SSH-DC-Access"  # AD group name (created if doesn't exist)
$ChangeDefaultPort = $false            # Set to $true to use custom port (reduces noise)
$CustomPort = 2222                     # Custom port if ChangeDefaultPort is $true

# Override port if custom port is requested
if ($ChangeDefaultPort) {
    $SshPort = $CustomPort
}

# ============================================================================
# SCRIPT START
# ============================================================================

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "OpenSSH Server Installation for DC" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

# ============================================================================
# 1. CHECK PREREQUISITES
# ============================================================================

Write-Host "[1/10] Checking prerequisites..." -ForegroundColor Yellow

# Verify we're on Windows Server
$osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
if ($osInfo.ProductType -ne 2 -and $osInfo.ProductType -ne 3) {
    Write-Warning "This script is designed for Windows Server. Current OS: $($osInfo.Caption)"
}

# Verify this is a Domain Controller
try {
    $isDC = (Get-CimInstance -ClassName Win32_ComputerSystem).DomainRole -ge 4
    if ($isDC) {
        Write-Host "  OK - Confirmed: This is a Domain Controller" -ForegroundColor Green
    } else {
        Write-Warning "  ! This does not appear to be a Domain Controller"
    }
} catch {
    Write-Warning "  ! Could not verify DC status"
}

# ============================================================================
# 2. INSTALL OPENSSH SERVER
# ============================================================================

Write-Host "`n[2/10] Checking OpenSSH Server installation..." -ForegroundColor Yellow

$sshServerFeature = Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH.Server*'

if ($sshServerFeature.State -eq 'Installed') {
    Write-Host "  OK - OpenSSH Server is already installed" -ForegroundColor Green
} else {
    Write-Host "  Installing OpenSSH Server capability..." -ForegroundColor Cyan
    try {
        Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0 | Out-Null
        Write-Host "  OK - OpenSSH Server installed successfully" -ForegroundColor Green
    } catch {
        Write-Error "  ERROR - Failed to install OpenSSH Server: $_"
        exit 1
    }
}

# ============================================================================
# 3. CONFIGURE SERVICES
# ============================================================================

Write-Host "`n[3/10] Configuring SSH services..." -ForegroundColor Yellow

# Configure sshd service
$sshdService = Get-Service -Name sshd -ErrorAction SilentlyContinue
if ($sshdService) {
    Set-Service -Name sshd -StartupType 'Automatic' -ErrorAction Stop
    Write-Host "  OK - sshd service set to Automatic" -ForegroundColor Green
} else {
    Write-Error "  ERROR - sshd service not found"
    exit 1
}

# Configure ssh-agent service
$sshAgentService = Get-Service -Name ssh-agent -ErrorAction SilentlyContinue
if ($sshAgentService) {
    Set-Service -Name ssh-agent -StartupType 'Automatic' -ErrorAction Stop
    Write-Host "  OK - ssh-agent service set to Automatic" -ForegroundColor Green
}

# ============================================================================
# 4. CONFIGURE FIREWALL
# ============================================================================

Write-Host "`n[4/10] Configuring Windows Firewall..." -ForegroundColor Yellow

$firewallRuleName = "OpenSSH-Server-In-TCP"
$existingRule = Get-NetFirewallRule -DisplayName $firewallRuleName -ErrorAction SilentlyContinue

if ($existingRule) {
    Set-NetFirewallRule -DisplayName $firewallRuleName -LocalPort $SshPort -Enabled True -ErrorAction Stop
    Write-Host "  OK - Updated existing firewall rule for port $SshPort" -ForegroundColor Green
} else {
    New-NetFirewallRule -Name 'sshd' -DisplayName $firewallRuleName -Description 'Inbound rule for OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort $SshPort -Profile Any -ErrorAction Stop | Out-Null
    Write-Host "  OK - Created firewall rule for port $SshPort" -ForegroundColor Green
}

# ============================================================================
# 5. BACKUP EXISTING SSHD_CONFIG
# ============================================================================

Write-Host "`n[5/10] Backing up configuration..." -ForegroundColor Yellow

$sshdConfigPath = "C:\ProgramData\ssh\sshd_config"
$sshdConfigBackup = "C:\ProgramData\ssh\sshd_config.backup_$(Get-Date -Format 'yyyyMMdd_HHmmss')"

if (Test-Path $sshdConfigPath) {
    Copy-Item -Path $sshdConfigPath -Destination $sshdConfigBackup -Force
    Write-Host "  OK - Backed up sshd_config to: $sshdConfigBackup" -ForegroundColor Green
} else {
    Write-Warning "  ! sshd_config not found - will be created on first service start"
}

# ============================================================================
# 6. GENERATE HOST KEYS
# ============================================================================

Write-Host "`n[6/10] Ensuring SSH host keys exist..." -ForegroundColor Yellow

$sshHostKeyPath = "C:\ProgramData\ssh\ssh_host_rsa_key"
if (-not (Test-Path $sshHostKeyPath)) {
    Write-Host "  Generating host keys..." -ForegroundColor Cyan
    Start-Service sshd -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 3
    Stop-Service sshd -ErrorAction SilentlyContinue
}

if (Test-Path $sshHostKeyPath) {
    Write-Host "  OK - SSH host keys present" -ForegroundColor Green
} else {
    Write-Warning "  ! Host keys will be generated on first start"
}

# ============================================================================
# 7. CONFIGURE SSHD_CONFIG
# ============================================================================

Write-Host "`n[7/10] Configuring sshd_config..." -ForegroundColor Yellow

$sshConfigDir = "C:\ProgramData\ssh"
if (-not (Test-Path $sshConfigDir)) {
    New-Item -Path $sshConfigDir -ItemType Directory -Force | Out-Null
}

if (-not (Test-Path $sshdConfigPath)) {
    Write-Host "  Generating default sshd_config..." -ForegroundColor Cyan
    Start-Service sshd -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    Stop-Service sshd -ErrorAction SilentlyContinue
}

$configContent = Get-Content $sshdConfigPath -ErrorAction SilentlyContinue

function Set-SshdConfigDirective {
    param([string]$Directive, [string]$Value)
    $pattern = "^\s*#?\s*$Directive\s+"
    $newLine = "$Directive $Value"
    if ($script:configContent -match $pattern) {
        $script:configContent = $script:configContent -replace $pattern, $newLine
    } else {
        $script:configContent += "`n$newLine"
    }
}

if ($SshPort -ne 22) {
    Set-SshdConfigDirective -Directive "Port" -Value $SshPort
    Write-Host "  OK - Set Port to $SshPort" -ForegroundColor Green
}

if ($AllowPasswordAuth) {
    Set-SshdConfigDirective -Directive "PasswordAuthentication" -Value "yes"
    Write-Host "  OK - Enabled PasswordAuthentication" -ForegroundColor Green
} else {
    Set-SshdConfigDirective -Directive "PasswordAuthentication" -Value "no"
    Write-Host "  OK - Disabled PasswordAuthentication" -ForegroundColor Green
}

if ($AllowPubkeyAuth) {
    Set-SshdConfigDirective -Directive "PubkeyAuthentication" -Value "yes"
    Write-Host "  OK - Enabled PubkeyAuthentication" -ForegroundColor Green
}

Set-SshdConfigDirective -Directive "PermitRootLogin" -Value "no"
Set-SshdConfigDirective -Directive "StrictModes" -Value "yes"
Set-SshdConfigDirective -Directive "MaxAuthTries" -Value "3"
Set-SshdConfigDirective -Directive "MaxSessions" -Value "5"
Set-SshdConfigDirective -Directive "LogLevel" -Value "VERBOSE"
Set-SshdConfigDirective -Directive "SyslogFacility" -Value "LOCAL0"
Set-SshdConfigDirective -Directive "AuthorizedKeysFile" -Value ".ssh/authorized_keys"

if ($configContent -notmatch "administrators_authorized_keys") {
    $configContent += "`n# For administrators, keys must be in:"
    $configContent += "`nMatch Group administrators"
    $configContent += "`n       AuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys"
}

Write-Host "  OK - Applied security hardening directives" -ForegroundColor Green
$configContent | Set-Content -Path $sshdConfigPath -Force

# ============================================================================
# 8. SETUP ADMINISTRATORS_AUTHORIZED_KEYS
# ============================================================================

Write-Host "`n[8/10] Setting up administrators_authorized_keys..." -ForegroundColor Yellow

$adminKeysPath = "C:\ProgramData\ssh\administrators_authorized_keys"

if (-not (Test-Path $adminKeysPath)) {
    New-Item -Path $adminKeysPath -ItemType File -Force | Out-Null
    Write-Host "  OK - Created $adminKeysPath" -ForegroundColor Green
}

try {
    $acl = Get-Acl $adminKeysPath
    $acl.SetAccessRuleProtection($true, $false)
    $acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) } | Out-Null
    
    $systemSid = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-18")
    $systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule($systemSid, "FullControl", "Allow")
    $acl.AddAccessRule($systemRule)
    
    $adminsSid = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")
    $adminsRule = New-Object System.Security.AccessControl.FileSystemAccessRule($adminsSid, "FullControl", "Allow")
    $acl.AddAccessRule($adminsRule)
    
    Set-Acl -Path $adminKeysPath -AclObject $acl
    Write-Host "  OK - Set proper ACLs on administrators_authorized_keys" -ForegroundColor Green
} catch {
    Write-Warning "  ! Failed to set ACLs: $_"
}

# ============================================================================
# 9. CREATE AD GROUP (Optional)
# ============================================================================

if ($RestrictToAdGroup) {
    Write-Host "`n[9/10] Setting up AD group for SSH access restriction..." -ForegroundColor Yellow
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        $adGroup = Get-ADGroup -Filter "Name -eq '$SshAccessGroupName'" -ErrorAction SilentlyContinue
        if (-not $adGroup) {
            $domainDN = (Get-ADDomain).DistinguishedName
            New-ADGroup -Name $SshAccessGroupName -GroupScope Global -GroupCategory Security -Description "Members can SSH to Domain Controllers" -Path "CN=Users,$domainDN"
            Write-Host "  OK - Created AD group: $SshAccessGroupName" -ForegroundColor Green
        } else {
            Write-Host "  OK - AD group already exists: $SshAccessGroupName" -ForegroundColor Green
        }
        $configContent = Get-Content $sshdConfigPath
        $domain = (Get-ADDomain).NetBIOSName
        $allowGroupsLine = "AllowGroups $domain\$SshAccessGroupName"
        if ($configContent -notmatch "AllowGroups") {
            $configContent += "`n# Restrict SSH access to specific AD group"
            $configContent += "`n$allowGroupsLine"
            $configContent | Set-Content -Path $sshdConfigPath -Force
            Write-Host "  OK - Added AllowGroups restriction" -ForegroundColor Green
        }
    } catch {
        Write-Warning "  ! Could not configure AD group restriction: $_"
    }
} else {
    Write-Host "`n[9/10] Skipping AD group restriction" -ForegroundColor Yellow
}

# ============================================================================
# 10. START SERVICES AND VERIFY
# ============================================================================

Write-Host "`n[10/10] Starting services and verifying..." -ForegroundColor Yellow

try {
    Start-Service ssh-agent -ErrorAction SilentlyContinue
    Restart-Service sshd -Force -ErrorAction Stop
    Start-Sleep -Seconds 2
    
    $sshdStatus = Get-Service sshd
    if ($sshdStatus.Status -eq 'Running') {
        Write-Host "  OK - sshd service is running" -ForegroundColor Green
    } else {
        Write-Warning "  ! sshd service status: $($sshdStatus.Status)"
    }
    
    $listening = Get-NetTCPConnection -LocalPort $SshPort -State Listen -ErrorAction SilentlyContinue
    if ($listening) {
        Write-Host "  OK - SSH is listening on port $SshPort" -ForegroundColor Green
    } else {
        Write-Warning "  ! Port $SshPort is not listening yet"
    }
} catch {
    Write-Error "  ERROR - Failed to start services: $_"
    Write-Host "`n  Check logs: Get-WinEvent -LogName 'OpenSSH/Operational' -MaxEvents 20" -ForegroundColor Yellow
    exit 1
}

# ============================================================================
# INSTALLATION COMPLETE
# ============================================================================

Write-Host "`n========================================" -ForegroundColor Green
Write-Host "SUCCESS - OpenSSH Server Installation Complete" -ForegroundColor Green
Write-Host "========================================`n" -ForegroundColor Green

Write-Host "Configuration Summary:" -ForegroundColor Cyan
Write-Host "  Port:                   $SshPort" -ForegroundColor White
Write-Host "  Password Auth:          $AllowPasswordAuth" -ForegroundColor White
Write-Host "  Public Key Auth:        $AllowPubkeyAuth" -ForegroundColor White
Write-Host "  AD Group Restriction:   $RestrictToAdGroup" -ForegroundColor White
if ($RestrictToAdGroup) {
    Write-Host "  Allowed Group:          $SshAccessGroupName" -ForegroundColor White
}
Write-Host "  Config File:            $sshdConfigPath" -ForegroundColor White
Write-Host "  Admin Keys File:        $adminKeysPath" -ForegroundColor White

Write-Host "`nNext Steps:" -ForegroundColor Yellow
Write-Host "  1. Add user public keys to $adminKeysPath" -ForegroundColor White
Write-Host "  2. Test: ssh DOMAIN\username@$($env:COMPUTERNAME)" -ForegroundColor White
Write-Host "  3. Review logs: Get-WinEvent -LogName 'OpenSSH/Operational' -MaxEvents 10" -ForegroundColor White

if ($AllowPasswordAuth) {
    Write-Host "`nSECURITY RECOMMENDATION:" -ForegroundColor Yellow
    Write-Host "  After testing public key auth, disable password auth for better security." -ForegroundColor White
}
