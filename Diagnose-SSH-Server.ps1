#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Diagnoses and fixes common Windows SSH Server issues.

.DESCRIPTION
    This script checks SSH server configuration, permissions, and connectivity.
    It can automatically fix common permission issues with authorized_keys files.

.PARAMETER PublicKey
    Optional. A public key to ensure is present in administrators_authorized_keys.
    If not provided, the script only diagnoses without adding keys.

.EXAMPLE
    .\Diagnose-SSH-Server.ps1
    # Runs diagnostics only

.EXAMPLE
    .\Diagnose-SSH-Server.ps1 -PublicKey "ssh-ed25519 AAAA... user@client"
    # Runs diagnostics and ensures the specified key is present
#>

param(
    [string]$PublicKey = ""
)

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "SSH Server Diagnostic Tool" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

$authKeysFile = "C:\ProgramData\ssh\administrators_authorized_keys"
$sshdConfig = "C:\ProgramData\ssh\sshd_config"

# Step 1: Check SSH Service
Write-Host "[1/7] Checking SSH service status..." -ForegroundColor Yellow
$service = Get-Service sshd -ErrorAction SilentlyContinue
if ($service) {
    Write-Host "  Service: $($service.Name)" -ForegroundColor White
    Write-Host "  Status: $($service.Status)" -ForegroundColor $(if ($service.Status -eq 'Running') { 'Green' } else { 'Red' })
    Write-Host "  StartType: $($service.StartType)" -ForegroundColor White

    if ($service.Status -ne 'Running') {
        Write-Host "  Attempting to start service..." -ForegroundColor Yellow
        Start-Service sshd -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
        $service = Get-Service sshd
        Write-Host "  New Status: $($service.Status)" -ForegroundColor $(if ($service.Status -eq 'Running') { 'Green' } else { 'Red' })
    }
} else {
    Write-Host "  ERROR - SSH service not installed!" -ForegroundColor Red
    Write-Host "  Run: Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0" -ForegroundColor Yellow
}

# Step 2: Check if listening on port 22
Write-Host "`n[2/7] Checking if SSH is listening..." -ForegroundColor Yellow
$listening = Get-NetTCPConnection -LocalPort 22 -State Listen -ErrorAction SilentlyContinue
if ($listening) {
    Write-Host "  OK - Listening on port 22" -ForegroundColor Green
    Write-Host "  Local Address: $($listening.LocalAddress):$($listening.LocalPort)" -ForegroundColor White
} else {
    Write-Host "  ERROR - Not listening on port 22" -ForegroundColor Red
    Write-Host "  Check firewall and service status" -ForegroundColor Yellow
}

# Step 3: Check firewall rule
Write-Host "`n[3/7] Checking firewall rules..." -ForegroundColor Yellow
$fwRule = Get-NetFirewallRule -DisplayName "*OpenSSH*" -ErrorAction SilentlyContinue
if ($fwRule) {
    foreach ($rule in $fwRule) {
        $enabled = if ($rule.Enabled) { "Yes" } else { "No" }
        Write-Host "  Rule: $($rule.DisplayName)" -ForegroundColor White
        Write-Host "    Enabled: $enabled, Direction: $($rule.Direction)" -ForegroundColor White
    }
} else {
    Write-Host "  WARNING - No OpenSSH firewall rule found" -ForegroundColor Yellow
    Write-Host "  Creating firewall rule..." -ForegroundColor Yellow
    New-NetFirewallRule -Name sshd -DisplayName 'OpenSSH-Server-In-TCP' `
        -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22 | Out-Null
    Write-Host "  OK - Firewall rule created" -ForegroundColor Green
}

# Step 4: Check sshd_config
Write-Host "`n[4/7] Checking sshd_config..." -ForegroundColor Yellow
if (Test-Path $sshdConfig) {
    Write-Host "  OK - Config file exists" -ForegroundColor Green

    # Check key settings
    $config = Get-Content $sshdConfig -Raw

    $pubkeyAuth = if ($config -match "(?m)^PubkeyAuthentication\s+(\w+)") { $matches[1] } else { "yes (default)" }
    $passwordAuth = if ($config -match "(?m)^PasswordAuthentication\s+(\w+)") { $matches[1] } else { "yes (default)" }
    $allowGroups = if ($config -match "(?m)^AllowGroups\s+(.+)$") { $matches[1] } else { "not set" }

    Write-Host "  PubkeyAuthentication: $pubkeyAuth" -ForegroundColor White
    Write-Host "  PasswordAuthentication: $passwordAuth" -ForegroundColor White
    Write-Host "  AllowGroups: $allowGroups" -ForegroundColor White

    # Check for Match Group administrators block
    if ($config -match "Match Group administrators") {
        Write-Host "  OK - Match Group administrators block found" -ForegroundColor Green
    } else {
        Write-Host "  WARNING - No 'Match Group administrators' block" -ForegroundColor Yellow
        Write-Host "  Admin keys may not work without this block" -ForegroundColor Yellow
    }
} else {
    Write-Host "  ERROR - Config file not found at $sshdConfig" -ForegroundColor Red
}

# Step 5: Check administrators_authorized_keys file
Write-Host "`n[5/7] Checking administrators_authorized_keys..." -ForegroundColor Yellow
if (Test-Path $authKeysFile) {
    Write-Host "  OK - File exists" -ForegroundColor Green

    try {
        $content = Get-Content $authKeysFile -Raw -ErrorAction Stop
        $keyCount = ($content -split "`n" | Where-Object { $_.Trim() -match "^ssh-" }).Count
        Write-Host "  Keys in file: $keyCount" -ForegroundColor White

        if ($PublicKey -and $content -notmatch [regex]::Escape($PublicKey.Substring(0, 50))) {
            Write-Host "  WARNING - Specified key not found" -ForegroundColor Yellow
            Write-Host "  Adding key..." -ForegroundColor Yellow
            Add-Content -Path $authKeysFile -Value $PublicKey
            Write-Host "  OK - Key added" -ForegroundColor Green
        } elseif ($PublicKey) {
            Write-Host "  OK - Specified key is present" -ForegroundColor Green
        }
    } catch {
        Write-Host "  ERROR - Cannot read file (permission issue?)" -ForegroundColor Red
    }
} else {
    Write-Host "  WARNING - File does not exist" -ForegroundColor Yellow
    if ($PublicKey) {
        Write-Host "  Creating file with specified key..." -ForegroundColor Yellow
        New-Item -Path $authKeysFile -ItemType File -Force | Out-Null
        $PublicKey | Set-Content -Path $authKeysFile -Force
        Write-Host "  OK - File created with key" -ForegroundColor Green
    } else {
        Write-Host "  Creating empty file..." -ForegroundColor Yellow
        New-Item -Path $authKeysFile -ItemType File -Force | Out-Null
        Write-Host "  OK - Empty file created" -ForegroundColor Green
    }
}

# Step 6: Check and fix permissions
Write-Host "`n[6/7] Checking/fixing file permissions..." -ForegroundColor Yellow
Write-Host "  Current ACLs:" -ForegroundColor Cyan
icacls $authKeysFile 2>&1 | ForEach-Object { Write-Host "    $_" -ForegroundColor White }

Write-Host "`n  Applying correct permissions..." -ForegroundColor Yellow
try {
    icacls $authKeysFile /inheritance:r 2>&1 | Out-Null
    Write-Host "    OK - Removed inheritance" -ForegroundColor Green

    icacls $authKeysFile /grant "NT AUTHORITY\SYSTEM:(F)" 2>&1 | Out-Null
    Write-Host "    OK - Granted SYSTEM full control" -ForegroundColor Green

    icacls $authKeysFile /grant "BUILTIN\Administrators:(F)" 2>&1 | Out-Null
    Write-Host "    OK - Granted Administrators full control" -ForegroundColor Green

    Write-Host "`n  New ACLs:" -ForegroundColor Cyan
    icacls $authKeysFile 2>&1 | ForEach-Object { Write-Host "    $_" -ForegroundColor White }
} catch {
    Write-Host "  ERROR - Failed to set permissions: $_" -ForegroundColor Red
}

# Step 7: Restart service and verify
Write-Host "`n[7/7] Restarting SSH service..." -ForegroundColor Yellow
try {
    Restart-Service sshd -Force -ErrorAction Stop
    Start-Sleep -Seconds 2
    Write-Host "  OK - Service restarted" -ForegroundColor Green
} catch {
    Write-Host "  ERROR - Failed to restart service: $_" -ForegroundColor Red
}

# Summary
Write-Host "`n========================================" -ForegroundColor Green
Write-Host "Diagnostic Complete" -ForegroundColor Green
Write-Host "========================================`n" -ForegroundColor Green

# Get computer and domain info for test commands
$computerName = $env:COMPUTERNAME
$domain = try { (Get-ADDomain -ErrorAction SilentlyContinue).NetBIOSName } catch { $env:USERDOMAIN }

Write-Host "Test the connection:" -ForegroundColor Yellow
Write-Host "  From this machine: ssh $domain\$env:USERNAME@localhost" -ForegroundColor Cyan
Write-Host "  From remote:       ssh $domain\username@$computerName" -ForegroundColor Cyan
Write-Host ""
Write-Host "If using non-domain account:" -ForegroundColor Yellow
Write-Host "  ssh $env:USERNAME@localhost" -ForegroundColor Cyan
Write-Host ""
