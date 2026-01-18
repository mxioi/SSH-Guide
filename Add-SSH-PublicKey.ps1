#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Add SSH public key for Windows SSH Server authentication
.DESCRIPTION
    Adds a public key to the correct location with proper permissions.
    Automatically detects if user is an administrator and uses the appropriate file.
.PARAMETER PublicKey
    The SSH public key to add (ssh-ed25519 AAAA... or ssh-rsa AAAA...)
.PARAMETER Username
    Username to add key for (defaults to current user)
.EXAMPLE
    .\Add-SSH-PublicKey.ps1 -PublicKey "ssh-ed25519 AAAAC3Nza... user@host"
.EXAMPLE
    Get-Content my_key.pub | .\Add-SSH-PublicKey.ps1
#>

param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
    [string]$PublicKey,
    
    [Parameter(Mandatory=$false)]
    [string]$Username = $env:USERNAME
)

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Add SSH Public Key" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# Trim whitespace
$PublicKey = $PublicKey.Trim()

# Validate key format
if ($PublicKey -notmatch '^(ssh-rsa|ssh-ed25519|ecdsa-sha2-nistp256|ssh-dss) [A-Za-z0-9+/]+=* .*') {
    Write-Error "Invalid public key format. Expected: ssh-ed25519 AAAA... comment"
    exit 1
}

Write-Host "Public Key: $($PublicKey.Substring(0, [Math]::Min(60, $PublicKey.Length)))..." -ForegroundColor White

# Check if user is administrator
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if ($isAdmin) {
    Write-Host "User Type: Administrator" -ForegroundColor Yellow
    $keyFile = "C:\ProgramData\ssh\administrators_authorized_keys"
} else {
    Write-Host "User Type: Standard User" -ForegroundColor Yellow
    $keyFile = "$env:USERPROFILE\.ssh\authorized_keys"
}

Write-Host "Key File: $keyFile" -ForegroundColor Cyan

# Create directory if needed
$keyDir = Split-Path $keyFile
if (-not (Test-Path $keyDir)) {
    Write-Host "`nCreating directory: $keyDir" -ForegroundColor Yellow
    New-Item -ItemType Directory -Path $keyDir -Force | Out-Null
    Write-Host "  OK - Directory created" -ForegroundColor Green
}

# Check if key already exists
if (Test-Path $keyFile) {
    $existingKeys = Get-Content $keyFile -Raw -ErrorAction SilentlyContinue
    if ($existingKeys -and $existingKeys.Contains($PublicKey)) {
        Write-Host "`n  INFO - Key already exists in file" -ForegroundColor Yellow
        Write-Host "  No changes made" -ForegroundColor Yellow
        exit 0
    }
}

# Add key
Write-Host "`nAdding public key..." -ForegroundColor Yellow
try {
    if (Test-Path $keyFile) {
        Add-Content -Path $keyFile -Value $PublicKey -ErrorAction Stop
    } else {
        $PublicKey | Set-Content -Path $keyFile -Force -ErrorAction Stop
    }
    Write-Host "  OK - Key added" -ForegroundColor Green
} catch {
    Write-Error "  ERROR - Failed to add key: $_"
    exit 1
}

# Fix permissions
Write-Host "`nSetting correct permissions..." -ForegroundColor Yellow

if ($isAdmin) {
    # Administrator key file: ONLY SYSTEM and Administrators
    try {
        icacls $keyFile /inheritance:r | Out-Null
        icacls $keyFile /grant "NT AUTHORITY\SYSTEM:(F)" | Out-Null
        icacls $keyFile /grant "BUILTIN\Administrators:(F)" | Out-Null
        Write-Host "  OK - Set SYSTEM and Administrators permissions" -ForegroundColor Green
    } catch {
        Write-Error "  ERROR - Failed to set permissions: $_"
        exit 1
    }
} else {
    # Standard user key file: User + SYSTEM + Administrators
    try {
        icacls $keyFile /inheritance:r | Out-Null
        icacls $keyFile /grant "${env:USERNAME}:(F)" | Out-Null
        icacls $keyFile /grant "NT AUTHORITY\SYSTEM:(F)" | Out-Null
        icacls $keyFile /grant "BUILTIN\Administrators:(F)" | Out-Null
        Write-Host "  OK - Set user, SYSTEM, and Administrators permissions" -ForegroundColor Green
    } catch {
        Write-Error "  ERROR - Failed to set permissions: $_"
        exit 1
    }
}

# Verify permissions
Write-Host "`nVerifying permissions..." -ForegroundColor Yellow
$perms = icacls $keyFile 2>&1
$perms | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }

# Restart SSH service
Write-Host "`nRestarting SSH service..." -ForegroundColor Yellow
try {
    Restart-Service sshd -Force -ErrorAction Stop
    Write-Host "  OK - Service restarted" -ForegroundColor Green
} catch {
    Write-Warning "  WARNING - Failed to restart service: $_"
    Write-Host "  Manually restart with: Restart-Service sshd" -ForegroundColor Yellow
}

# Success
Write-Host "`n========================================" -ForegroundColor Green
Write-Host "SUCCESS - Public Key Added" -ForegroundColor Green
Write-Host "========================================`n" -ForegroundColor Green

Write-Host "Key file: $keyFile" -ForegroundColor Cyan
Write-Host "`nTest the connection:" -ForegroundColor Yellow
if ($env:USERDOMAIN) {
    Write-Host "  ssh $env:USERDOMAIN\$Username@localhost" -ForegroundColor White
} else {
    Write-Host "  ssh $Username@localhost" -ForegroundColor White
}
Write-Host ""

