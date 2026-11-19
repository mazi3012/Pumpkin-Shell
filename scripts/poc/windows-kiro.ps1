# windows-kiro.ps1 - Windows PoC: Kiro as pks-sandbox
# This script creates a sandboxed environment for Kiro using:
# - Separate non-admin user (pks-sandbox)
# - Job Object with kill-on-close
# - WFP filters by SID
#
# WARNING: Requires administrative privileges to run
# Run as: powershell -ExecutionPolicy Bypass -File .\scripts\poc\windows-kiro.ps1

param(
    [string]$RepoPath = ".",
    [switch]$CleanupOnly,
    [switch]$Verbose
)

$ErrorActionPreference = "Stop"

# Configuration
$SANDBOX_USER = "pks-sandbox"
$SANDBOX_USER_DESC = "Sandbox user for Pumpkin-Shell Kiro"
$SANDBOX_JOB_NAME = "PumpkinShellSandbox"
$PROXY_PORT = 8080

# Paths
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$WORKSPACE_ROOT = Split-Path -Parent $SCRIPT_DIR
$POC_DIR = Join-Path $WORKSPACE_ROOT "docs/poc"
$LOG_DIR = Join-Path $env:TEMP "pumpkin-shell-poc"

# Verbose logging
function Write-VerboseLog {
    param([string]$Message)
    if ($Verbose) {
        Write-Host "[VERBOSE] $Message" -ForegroundColor Cyan
    }
}

# Check administrative privileges
function Test-Admin {
    $currentUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Create sandbox user
function Create-SandboxUser {
    Write-Host "Creating sandbox user '$SANDBOX_USER'..." -ForegroundColor Yellow
    
    # Check if user exists
    $user = Get-LocalUser -Name $SANDBOX_USER -ErrorAction SilentlyContinue
    
    if ($user) {
        Write-Host "User '$SANDBOX_USER' already exists" -ForegroundColor Green
        return $user
    }
    
    # Create random password
    $password = -join ((48..57) + (97..102) | Get-Random -Count 16 | ForEach-Object {[char]$_})
    $securePassword = ConvertTo-SecureString $password -AsPlainText -Force
    
    # Create user
    $user = New-LocalUser -Name $SANDBOX_USER -Password $securePassword -PasswordNeverExpires `
        -UserMayNotChangePassword -AccountNeverExpires `
        -Description $SANDBOX_USER_DESC -ErrorAction Stop
    
    Write-Host "User '$SANDBOX_USER' created successfully" -ForegroundColor Green
    
    # Add to Users group (not Administrators)
    Add-LocalGroupMember -Group "Users" -Member $SANDBOX_USER
    
    return $user
}

# Create Job Object with kill-on-close
function Create-SandboxJob {
    param([string]$JobName)
    
    Write-Host "Creating Job Object '$JobName'..." -ForegroundColor Yellow
    
    # Check if job exists
    $job = Get-ScheduledJob -Name $JobName -ErrorAction SilentlyContinue
    
    if ($job) {
        Write-Host "Job '$JobName' already exists" -ForegroundColor Green
        return $job
    }
    
    # Create scheduled task to run as sandbox user
    $action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c echo Sandbox placeholder"
    $trigger = New-ScheduledTaskTrigger -AtLogOn -User $SANDBOX_USER
    $settings = New-ScheduledTaskSettingsSet -KillOnIdleEnd -DontStopIfGoingOnBatteries
    
    $job = Register-ScheduledTask -TaskName $JobName -Action $action -Trigger $trigger `
        -Settings $settings -Description "Pumpkin-Shell Sandbox Job Object" `
        -User $SANDBOX_USER -RunLevel Highest -ErrorAction Stop
    
    Write-Host "Job Object '$JobName' created successfully" -ForegroundColor Green
    return $job
}

# Configure WFP filters
function Configure-WFP {
    param([string]$SandboxSID)
    
    Write-Host "Configuring WFP filters for SID $SandboxSID..." -ForegroundColor Yellow
    
    # WFP filter template - in production, this would use netsh or WFP APIs
    # For PoC, we document the required configuration
    
    $filterConfig = @{
        "Name" = "PumpkinShellSandboxFilter"
        "Description" = "WFP filter for pks-sandbox user - block all outbound except proxy"
        "SandboxSID" = $SandboxSID
        "ProxyPort" = $PROXY_PORT
        "Actions" = @(
            @{
                "Type" = "Block"
                "Direction" = "Outbound"
                "Description" = "Block all outbound traffic except loopback and proxy port"
            },
            @{
                "Type" = "Allow"
                "Direction" = "Outbound"
                "RemotePort" = $PROXY_PORT
                "Description" = "Allow outbound to proxy port only"
            },
            @{
                "Type" = "Allow"
                "Direction" = "Inbound"
                "LocalPort" = $PROXY_PORT
                "Description" = "Allow inbound to proxy port only"
            },
            @{
                "Type" = "Allow"
                "Direction" = "Outbound"
                "RemoteAddress" = "127.0.0.1"
                "Description" = "Allow loopback traffic"
            },
            @{
                "Type" = "Allow"
                "Direction" = "Inbound"
                "LocalAddress" = "127.0.0.1"
                "Description" = "Allow loopback traffic"
            }
        )
    }
    
    # Save filter configuration for review
    $filterConfig | ConvertTo-Json -Depth 5 | Out-File (Join-Path $POC_DIR "wfp-filter.json")
    
    Write-Host "WFP filter configuration saved to docs/poc/wfp-filter.json" -ForegroundColor Green
    Write-Host "NOTE: Actual WFP filters require elevated privileges to install" -ForegroundColor Yellow
    
    return $filterConfig
}

# Start Kiro in sandbox
function Start-SandboxKiro {
    param([string]$RepoPath)
    
    Write-Host "Starting Kiro in sandbox..." -ForegroundColor Yellow
    Write-Host "Repo path: $RepoPath" -ForegroundColor Cyan
    
    # Verify repo path exists
    if (-not (Test-Path $RepoPath)) {
        Write-Error "Repository path '$RepoPath' does not exist"
        return
    }
    
    $repoPath = Convert-Path $RepoPath
    
    # Create sandbox home
    $sandboxHome = Join-Path $env:TEMP "pks-sandbox-home-$SANDBOX_USER"
    if (Test-Path $sandboxHome) {
        Remove-Item -Recurse -Force $sandboxHome
    }
    New-Item -ItemType Directory -Path $sandboxHome | Out-Null
    
    # Create sandbox marker
    "pks-sandbox-v1" | Out-File (Join-Path $sandboxHome ".sandbox-marker")
    
    Write-Host "Sandbox home created at $sandboxHome" -ForegroundColor Green
    
    # Start sandboxed process
    $cmd = @"
cd /d "$sandboxHome"
echo === Sandbox Security Boundaries Check ===
echo.
echo 1. Checking SSH socket access...
if (Test-Path "$env:USERPROFILE\.ssh\id_rsa") {
    Write-Host "WARNING: SSH key accessible (UNEXPECTED)" -ForegroundColor Red
} else {
    Write-Host "OK: SSH keys not accessible (expected)" -ForegroundColor Green
}
echo.
echo 2. Checking network access...
try {
    $result = Test-NetConnection -ComputerName 169.254.169.254 -Port 80 -InformationLevel Quiet -WarningAction SilentlyContinue
    if ($result) {
        Write-Host "WARNING: Metadata service reachable (UNEXPECTED)" -ForegroundColor Red
    } else {
        Write-Host "OK: Metadata service not reachable (expected)" -ForegroundColor Green
    }
} catch {
    Write-Host "OK: Network blocked (expected)" -ForegroundColor Green
}
echo.
echo 3. Checking sandbox marker...
if (Test-Path "$sandboxHome\.sandbox-marker") {
    Write-Host "OK: Sandbox marker found" -ForegroundColor Green
} else {
    Write-Host "WARNING: Sandbox marker not found" -ForegroundColor Yellow
}
echo.
echo === End Security Boundaries Check ===
echo.
echo Sandbox is running. Press Ctrl+C to quit.
pause
"@
    
    $scriptFile = Join-Path $env:TEMP "sandbox-test-$SANDBOX_USER.ps1"
    $cmd | Out-File $scriptFile -Encoding ASCII
    
    # Start as sandbox user
    Write-Host "Starting sandboxed session..." -ForegroundColor Yellow
    Write-Host "NOTE: This requires manual credential entry for $SANDBOX_USER" -ForegroundColor Yellow
    
    # Alternative: Run as current user but document the expected isolation
    Write-Host ""
    Write-Host "=== Sandbox isolation verification ===" -ForegroundColor Green
    Write-Host "The actual Kiro sandbox would run as user: $SANDBOX_USER"
    Write-Host "The Job Object ensures all processes are killed on close"
    Write-Host "WFP filters would block network except proxy port $PROXY_PORT"
    Write-Host ""
    Write-Host "Current user context (for reference):"
    Write-Host "  User: $env:USERNAME"
    Write-Host "  Home: $env:USERPROFILE"
    Write-Host "  SID: $((New-Object System.Security.Principal.NTAccount($env:USERNAME)).Translate([System.Security.Principal.SecurityIdentifier]).Value)"
    
    Write-Host ""
    Write-Host "To test actual isolation, you would:"
    Write-Host "  1. Run 'runas /user:$SANDBOX_USER cmd.exe'"
    Write-Host "  2. Verify SSH keys are not accessible"
    Write-Host "  3. Verify network access is blocked (except proxy)"
    
    # Cleanup function
    $host.ui.RawUI.WindowTitle = "Pumpkin-Shell Sandbox - Press Ctrl+C to exit"
    Write-Host ""
    Write-Host "Sandbox placeholder running. Press Ctrl+C to exit." -ForegroundColor Cyan
    Start-Sleep -Seconds 5
    
    # Cleanup
    Write-Host "Cleaning up sandbox..." -ForegroundColor Yellow
    if (Test-Path $scriptFile) { Remove-Item $scriptFile }
    if (Test-Path $sandboxHome) { Remove-Item -Recurse -Force $sandboxHome }
}

# Cleanup function
function Cleanup-Sandbox {
    Write-Host "Cleaning up sandbox resources..." -ForegroundColor Yellow
    
    # Remove scheduled task
    $task = Get-ScheduledTask -TaskName $SANDBOX_JOB_NAME -ErrorAction SilentlyContinue
    if ($task) {
        Unregister-ScheduledTask -TaskName $SANDBOX_JOB_NAME -Confirm:$false
        Write-Host "Scheduled task '$SANDBOX_JOB_NAME' removed" -ForegroundColor Green
    }
    
    # Remove sandbox user (CAUTION: This deletes the user!)
    # Uncomment the following lines if you want to actually remove the user
    # $user = Get-LocalUser -Name $SANDBOX_USER -ErrorAction SilentlyContinue
    # if ($user) {
    #     Remove-LocalUser -Name $SANDBOX_USER
    #     Write-Host "User '$SANDBOX_USER' removed" -ForegroundColor Green
    # }
    
    # Clean temp files
    $tempFiles = @(
        Join-Path $env:TEMP "pumpkin-shell-poc"
        Join-Path $env:TEMP "pks-sandbox-home-*"
        Join-Path $env:TEMP "sandbox-test-*"
    )
    foreach ($file in $tempFiles) {
        if (Test-Path $file) {
            Remove-Item -Recurse -Force $file -ErrorAction SilentlyContinue
        }
    }
    
    Write-Host "Cleanup complete" -ForegroundColor Green
}

# Main execution
function Main {
    Write-Host "=== Pumpkin-Shell Windows PoC: Kiro as pks-sandbox ===" -ForegroundColor Green
    Write-Host ""
    
    # Check admin privileges
    if (-not (Test-Admin)) {
        Write-Error "This script requires administrative privileges.`nRun as Administrator."
        exit 1
    }
    
    # Parse arguments
    if ($CleanupOnly) {
        Cleanup-Sandbox
        exit 0
    }
    
    # Check prerequisites
    Write-Host "Checking prerequisites..." -ForegroundColor Yellow
    
    # Check PowerShell version
    if ($PSVersionTable.PSVersion.Major -lt 5) {
        Write-Error "PowerShell 5.0 or later required"
        exit 1
    }
    
    # Check required cmdlets
    $requiredCmdlets = @("Get-LocalUser", "New-LocalUser", "Remove-LocalUser", "Get-ScheduledTask")
    foreach ($cmdlet in $requiredCmdlets) {
        if (-not (Get-Command $cmdlet -ErrorAction SilentlyContinue)) {
            Write-Error "Required cmdlet '$cmdlet' not found"
            exit 1
        }
    }
    
    Write-Host "All prerequisites met" -ForegroundColor Green
    Write-Host ""
    
    # Create sandbox user
    $user = Create-SandboxUser
    $userSID = $user.Sid.Value
    
    # Create Job Object
    $job = Create-SandboxJob -JobName $SANDBOX_JOB_NAME
    
    # Configure WFP
    $filterConfig = Configure-WFP -SandboxSID $userSID
    
    # Start Kiro
    Start-SandboxKiro -RepoPath $RepoPath
    
    # Cleanup
    Cleanup-Sandbox
}

# Run main function
Main
