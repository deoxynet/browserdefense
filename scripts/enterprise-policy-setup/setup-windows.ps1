# BrowserDefense Enterprise Policy Setup for Windows
#
# This script installs the BrowserDefense extension via Chrome enterprise policy,
# enabling webRequestBlocking permissions for MV3.
#
# REQUIREMENTS:
# - Windows with Chrome installed
# - Administrator privileges
# - Built extension in dist/ directory with known extension ID
#
# USAGE:
#   Run as Administrator:
#   .\setup-windows.ps1 -ExtensionId "abcdefghijklmnopqrstuvwxyzabcdef"
#   .\setup-windows.ps1 -ExtensionId "abcdefghijklmnopqrstuvwxyzabcdef" -UpdateUrl "https://your-server.com/updates.xml"
#
# NOTES:
# - Chrome must be restarted after policy installation
# - Extension will show "Installed by enterprise policy"
# - Extension cannot be disabled/uninstalled by user
#

param(
    [Parameter(Mandatory=$true)]
    [ValidatePattern("^[a-z]{32}$")]
    [string]$ExtensionId,

    [Parameter(Mandatory=$false)]
    [string]$UpdateUrl = ""
)

# Check for Administrator privileges
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "This script must be run as Administrator"
    Write-Host "Right-click PowerShell and select 'Run as Administrator'"
    exit 1
}

Write-Host "=== BrowserDefense Enterprise Policy Setup for Windows ===" -ForegroundColor Cyan
Write-Host "Extension ID: $ExtensionId"
Write-Host "Update URL: $(if ($UpdateUrl) { $UpdateUrl } else { '<none - local development mode>' })"
Write-Host ""

# Registry paths
$ChromePoliciesPath = "HKLM:\SOFTWARE\Policies\Google\Chrome"
$ExtensionForcelist = "$ChromePoliciesPath\ExtensionInstallForcelist"
$ExtensionSettings = "$ChromePoliciesPath\ExtensionSettings\$ExtensionId"

# Build policy value
if ($UpdateUrl) {
    $PolicyValue = "${ExtensionId};${UpdateUrl}"
} else {
    $PolicyValue = $ExtensionId
}

# Create Chrome policies key if it doesn't exist
if (-not (Test-Path $ChromePoliciesPath)) {
    New-Item -Path $ChromePoliciesPath -Force | Out-Null
    Write-Host "[OK] Created Chrome policies registry key"
}

# Create ExtensionInstallForcelist key
if (-not (Test-Path $ExtensionForcelist)) {
    New-Item -Path $ExtensionForcelist -Force | Out-Null
    Write-Host "[OK] Created ExtensionInstallForcelist registry key"
}

# Find next available index for forcelist
$existingValues = Get-ItemProperty -Path $ExtensionForcelist -ErrorAction SilentlyContinue
$nextIndex = 1
if ($existingValues) {
    $existingIndices = $existingValues.PSObject.Properties |
        Where-Object { $_.Name -match "^\d+$" } |
        ForEach-Object { [int]$_.Name }
    if ($existingIndices) {
        $nextIndex = ($existingIndices | Measure-Object -Maximum).Maximum + 1
    }
}

# Add extension to forcelist
Set-ItemProperty -Path $ExtensionForcelist -Name $nextIndex -Value $PolicyValue
Write-Host "[OK] Added extension to ExtensionInstallForcelist at index $nextIndex"

# Create ExtensionSettings for granular control
$ExtensionSettingsPath = "$ChromePoliciesPath\ExtensionSettings"
if (-not (Test-Path $ExtensionSettingsPath)) {
    New-Item -Path $ExtensionSettingsPath -Force | Out-Null
}
if (-not (Test-Path $ExtensionSettings)) {
    New-Item -Path $ExtensionSettings -Force | Out-Null
}

# Set extension settings
Set-ItemProperty -Path $ExtensionSettings -Name "installation_mode" -Value "force_installed"
Write-Host "[OK] Set installation_mode to force_installed"

Write-Host ""
Write-Host "=== Installation Complete ===" -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:"
Write-Host "  1. Close all Chrome windows"
Write-Host "  2. Reopen Chrome"
Write-Host "  3. Navigate to chrome://extensions"
Write-Host "  4. Verify BrowserDefense shows 'Installed by enterprise policy'"
Write-Host "  5. Run enterprise integration tests:"
Write-Host "     npm run test:e2e -- --grep 'Enterprise'"
Write-Host ""
Write-Host "To remove policy:" -ForegroundColor Yellow
Write-Host "  Run as Administrator:"
Write-Host "  Remove-Item -Path '$ExtensionForcelist' -Recurse"
Write-Host "  Remove-Item -Path '$ExtensionSettings' -Recurse"
Write-Host "  Then restart Chrome"
