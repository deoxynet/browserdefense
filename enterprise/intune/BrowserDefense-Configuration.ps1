<#
.SYNOPSIS
    BrowserDefense Chrome Extension - PowerShell Configuration Script for Intune

.DESCRIPTION
    This script configures BrowserDefense Chrome extension settings via registry.
    Deploy as a PowerShell script in Intune or run locally for testing.

.PARAMETER ExtensionId
    The Chrome Web Store extension ID for BrowserDefense

.PARAMETER BlocklistEndpoint
    URL where the extension fetches signed blocklist updates

.PARAMETER OrgId
    Unique identifier for your organization

.PARAMETER ForensicsEndpoint
    URL where encrypted forensics data is uploaded (REQUIRED)

.PARAMETER IocSalt
    Salt for IOC hashing - must match CLI compile salt (REQUIRED)

.PARAMETER UpdateIntervalMinutes
    How frequently to check for blocklist updates (default: 60)

.PARAMETER SigningPublicKey
    P-256 ECDSA public key in JWK format (JSON string) (REQUIRED)

.PARAMETER EncryptionPublicKey
    RSA-OAEP public key in JWK format (JSON string) (REQUIRED)

.EXAMPLE
    .\BrowserDefense-Configuration.ps1 -ExtensionId "abcdefghijklmnop" -BlocklistEndpoint "https://blocklist.example.com/v1/manifest.json" -OrgId "acme-corp" -ForensicsEndpoint "https://siem.example.com/api/v1/forensics" -IocSalt "your-salt" -SigningPublicKey '{"kty":"EC",...}' -EncryptionPublicKey '{"kty":"RSA",...}'

.NOTES
    Version: 1.0.0
    Requires: Windows 10+, Chrome browser
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ExtensionId,

    [Parameter(Mandatory = $true)]
    [string]$BlocklistEndpoint,

    [Parameter(Mandatory = $true)]
    [string]$OrgId,

    [Parameter(Mandatory = $true)]
    [string]$ForensicsEndpoint,

    [Parameter(Mandatory = $true)]
    [string]$IocSalt,

    [Parameter(Mandatory = $false)]
    [int]$UpdateIntervalMinutes = 60,

    [Parameter(Mandatory = $true)]
    [string]$SigningPublicKey,

    [Parameter(Mandatory = $true)]
    [string]$EncryptionPublicKey,

    [Parameter(Mandatory = $false)]
    [switch]$EnableDebugLogging
)

$ErrorActionPreference = "Stop"

# Registry paths
$ChromePolicyPath = "HKLM:\SOFTWARE\Policies\Google\Chrome"
$ExtensionPolicyPath = "$ChromePolicyPath\3rdparty\extensions\$ExtensionId\policy"
$ExtensionSettingsPath = "$ChromePolicyPath\ExtensionSettings"

function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[$timestamp] $Message"
}

function Ensure-RegistryPath {
    param([string]$Path)
    if (-not (Test-Path $Path)) {
        New-Item -Path $Path -Force | Out-Null
        Write-Log "Created registry path: $Path"
    }
}

try {
    Write-Log "BrowserDefense Configuration Script Starting..."
    Write-Log "Extension ID: $ExtensionId"

    # Ensure base Chrome policy paths exist
    Ensure-RegistryPath $ChromePolicyPath
    Ensure-RegistryPath $ExtensionSettingsPath
    Ensure-RegistryPath $ExtensionPolicyPath

    # Configure ExtensionSettings for force-install
    $extensionSettings = @{
        $ExtensionId = @{
            installation_mode = "force_installed"
            update_url = "https://clients2.google.com/service/update2/crx"
            toolbar_pin = "force_pinned"
        }
    }
    $extensionSettingsJson = $extensionSettings | ConvertTo-Json -Compress
    Set-ItemProperty -Path $ExtensionSettingsPath -Name $ExtensionId -Value $extensionSettingsJson -Type String
    Write-Log "Configured ExtensionSettings for force-install"

    # Configure BrowserDefense-specific settings
    Write-Log "Configuring BrowserDefense settings..."

    # Blocklist Endpoint (required)
    Set-ItemProperty -Path $ExtensionPolicyPath -Name "blocklist_endpoint" -Value $BlocklistEndpoint -Type String
    Write-Log "Set blocklist_endpoint: $BlocklistEndpoint"

    # Organization ID (required)
    Set-ItemProperty -Path $ExtensionPolicyPath -Name "org_id" -Value $OrgId -Type String
    Write-Log "Set org_id: $OrgId"

    # Forensics Endpoint (required)
    Set-ItemProperty -Path $ExtensionPolicyPath -Name "forensics_endpoint" -Value $ForensicsEndpoint -Type String
    Write-Log "Set forensics_endpoint: $ForensicsEndpoint"

    # IOC Salt (required)
    Set-ItemProperty -Path $ExtensionPolicyPath -Name "ioc_salt" -Value $IocSalt -Type String
    Write-Log "Set ioc_salt: [configured]"

    # Update Interval
    Set-ItemProperty -Path $ExtensionPolicyPath -Name "update_interval_minutes" -Value $UpdateIntervalMinutes -Type DWord
    Write-Log "Set update_interval_minutes: $UpdateIntervalMinutes"

    # Signing Public Key (required)
    Set-ItemProperty -Path $ExtensionPolicyPath -Name "signing_public_key" -Value $SigningPublicKey -Type String
    Write-Log "Set signing_public_key: [configured]"

    # Encryption Public Key (required)
    Set-ItemProperty -Path $ExtensionPolicyPath -Name "encryption_public_key" -Value $EncryptionPublicKey -Type String
    Write-Log "Set encryption_public_key: [configured]"

    # Debug Logging
    $debugValue = if ($EnableDebugLogging) { 1 } else { 0 }
    Set-ItemProperty -Path $ExtensionPolicyPath -Name "enable_debug_logging" -Value $debugValue -Type DWord
    Write-Log "Set enable_debug_logging: $debugValue"

    Write-Log "BrowserDefense configuration completed successfully!"
    Write-Log ""
    Write-Log "Next steps:"
    Write-Log "1. Restart Chrome for policies to take effect"
    Write-Log "2. Navigate to chrome://policy to verify settings"
    Write-Log "3. Click the BrowserDefense extension icon to verify connection"

    exit 0
}
catch {
    Write-Log "ERROR: $($_.Exception.Message)"
    Write-Log "Stack trace: $($_.ScriptStackTrace)"
    exit 1
}
