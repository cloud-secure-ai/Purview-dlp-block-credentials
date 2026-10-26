#Requires -Version 5.1
<#
.SYNOPSIS
    Creates a Microsoft Purview DLP policy and rule that blocks content containing
    credentials and secrets (the built-in "All Credential Types" sensitive information type).

.DESCRIPTION
    Connects to Security & Compliance PowerShell, confirms you are signed in to the
    tenant you specified, checks that your account holds the DLP management permissions,
    then creates:

      Policy : scoped to Exchange email, SharePoint sites, OneDrive accounts and
               Teams chat and channel messages (all users, full directory)
      Rule   : condition - All Credential Types, configurable confidence, 1+ instances
               action    - block access for everyone
               alerting  - admin alert + incident report to the recipients you supply,
                           at High severity

    Incident reports deliberately EXCLUDE OriginalContent, MatchedItem and
    DetectionDetails, so the credential that triggered the rule is never emailed out.

    The script is idempotent: an existing policy or rule with the same name is reported
    and skipped rather than overwritten. Supports -WhatIf.

.PARAMETER TenantId
    Microsoft Entra tenant ID (GUID). Prompted for if not supplied.

.PARAMETER UserPrincipalName
    Admin account used to sign in. Prompted for if not supplied.

.PARAMETER AlertRecipients
    One or more email addresses for alerts and incident reports. Must be recipients
    that exist in the tenant (users, groups or mail contacts). Prompted for if not supplied.

.PARAMETER PolicyName
    DLP policy name. Default: "Block Credentials and Secrets".

.PARAMETER RuleName
    DLP rule name. Default: "Block credentials and secrets".

.PARAMETER Mode
    Policy mode. Enable (enforce immediately - default), TestWithNotifications,
    TestWithoutNotifications (simulation) or Disable.

.PARAMETER ConfidenceLevel
    Minimum SIT confidence: Low, Medium (default) or High.

.PARAMETER Force
    Skip the final "type YES to continue" confirmation before an enforced policy is created.

.PARAMETER KeepConnected
    Leave the Security & Compliance session open when the script finishes.

.EXAMPLE
    .\New-CredentialDlpPolicy.ps1
    Prompts for tenant ID, admin UPN and alert recipients, then creates an enforced policy.

.EXAMPLE
    .\New-CredentialDlpPolicy.ps1 -TenantId 00000000-0000-0000-0000-000000000000 `
        -UserPrincipalName admin@contoso.onmicrosoft.com `
        -AlertRecipients secops@contoso.com -Mode TestWithoutNotifications
    Creates the policy in simulation mode.

.EXAMPLE
    .\New-CredentialDlpPolicy.ps1 -WhatIf
    Shows what would be created without making any changes.

.NOTES
    Author  : Seán O'Farrell
    Website : https://cloud-secure.ai/
    Version : 1.0

    Requires the ExchangeOnlineManagement module (3.2.0 or later) and a Microsoft 365 E5,
    E5 Compliance or E5 Information Protection & Governance licence for credential
    scanning SITs. Allow up to an hour for a new policy to sync to all locations.
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [ValidatePattern('^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')]
    [string]$TenantId,

    [string]$UserPrincipalName,

    [string[]]$AlertRecipients,

    [string]$PolicyName = 'Block Credentials and Secrets',

    [string]$RuleName = 'Block credentials and secrets',

    [ValidateSet('Enable', 'TestWithNotifications', 'TestWithoutNotifications', 'Disable')]
    [string]$Mode = 'Enable',

    [ValidateSet('Low', 'Medium', 'High')]
    [string]$ConfidenceLevel = 'Medium',

    [switch]$Force,

    [switch]$KeepConnected
)

$ErrorActionPreference = 'Stop'
$guidPattern  = '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$'
$emailPattern = '^[^@\s]+@[^@\s]+\.[^@\s]+$'
$summary = [ordered]@{ Created = 0; Skipped = 0; Failed = 0 }

#region Required privileges
Write-Host ''
Write-Host '🔐 Required privileges' -ForegroundColor Cyan
Write-Host '   The account you sign in with must be a member of ONE of these Purview role groups:'
Write-Host '     - Compliance Administrator'
Write-Host '     - Compliance Data Administrator'
Write-Host '     - Information Protection Admin'
Write-Host '     - Security Administrator'
Write-Host '   or a custom role group that includes the "DLP Compliance Management" role.'
Write-Host '   The Entra ID roles Compliance Administrator or Global Administrator also work.'
Write-Host '   Licensing: Microsoft 365 E5 / E5 Compliance / E5 Information Protection & Governance'
Write-Host '   is required to use credential scanning sensitive information types.'
Write-Host ''
#endregion

#region Prompts and input validation
while (-not $TenantId -or $TenantId -notmatch $guidPattern) {
    if ($TenantId) { Write-Host '⚠️  That is not a valid tenant ID (GUID).' -ForegroundColor Yellow }
    $TenantId = (Read-Host '🏢 Enter the tenant ID (GUID)').Trim()
}

while (-not $UserPrincipalName -or $UserPrincipalName -notmatch $emailPattern) {
    $UserPrincipalName = (Read-Host '👤 Enter the admin user principal name').Trim()
}

if (-not $AlertRecipients) {
    $raw = Read-Host '📧 Enter alert recipient email address(es), comma-separated'
    $AlertRecipients = $raw -split '[,;]' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
}
$invalid = $AlertRecipients | Where-Object { $_ -notmatch $emailPattern }
if (-not $AlertRecipients -or $invalid) {
    throw "Invalid or missing alert recipient(s): $($invalid -join ', ')"
}
#endregion

#region Validate the tenant ID exists
Write-Host "🔎 Checking tenant $TenantId exists..." -ForegroundColor Cyan
try {
    $oidc = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$TenantId/v2.0/.well-known/openid-configuration" -ErrorAction Stop
    if ($oidc.issuer -notlike "*$TenantId*") { throw 'Issuer does not match the tenant ID.' }
    Write-Host '✅ Tenant found.' -ForegroundColor Green
}
catch {
    throw "❌ Could not resolve tenant ID $TenantId. Check the GUID and try again. ($($_.Exception.Message))"
}
#endregion

#region Module check
$module = Get-Module -ListAvailable -Name ExchangeOnlineManagement |
    Sort-Object Version -Descending | Select-Object -First 1
if (-not $module -or $module.Version -lt [version]'3.2.0') {
    Write-Host '❌ ExchangeOnlineManagement 3.2.0 or later is required.' -ForegroundColor Red
    Write-Host '   Install it with:  Install-Module ExchangeOnlineManagement -Scope CurrentUser' -ForegroundColor Yellow
    return
}
Import-Module ExchangeOnlineManagement -MinimumVersion 3.2.0 -ErrorAction Stop
Write-Host "✅ ExchangeOnlineManagement $($module.Version) loaded." -ForegroundColor Green
#endregion

#region Connect and confirm the tenant
Write-Host "🔌 Connecting to Security & Compliance PowerShell as $UserPrincipalName..." -ForegroundColor Cyan
try {
    Connect-IPPSSession -UserPrincipalName $UserPrincipalName -ShowBanner:$false -ErrorAction Stop
}
catch {
    throw "❌ Sign-in failed: $($_.Exception.Message)"
}

$conn = Get-ConnectionInformation -ErrorAction SilentlyContinue |
    Where-Object { $_.State -eq 'Connected' -and $_.ConnectionUri -like '*compliance*' } |
    Select-Object -Last 1
if ($conn -and $conn.TenantID) {
    if ($conn.TenantID.ToString() -ne $TenantId) {
        Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
        throw "❌ Signed in to tenant $($conn.TenantID), not $TenantId. Disconnected - nothing was changed."
    }
    Write-Host "✅ Connected to tenant $TenantId." -ForegroundColor Green
}
else {
    Write-Host '⚠️  Could not read the connected tenant ID - confirm you signed in to the right tenant.' -ForegroundColor Yellow
}
#endregion

try {
    #region Permission check
    # Security & Compliance PowerShell only exposes the cmdlets your roles allow.
    $needed  = 'Get-DlpSensitiveInformationType', 'New-DlpCompliancePolicy', 'New-DlpComplianceRule'
    $missing = $needed | Where-Object { -not (Get-Command $_ -ErrorAction SilentlyContinue) }
    if ($missing) {
        throw "❌ Your account lacks DLP management permissions (missing: $($missing -join ', ')). See the required privileges above."
    }
    Write-Host '✅ DLP management permissions confirmed.' -ForegroundColor Green
    #endregion

    #region Resolve the sensitive information type
    $sit = Get-DlpSensitiveInformationType -ErrorAction Stop |
        Where-Object { $_.Name -in @('All Credential Types', 'All credentials') } |
        Select-Object -First 1
    if (-not $sit) {
        throw '❌ The "All Credential Types" SIT was not found in this tenant. Check licensing (E5 or equivalent).'
    }
    Write-Host "✅ Found sensitive information type: $($sit.Name)" -ForegroundColor Green
    #endregion

    #region Final confirmation for enforced policies
    Write-Host ''
    Write-Host '📋 About to create:' -ForegroundColor Cyan
    Write-Host "   Policy     : $PolicyName"
    Write-Host "   Rule       : $RuleName"
    Write-Host '   Locations  : Exchange, SharePoint, OneDrive, Teams (all users)'
    Write-Host "   Condition  : $($sit.Name), $ConfidenceLevel confidence, 1+ instances"
    Write-Host '   Action     : Block access for everyone'
    Write-Host "   Alerts to  : $($AlertRecipients -join ', ') (High severity)"
    Write-Host "   Mode       : $Mode"
    Write-Host ''

    if ($Mode -eq 'Enable' -and -not $Force -and -not $WhatIfPreference) {
        Write-Host '⚠️  Enable mode blocks matching content as soon as the policy syncs.' -ForegroundColor Yellow
        $answer = Read-Host 'Type YES to continue'
        if ($answer -cne 'YES') {
            Write-Host '🛑 Cancelled - nothing was changed.' -ForegroundColor Yellow
            return
        }
    }
    #endregion

    #region Create the policy
    $existingPolicy = Get-DlpCompliancePolicy -Identity $PolicyName -ErrorAction SilentlyContinue
    if ($existingPolicy) {
        Write-Host "⏭️  Policy '$PolicyName' already exists - skipping." -ForegroundColor Yellow
        $summary.Skipped++
    }
    elseif ($PSCmdlet.ShouldProcess($PolicyName, 'Create DLP policy')) {
        try {
            $policyParams = @{
                Name               = $PolicyName
                Comment            = 'Blocks content containing credentials and secrets. Created by New-CredentialDlpPolicy.ps1 (cloud-secure.ai).'
                ExchangeLocation   = 'All'
                SharePointLocation = 'All'
                OneDriveLocation   = 'All'
                TeamsLocation      = 'All'
                Mode               = $Mode
                ErrorAction        = 'Stop'
            }
            New-DlpCompliancePolicy @policyParams | Out-Null
            Write-Host "✅ Created policy '$PolicyName'." -ForegroundColor Green
            $summary.Created++
        }
        catch {
            Write-Host "❌ Failed to create policy: $($_.Exception.Message)" -ForegroundColor Red
            $summary.Failed++
            throw
        }
    }
    #endregion

    #region Create the rule
    $existingRule = Get-DlpComplianceRule -Identity $RuleName -ErrorAction SilentlyContinue
    if ($existingRule) {
        Write-Host "⏭️  Rule '$RuleName' already exists - skipping." -ForegroundColor Yellow
        $summary.Skipped++
    }
    elseif ($PSCmdlet.ShouldProcess($RuleName, "Create DLP rule in policy '$PolicyName'")) {
        try {
            $ruleParams = @{
                Name                                = $RuleName
                Policy                              = $PolicyName
                Comment                             = 'Blocks content matching All Credential Types and alerts the security team.'
                ContentContainsSensitiveInformation = @(@{
                    Name            = $sit.Name
                    minCount        = '1'
                    confidencelevel = $ConfidenceLevel
                })
                BlockAccess                         = $true
                BlockAccessScope                    = 'All'
                GenerateAlert                       = $AlertRecipients
                GenerateIncidentReport              = $AlertRecipients
                # Excludes OriginalContent, MatchedItem and DetectionDetails so the secret itself is never emailed.
                IncidentReportContent               = 'Title', 'DocumentAuthor', 'DocumentLastModifier', 'Service', 'Severity', 'RulesMatched', 'Detections'
                ReportSeverityLevel                 = 'High'
                ErrorAction                         = 'Stop'
            }
            New-DlpComplianceRule @ruleParams | Out-Null
            Write-Host "✅ Created rule '$RuleName'." -ForegroundColor Green
            $summary.Created++
        }
        catch {
            Write-Host "❌ Failed to create rule: $($_.Exception.Message)" -ForegroundColor Red
            $summary.Failed++
            throw
        }
    }
    #endregion
}
finally {
    Write-Host ''
    Write-Host '📊 Summary' -ForegroundColor Cyan
    Write-Host "   Created : $($summary.Created)"
    Write-Host "   Skipped : $($summary.Skipped)"
    Write-Host "   Failed  : $($summary.Failed)"
    if ($summary.Created -gt 0) {
        Write-Host '⏳ Allow up to an hour for the policy to sync. Check status with:' -ForegroundColor Cyan
        Write-Host "   Get-DlpCompliancePolicy -Identity '$PolicyName' | Select-Object Name, Mode, DistributionStatus"
    }
    if (-not $KeepConnected) {
        Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
        Write-Host '🔌 Disconnected.' -ForegroundColor Cyan
    }
}
