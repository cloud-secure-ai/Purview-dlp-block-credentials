# New-CredentialDlpPolicy.ps1

Creates a Microsoft Purview Data Loss Prevention (DLP) policy that **blocks content containing credentials and secrets** across Exchange email, SharePoint, OneDrive and Teams, and alerts your security team when it fires.

The script builds the same policy as the portal walkthrough in the accompanying blog post on [cloud-secure.ai](https://cloud-secure.ai/), in a single repeatable run.

## What it creates

| Setting | Value |
|---|---|
| Policy name | Block Credentials and Secrets |
| Locations | Exchange email, SharePoint sites, OneDrive accounts, Teams chat and channel messages |
| Scope | All users (full directory) |
| Condition | Content contains **All Credential Types**, Medium confidence, 1 or more instances |
| Action | Block access for everyone |
| Alerts | Admin alert and incident report to the recipients you supply, High severity |
| Mode | Enable (enforced immediately) - configurable |

**All Credential Types** is a bundled sensitive information type (SIT). It detects the individual credential SITs Microsoft publishes, including Azure storage keys and SAS tokens, Azure SQL connection strings, client secrets and API keys, GitHub personal access tokens, Google API keys, Slack tokens, HTTP authorisation headers, X.509 private keys, user login credentials and general passwords.

### Incident reports do not contain the secret

Incident reports are limited to the title, author, last modifier, service, severity, rules matched and detection summary. `OriginalContent`, `MatchedItem` and `DetectionDetails` are deliberately excluded, so the credential that triggered the rule is **not** emailed to the alert recipients.

## Prerequisites

### Permissions

The account you sign in with must be a member of **one** of these Microsoft Purview role groups:

- Compliance Administrator
- Compliance Data Administrator
- Information Protection Admin
- Security Administrator

Alternatively, use a custom role group that includes the **DLP Compliance Management** role. This is the least-privileged option. The Entra ID roles Compliance Administrator or Global Administrator also work.

The script checks this after sign-in. Security & Compliance PowerShell only exposes the cmdlets your roles allow, so if `New-DlpCompliancePolicy` or `New-DlpComplianceRule` is missing, the script stops before making any change.

### Licensing

Credential scanning SITs require Microsoft 365 E5, E5 Compliance, or E5 Information Protection & Governance.

### Software

- Windows PowerShell 5.1 or PowerShell 7+
- ExchangeOnlineManagement module 3.2.0 or later:

```powershell
Install-Module ExchangeOnlineManagement -Scope CurrentUser
```

### What you need to hand

- **Tenant ID** (GUID). Find it in the Entra admin centre under **Overview**, or run `(Get-MgOrganization).Id`.
- **Admin UPN** for an account with the permissions above.
- **Alert recipient(s)**. These must exist in the tenant as users, groups or mail contacts. External addresses need a mail contact created first in Exchange admin centre > **Recipients** > **Contacts**.

## How to run

1. Download `New-CredentialDlpPolicy.ps1` and unblock it:

   ```powershell
   Unblock-File .\New-CredentialDlpPolicy.ps1
   ```

2. Preview the changes without making them:

   ```powershell
   .\New-CredentialDlpPolicy.ps1 -WhatIf
   ```

3. Run it interactively. You'll be prompted for the tenant ID, admin UPN and alert recipients:

   ```powershell
   .\New-CredentialDlpPolicy.ps1
   ```

4. Sign in when the browser prompt appears.

5. Review the summary and type `YES` to create an enforced policy.

### What the script does, in order

1. Lists the required privileges and licensing.
2. Prompts for and validates the tenant ID, UPN and alert recipients.
3. Confirms the tenant ID exists by querying the Microsoft Entra OpenID endpoint.
4. Checks the ExchangeOnlineManagement module version.
5. Connects with `Connect-IPPSSession`. It then **confirms the signed-in tenant matches the tenant ID you entered**, and disconnects without changes if it doesn't.
6. Confirms your account has DLP management permissions.
7. Confirms the **All Credential Types** SIT is available.
8. Shows a summary and asks for confirmation (Enable mode only).
9. Creates the policy and rule, skipping either if one with the same name already exists.
10. Prints a summary and disconnects.

## Parameters

| Parameter | Required | Default | Description |
|---|---|---|---|
| `-TenantId` | Prompted | - | Microsoft Entra tenant ID (GUID) |
| `-UserPrincipalName` | Prompted | - | Admin account used to sign in |
| `-AlertRecipients` | Prompted | - | One or more email addresses for alerts and incident reports |
| `-PolicyName` | No | `Block Credentials and Secrets` | DLP policy name |
| `-RuleName` | No | `Block credentials and secrets` | DLP rule name |
| `-Mode` | No | `Enable` | `Enable`, `TestWithNotifications`, `TestWithoutNotifications` (simulation) or `Disable` |
| `-ConfidenceLevel` | No | `Medium` | `Low`, `Medium` or `High` |
| `-Force` | No | - | Skips the `YES` confirmation for Enable mode |
| `-KeepConnected` | No | - | Leaves the session open afterwards |
| `-WhatIf` | No | - | Shows what would be created without making changes |

### Examples

Fully non-interactive, enforced:

```powershell
.\New-CredentialDlpPolicy.ps1 -TenantId 00000000-0000-0000-0000-000000000000 `
    -UserPrincipalName admin@contoso.onmicrosoft.com `
    -AlertRecipients secops@contoso.com, it@contoso.com -Force
```

Simulation mode first, to measure impact before enforcing:

```powershell
.\New-CredentialDlpPolicy.ps1 -Mode TestWithoutNotifications
```

Switch an existing policy from simulation to enforced:

```powershell
Set-DlpCompliancePolicy -Identity 'Block Credentials and Secrets' -Mode Enable
```

## After running

Allow up to an hour for the policy to sync to all locations. Check its status:

```powershell
Connect-IPPSSession -UserPrincipalName admin@contoso.onmicrosoft.com
Get-DlpCompliancePolicy -Identity 'Block Credentials and Secrets' |
    Select-Object Name, Mode, DistributionStatus
```

`DistributionStatus` should show `Success`.

To test it, use **synthetic** credentials only: a fake GitHub token format, or an Azure storage connection string with a made-up key. Send one by email or Teams, or upload one to SharePoint. Then check **Purview > Data loss prevention > Alerts** and **Activity explorer**.

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `Could not resolve tenant ID` | The GUID is wrong, or the machine can't reach `login.microsoftonline.com`. |
| `Signed in to tenant X, not Y` | You chose the wrong account at sign-in. Re-run and choose an account in the right tenant. |
| `lacks DLP management permissions` | Add the account to a role group listed above. Role changes can take up to an hour to apply. |
| `All Credential Types SIT was not found` | The tenant isn't licensed for credential scanning SITs. |
| Rule creation fails on `GenerateAlert` | A recipient doesn't exist in the tenant. Create a mail contact or use an internal address. |
| Policy `DistributionStatus` is `Pending` | Normal for up to an hour after creation. |

## Removing the policy

```powershell
Remove-DlpComplianceRule -Identity 'Block credentials and secrets'
Remove-DlpCompliancePolicy -Identity 'Block Credentials and Secrets'
```

## Credit

Written by **Seán O'Farrell** - [cloud-secure.ai](https://cloud-secure.ai/)
