# Get-SSOApps

A PowerShell 7 script that exports Microsoft Entra enterprise applications and provides a factual SSO determination based on Microsoft Graph configuration and optional observed sign-in activity.

Microsoft Entra does not expose one definitive **SSO enabled** property for every enterprise application. The report therefore returns `Yes`, `No`, or `Not verified` with the exact basis for the result instead of using a confidence score or treating a missing `preferredSingleSignOnMode` as disabled.

Created by Jose Guajardo.

## What it does

- Reads Microsoft Entra service principals of type `Application` and `Legacy` through Microsoft Graph.
- Identifies configured SSO modes such as SAML and OIDC.
- Optionally aggregates successful interactive SAML, OAuth/OIDC, and WS-Federation sign-ins from a Log Analytics `SigninLogs` table.
- Produces a semicolon-delimited CSV report with an SSO determination, the factual basis for that result, observed activity, and application metadata.

By default, the script exports every enabled `Application` and `Legacy` service principal. Use `-IncludeDisabled` to include disabled service principals.

## How the SSO determination works

| Result | Condition |
| --- | --- |
| `Yes` | Microsoft Graph records `SAML`, `OIDC`, or `Password` as the configured SSO mode, or a successful SSO sign-in was observed in Log Analytics. |
| `No` | The service principal is disabled, or Microsoft Graph explicitly records `notSupported`. |
| `Not verified` | Microsoft Graph has no SSO mode recorded and successful SSO activity did not establish a `Yes` answer. |

Tags are exported as inventory metadata but never determine the SSO result. The `SSO Determination Basis` column explains the specific fact used for every row.

## Requirements

- PowerShell 7.0 or later
- The `Microsoft.Graph.Authentication` PowerShell module
- Delegated Microsoft Graph permission: `Application.Read.All` (administrator consent required)

For optional sign-in activity enrichment:

- `Az.Accounts`
- `Az.OperationalInsights`
- Query access to a Log Analytics workspace that receives Microsoft Entra `SigninLogs`

Install the required modules for the current user:

```powershell
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
Install-Module Az.Accounts -Scope CurrentUser
Install-Module Az.OperationalInsights -Scope CurrentUser
```

> Only `Microsoft.Graph.Authentication` is required when running without `-WorkspaceId`.

## Usage

Run a configuration-only report:

```powershell
./get-ssoapps.ps1 -TenantId '00000000-0000-0000-0000-000000000000'
```

Include observed sign-in protocol activity from Log Analytics:

```powershell
./get-ssoapps.ps1 `
  -TenantId '00000000-0000-0000-0000-000000000000' `
  -WorkspaceId '11111111-1111-1111-1111-111111111111' `
  -LookbackDays 90
```

Test with a limited number of service principals:

```powershell
./get-ssoapps.ps1 -Top 25
```

Specify an output location:

```powershell
./get-ssoapps.ps1 -OutputPath './reports/custom-sso-applications.csv'
```

Without `-OutputPath`, the script creates the `reports` subfolder when needed and writes a timestamped CSV there.

## Parameters

| Parameter | Description |
| --- | --- |
| `TenantId` | Optional Microsoft Entra tenant ID. Use this to ensure authentication occurs in the expected tenant. |
| `WorkspaceId` | Optional Log Analytics workspace customer ID for observed sign-in activity. |
| `LookbackDays` | Sign-in activity window from 1 to 365 days. Default: `90`. |
| `Top` | Maximum number of service principals to retrieve. `0` retrieves all. Default: `0`. |
| `IncludeDisabled` | Includes disabled service principals. |
| `OutputPath` | CSV report path. Defaults to a timestamped CSV in the local `reports` subfolder. |

## Report fields

The CSV includes application and service-principal IDs, `SSO Determination`, `SSO Determination Basis`, the configured SSO mode, observed-activity status, protocols and sign-in counts when available, application status, URLs, tags, and the source of activity data.

`SSO Activity Observed` is `Not checked` unless a Log Analytics workspace is supplied and its query succeeds. `Observed Sign-In Count` and `Last Observed Sign-In (UTC)` describe only the selected lookback period.

## Security and privacy

- The script uses interactive Microsoft Graph and, optionally, Azure authentication. It does not contain client secrets, access tokens, passwords, tenant-specific values, or telemetry endpoints.
- Authentication uses process-scoped Graph context and disconnects that context when the script created it.
- The Log Analytics query aggregates successful interactive sign-ins by application and protocol; it does not request user identities or raw sign-in events.
- Generated reports can contain tenant-specific application names, IDs, URLs, tags, and sign-in aggregates. Treat CSV output as sensitive operational inventory and do **not** commit or publish it.
- The complete `reports` folder and legacy root-level report filenames are excluded by this repository's `.gitignore`.

Before publishing changes, review the Git diff and verify that no generated CSV reports or organization-specific examples have been added.

## Limitations

- Microsoft Graph documents that `preferredSingleSignOnMode` might be null for older SAML applications and OIDC applications where it wasn't set automatically. Those rows are reported as `Not verified` unless successful SSO activity is observed; they are never mislabeled as `No`.
- Observed activity depends on Log Analytics retention, diagnostic settings, and the caller's workspace permissions.
- The script reports service-principal evidence; it does not validate individual application configuration end-to-end.

## License

This project is licensed under the [MIT License](LICENSE).
