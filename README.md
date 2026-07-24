# Get-SSOApps

A PowerShell 7 script that exports Microsoft Entra enterprise applications with evidence indicating that single sign-on (SSO) is configured, observed, or inferred from application tags.

Microsoft Entra does not expose one definitive **SSO enabled** property for every enterprise application. This report therefore records the evidence and confidence level rather than assuming that a missing `preferredSingleSignOnMode` means SSO is disabled.

Created by Jose Guajardo.

## What it does

- Reads Microsoft Entra service principals of type `Application` and `Legacy` through Microsoft Graph.
- Identifies configured SSO modes such as SAML and OIDC.
- Uses conservative tag-based heuristics to flag possible SAML or Entra-integrated applications.
- Optionally aggregates successful interactive SAML, OAuth/OIDC, and WS-Federation sign-ins from a Log Analytics `SigninLogs` table.
- Produces a semicolon-delimited CSV report with evidence, confidence, activity, and application metadata.

By default, the script exports only enabled applications with configured, observed, or tag-inferred SSO evidence.

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

Test with a limited number of service principals and include applications without SSO evidence:

```powershell
./get-ssoapps.ps1 -Top 25 -IncludeUnclassified
```

Specify an output location:

```powershell
./get-ssoapps.ps1 -OutputPath './exports/sso-applications.csv'
```

## Parameters

| Parameter | Description |
| --- | --- |
| `TenantId` | Optional Microsoft Entra tenant ID. Use this to ensure authentication occurs in the expected tenant. |
| `WorkspaceId` | Optional Log Analytics workspace customer ID for observed sign-in activity. |
| `LookbackDays` | Sign-in activity window from 1 to 365 days. Default: `90`. |
| `Top` | Maximum number of service principals to retrieve. `0` retrieves all. Default: `0`. |
| `IncludeUnclassified` | Includes applications without configured, observed, or tag-inferred SSO evidence. |
| `IncludeDisabled` | Includes disabled service principals. |
| `OutputPath` | CSV report path. Defaults to a timestamped CSV beside the script. |

## Report fields

The CSV includes application and service-principal IDs, SSO configuration and tag evidence, observed protocols and sign-in counts when available, confidence, status, URLs, tags, and the source of activity data.

`Observed Sign-In Count` and `Last Observed Sign-In (UTC)` are populated only when a Log Analytics workspace is supplied and its query succeeds.

## Security and privacy

- The script uses interactive Microsoft Graph and, optionally, Azure authentication. It does not contain client secrets, access tokens, passwords, tenant-specific values, or telemetry endpoints.
- Authentication uses process-scoped Graph context and disconnects that context when the script created it.
- The Log Analytics query aggregates successful interactive sign-ins by application and protocol; it does not request user identities or raw sign-in events.
- Generated reports can contain tenant-specific application names, IDs, URLs, tags, and sign-in aggregates. Treat CSV output as sensitive operational inventory and do **not** commit or publish it.
- Generated report filenames are excluded by this repository's `.gitignore`.

Before publishing changes, review the Git diff and verify that no generated CSV reports or organization-specific examples have been added.

## Limitations

- Tag inference is an inventory heuristic, not proof that SSO is active or that a particular protocol is configured.
- A missing `preferredSingleSignOnMode` can still correspond to older SAML or OIDC applications.
- Observed activity depends on Log Analytics retention, diagnostic settings, and the caller's workspace permissions.
- The script reports service-principal evidence; it does not validate individual application configuration end-to-end.

## License

This project is licensed under the [MIT License](LICENSE).
