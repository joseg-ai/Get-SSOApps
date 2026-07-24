<#
.SYNOPSIS
    Exports enterprise applications with configured, observed, or candidate SSO evidence.

.DESCRIPTION
    Combines Microsoft Graph service-principal configuration with optional, aggregated
    Microsoft Entra sign-in activity from Log Analytics. Microsoft Entra has no single
    authoritative "SSO enabled" property. A null preferredSingleSignOnMode can still
    represent an older SAML application or an OIDC application, so this report records
    evidence and confidence rather than treating null as "disabled."

    By default, only enabled applications with configured, observed, or tag-inferred
    SSO evidence are exported. Tag inference is deliberately conservative: SAML-specific
    tags identify SAML candidates, while the generic Entra integrated-app tag identifies
    a candidate whose protocol still requires validation. Use -IncludeUnclassified or
    -IncludeDisabled to broaden the report.

.PARAMETER TenantId
    Optional Microsoft Entra tenant ID. Supplying it avoids signing into the wrong tenant.

.PARAMETER WorkspaceId
    Optional Log Analytics workspace customer ID. When supplied, successful interactive
    SAML, OAuth/OIDC, and WS-Federation sign-ins are aggregated by application.

.PARAMETER LookbackDays
    Sign-in activity window. The default is 90 days.

.PARAMETER Top
    Maximum number of service principals to retrieve for a test. Zero retrieves all.

.PARAMETER IncludeUnclassified
    Includes applications without configured, observed, or tag-inferred SSO evidence.

.PARAMETER IncludeDisabled
    Includes disabled service principals.

.PARAMETER OutputPath
    CSV output path. Defaults to a timestamped file beside this script.

.EXAMPLE
    .\get-ssoapps.ps1 -TenantId '00000000-0000-0000-0000-000000000000'

    Creates a configuration-only SSO report.

.EXAMPLE
    .\get-ssoapps.ps1 -TenantId '00000000-0000-0000-0000-000000000000' `
        -WorkspaceId '11111111-1111-1111-1111-111111111111' -LookbackDays 90

    Adds SSO protocols observed in the Log Analytics SigninLogs table.

.EXAMPLE
    .\get-ssoapps.ps1 -Top 25 -IncludeUnclassified

    Runs a 25-application test and includes applications with unknown SSO state.

.NOTES
    Required:
    - Microsoft.Graph.Authentication
    - Delegated Application.Read.All permission (admin consent required)

    Optional activity enrichment:
    - Az.Accounts and Az.OperationalInsights
    - Query access to a Log Analytics workspace receiving Entra SigninLogs

    Tag values are used only as inventory heuristics. They do not prove that SSO is
    active or identify the protocol for a generic Entra integrated application.

    Author: Jose Guajardo
    Revised: 2026-07-24
    Version: 8.1 - Configuration, tag inference, and observed SSO evidence
#>

#requires -Version 7.0

[CmdletBinding()]
param(
    [Parameter()]
    [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
    [string]$TenantId,

    [Parameter()]
    [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
    [string]$WorkspaceId,

    [Parameter()]
    [ValidateRange(1, 365)]
    [int]$LookbackDays = 90,

    [Parameter()]
    [ValidateRange(0, 1000000)]
    [int]$Top = 0,

    [Parameter()]
    [switch]$IncludeUnclassified,

    [Parameter()]
    [switch]$IncludeDisabled,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPath = (Join-Path $PSScriptRoot ("Report_SSO_Applications_{0}.csv" -f (Get-Date -Format 'yyyy-MM-dd-HHmm')))
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Invoke-GraphCollectionRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Uri,

        [Parameter()]
        [ValidateRange(0, 1000000)]
        [int]$MaximumItems = 0
    )

    $items = [System.Collections.Generic.List[object]]::new()
    $nextLink = $Uri

    while (-not [string]::IsNullOrWhiteSpace($nextLink)) {
        $response = Invoke-MgGraphRequest -Method GET -Uri $nextLink -OutputType PSObject -ErrorAction Stop
        $valueProperty = $response.PSObject.Properties['value']

        if ($null -eq $valueProperty) {
            throw "Microsoft Graph returned an unexpected response for '$nextLink'."
        }

        foreach ($item in @($valueProperty.Value)) {
            [void]$items.Add($item)
            if ($MaximumItems -gt 0 -and $items.Count -ge $MaximumItems) {
                return $items.ToArray()
            }
        }

        $nextLinkProperty = $response.PSObject.Properties['@odata.nextLink']
        $nextLink = if ($null -ne $nextLinkProperty) {
            [string]$nextLinkProperty.Value
        }
        else {
            $null
        }
    }

    return $items.ToArray()
}

function Get-ConfiguredSsoMode {
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Mode
    )

    if ([string]::IsNullOrWhiteSpace($Mode)) {
        return 'Unknown'
    }

    switch ($Mode.ToLowerInvariant()) {
        'saml' { return 'SAML' }
        'oidc' { return 'OIDC' }
        'password' { return 'Password' }
        'notsupported' { return 'Not supported' }
        default { return "Other ($Mode)" }
    }
}

function ConvertTo-ObservedProtocolLabel {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Protocol
    )

    switch ($Protocol.ToLowerInvariant()) {
        'saml20' { return 'SAML 2.0' }
        'oauth2' { return 'OAuth 2.0 / OIDC' }
        'wsfederation' { return 'WS-Federation' }
        default { return $Protocol }
    }
}

function Get-TagSsoEvidence {
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowNull()]
        [object[]]$Tags
    )

    $tagValues = @($Tags | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
    $gallerySamlTag = 'WindowsAzureActiveDirectoryGalleryApplicationPrimaryV1'
    $customSamlTag = 'WindowsAzureActiveDirectoryCustomSingleSignOnApplication'
    $integratedAppTag = 'WindowsAzureActiveDirectoryIntegratedApp'

    if ($tagValues -contains $gallerySamlTag) {
        return [PSCustomObject]@{
            Mode = 'SAML'
            Evidence = 'Gallery SAML tag'
            Confidence = 'Medium (tag inference)'
            IsCandidate = $true
        }
    }

    if ($tagValues -contains $customSamlTag) {
        return [PSCustomObject]@{
            Mode = 'SAML'
            Evidence = 'Non-gallery SAML tag'
            Confidence = 'Medium (tag inference)'
            IsCandidate = $true
        }
    }

    if ($tagValues -contains $integratedAppTag) {
        return [PSCustomObject]@{
            Mode = 'Entra integrated (protocol unknown)'
            Evidence = 'Integrated application tag'
            Confidence = 'Low (protocol requires validation)'
            IsCandidate = $true
        }
    }

    return [PSCustomObject]@{
        Mode = 'None'
        Evidence = 'None'
        Confidence = 'Unknown'
        IsCandidate = $false
    }
}

function Get-ObservedSsoActivity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$WorkspaceId,

        [Parameter(Mandatory)]
        [ValidateRange(1, 365)]
        [int]$LookbackDays,

        [Parameter(Mandatory)]
        [string]$TenantId
    )

    foreach ($moduleName in 'Az.Accounts', 'Az.OperationalInsights') {
        if (-not (Get-Module -ListAvailable -Name $moduleName)) {
            throw "Module '$moduleName' is required when -WorkspaceId is supplied."
        }
    }

    Import-Module Az.Accounts -ErrorAction Stop
    Import-Module Az.OperationalInsights -ErrorAction Stop

    $azContext = Get-AzContext -ErrorAction SilentlyContinue
    if ($null -eq $azContext -or $azContext.Tenant.Id -ne $TenantId) {
        Write-Host 'Connecting to Azure for Log Analytics access...' -ForegroundColor Cyan
        $null = Connect-AzAccount -Tenant $TenantId -ErrorAction Stop
    }

    $query = @"
SigninLogs
| where TimeGenerated >= ago(${LookbackDays}d)
| where IsInteractive == true
| where toint(ResultType) == 0
| where AuthenticationProtocol in~ ("saml20", "oAuth2", "wsFederation")
| summarize ObservedSignInCount = count(), LastObservedSignInUtc = max(TimeGenerated)
    by AppId, AppDisplayName, AuthenticationProtocol
"@

    $queryResult = Invoke-AzOperationalInsightsQuery `
        -WorkspaceId $WorkspaceId `
        -Query $query `
        -Timespan (New-TimeSpan -Days $LookbackDays) `
        -Wait 120 `
        -ErrorAction Stop

    $errorProperty = $queryResult.PSObject.Properties['Error']
    if ($null -ne $errorProperty -and $null -ne $errorProperty.Value) {
        throw "Log Analytics query failed: $($errorProperty.Value)"
    }

    return @($queryResult.Results)
}

$graphConnectionCreated = $false

try {
    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
        throw "Module 'Microsoft.Graph.Authentication' is required."
    }

    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop

    $graphContext = Get-MgContext -ErrorAction SilentlyContinue
    $hasRequiredScope = $null -ne $graphContext -and (
        $graphContext.Scopes -contains 'Application.Read.All' -or
        $graphContext.Scopes -contains 'Directory.Read.All'
    )
    $isRequestedTenant = [string]::IsNullOrWhiteSpace($TenantId) -or (
        $null -ne $graphContext -and $graphContext.TenantId -eq $TenantId
    )

    if ($null -eq $graphContext -or -not $hasRequiredScope -or -not $isRequestedTenant) {
        Write-Host 'Connecting to Microsoft Graph...' -ForegroundColor Cyan
        $connectParameters = @{
            Scopes       = 'Application.Read.All'
            ContextScope = 'Process'
            NoWelcome    = $true
            ErrorAction  = 'Stop'
        }

        if (-not [string]::IsNullOrWhiteSpace($TenantId)) {
            $connectParameters.TenantId = $TenantId
        }

        Connect-MgGraph @connectParameters
        $graphConnectionCreated = $true
        $graphContext = Get-MgContext -ErrorAction Stop
    }

    if ([string]::IsNullOrWhiteSpace($TenantId)) {
        $TenantId = $graphContext.TenantId
    }

    Write-Host "Connected to tenant $TenantId." -ForegroundColor Green
    Write-Host 'Retrieving Application and Legacy service principals...' -ForegroundColor Cyan

    $properties = @(
        'id'
        'displayName'
        'appId'
        'accountEnabled'
        'appRoleAssignmentRequired'
        'preferredSingleSignOnMode'
        'servicePrincipalType'
        'servicePrincipalNames'
        'replyUrls'
        'homepage'
        'loginUrl'
        'tags'
    ) -join ','
    $filter = "servicePrincipalType eq 'Application' or servicePrincipalType eq 'Legacy'"
    $pageSize = if ($Top -gt 0 -and $Top -lt 100) { $Top } else { 100 }
    $uri = 'https://graph.microsoft.com/v1.0/servicePrincipals?$select={0}&$filter={1}&$top={2}' -f `
        $properties, [System.Uri]::EscapeDataString($filter), $pageSize

    $enterpriseApps = @(Invoke-GraphCollectionRequest -Uri $uri -MaximumItems $Top)
    Write-Host "Retrieved $($enterpriseApps.Count) service principals." -ForegroundColor Green

    $observedByAppId = @{}
    $activitySource = 'Not queried'

    if (-not [string]::IsNullOrWhiteSpace($WorkspaceId)) {
        Write-Host "Querying $LookbackDays days of SSO activity from Log Analytics..." -ForegroundColor Cyan
        try {
            $activityRows = @(Get-ObservedSsoActivity `
                    -WorkspaceId $WorkspaceId `
                    -LookbackDays $LookbackDays `
                    -TenantId $TenantId)

            foreach ($row in $activityRows) {
                $appId = [string]$row.AppId
                if ([string]::IsNullOrWhiteSpace($appId)) {
                    continue
                }

                $key = $appId.ToLowerInvariant()
                if (-not $observedByAppId.ContainsKey($key)) {
                    $observedByAppId[$key] = @{
                        Protocols = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
                        Count = [long]0
                        LastSignInUtc = [datetimeoffset]::MinValue
                    }
                }

                $entry = $observedByAppId[$key]
                $protocol = ConvertTo-ObservedProtocolLabel -Protocol ([string]$row.AuthenticationProtocol)
                [void]$entry.Protocols.Add($protocol)
                $entry.Count += [long]$row.ObservedSignInCount

                $lastSignIn = [datetimeoffset]::Parse(
                    [string]$row.LastObservedSignInUtc,
                    [System.Globalization.CultureInfo]::InvariantCulture,
                    [System.Globalization.DateTimeStyles]::AssumeUniversal
                )
                if ($lastSignIn -gt $entry.LastSignInUtc) {
                    $entry.LastSignInUtc = $lastSignIn
                }
            }

            $activitySource = "Log Analytics ($LookbackDays days)"
            Write-Host "Observed SSO activity found for $($observedByAppId.Count) applications." -ForegroundColor Green
        }
        catch {
            $activitySource = 'Log Analytics unavailable'
            Write-Warning "Activity enrichment failed; continuing with configuration data. $($_.Exception.Message)"
        }
    }
    else {
        Write-Warning 'No WorkspaceId supplied. Tag inference will identify candidates, but observed protocol and usage cannot be confirmed.'
    }

    $reportData = foreach ($app in $enterpriseApps) {
        $isEnabled = $app.AccountEnabled -eq $true
        if (-not $IncludeDisabled -and -not $isEnabled) {
            continue
        }

        $configuredMode = Get-ConfiguredSsoMode -Mode ([string]$app.PreferredSingleSignOnMode)
        $hasConfiguredSso = $configuredMode -in 'SAML', 'OIDC', 'Password'
        $tagEvidence = Get-TagSsoEvidence -Tags @($app.Tags)
        $hasTagCandidate = $tagEvidence.IsCandidate

        $appId = [string]$app.AppId
        $observed = if (-not [string]::IsNullOrWhiteSpace($appId)) {
            $observedByAppId[$appId.ToLowerInvariant()]
        }
        else {
            $null
        }
        $hasObservedSso = $null -ne $observed -and $observed.Protocols.Count -gt 0

        if (-not $IncludeUnclassified -and -not $hasConfiguredSso -and -not $hasObservedSso -and -not $hasTagCandidate) {
            continue
        }

        $evidence = if ($hasConfiguredSso -and $hasObservedSso) {
            'Configured and observed'
        }
        elseif ($hasConfiguredSso) {
            'Configured'
        }
        elseif ($hasObservedSso) {
            'Observed only'
        }
        elseif ($hasTagCandidate) {
            $tagEvidence.Evidence
        }
        else {
            'Unclassified'
        }

        $confidence = if ($hasConfiguredSso -and $hasObservedSso) {
            'High'
        }
        elseif ($hasConfiguredSso) {
            'High (configuration)'
        }
        elseif ($hasObservedSso) {
            'Medium (activity)'
        }
        elseif ($hasTagCandidate) {
            $tagEvidence.Confidence
        }
        else {
            'Unknown'
        }

        $configurationConflict = $configuredMode -eq 'Not supported' -and $hasObservedSso
        $lastObservedSignIn = if ($hasObservedSso) {
            $observed.LastSignInUtc.UtcDateTime.ToString('o')
        }
        else {
            $null
        }

        [PSCustomObject][ordered]@{
            'Application Name' = $app.DisplayName
            'Application (Client) ID' = $app.AppId
            'Service Principal Object ID' = $app.Id
            'Service Principal Type' = $app.ServicePrincipalType
            'Status' = if ($isEnabled) { 'Enabled' } else { 'Disabled' }
            'Configured SSO Mode' = $configuredMode
            'Tag-Inferred SSO Mode' = $tagEvidence.Mode
            'Observed Protocols' = if ($hasObservedSso) { (@($observed.Protocols) | Sort-Object) -join ', ' } else { $null }
            'SSO Evidence' = $evidence
            'Confidence' = $confidence
            'Protocol Validation Required' = if (-not $hasConfiguredSso -and -not $hasObservedSso -and $hasTagCandidate) { 'Yes' } else { 'No' }
            'Configuration Conflict' = if ($configurationConflict) { 'Yes' } else { 'No' }
            'Last Observed Sign-In (UTC)' = $lastObservedSignIn
            'Observed Sign-In Count' = if ($hasObservedSso) { $observed.Count } else { 0 }
            'Activity Source' = $activitySource
            'Assignment Required' = if ($app.AppRoleAssignmentRequired) { 'Yes' } else { 'No' }
            'Service Principal Names' = @($app.ServicePrincipalNames) -join ', '
            'Reply URLs' = @($app.ReplyUrls) -join ', '
            'Home Page' = $app.Homepage
            'Login URL' = $app.LoginUrl
            'Tags' = @($app.Tags) -join ', '
        }
    }

    $reportData = @($reportData | Sort-Object 'Application Name', 'Application (Client) ID')
    if ($reportData.Count -eq 0) {
        Write-Warning 'No configured, observed, or tag-inferred SSO candidates matched. Use -IncludeUnclassified to export the full enabled-app inventory.'
        return
    }

    $resolvedOutputPath = [System.IO.Path]::GetFullPath($OutputPath)
    $outputDirectory = Split-Path -Path $resolvedOutputPath -Parent
    if (-not (Test-Path -LiteralPath $outputDirectory)) {
        $null = New-Item -ItemType Directory -Path $outputDirectory -Force
    }

    $reportData | Export-Csv -LiteralPath $resolvedOutputPath -NoTypeInformation -Encoding UTF8 -Delimiter ';'

    Write-Host '--------------------------------------------------------' -ForegroundColor Cyan
    Write-Host "Report complete: $($reportData.Count) applications" -ForegroundColor Green
    Write-Host "Activity source: $activitySource" -ForegroundColor White
    Write-Host $resolvedOutputPath -ForegroundColor White
    Write-Host '--------------------------------------------------------' -ForegroundColor Cyan

    $resolvedOutputPath
}
catch {
    if ($_.Exception.Message -match 'consent|approval|AADSTS65001') {
        Write-Error 'Admin consent is required for Application.Read.All. Ask a tenant administrator to approve Microsoft Graph Command Line Tools, then retry.'
    }
    throw
}
finally {
    if ($graphConnectionCreated -and $null -ne (Get-MgContext -ErrorAction SilentlyContinue)) {
        Write-Host 'Disconnecting the process-scoped Microsoft Graph session.' -ForegroundColor DarkGray
        Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
    }
}