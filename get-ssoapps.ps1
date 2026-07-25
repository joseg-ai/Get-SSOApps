<#
.SYNOPSIS
    Exports enterprise applications with a factual SSO determination.

.DESCRIPTION
    Combines Microsoft Graph service-principal configuration with optional, aggregated
    Microsoft Entra sign-in activity from Log Analytics. Every enabled Application and
    Legacy service principal is exported by default. Use -IncludeDisabled to include
    disabled service principals too.

    The SSO Determination column contains Yes, No, or Not verified. Yes requires an
    explicit SAML, OIDC, or password SSO mode in Microsoft Graph, or a successful SSO
    sign-in observed in Log Analytics. No is used only when the service principal is
    disabled or Microsoft Graph explicitly reports that SSO isn't supported. Not verified
    means Microsoft Graph has no mode recorded and no successful SSO activity established
    the answer. Tags never determine the result.

.PARAMETER TenantId
    Optional Microsoft Entra tenant ID. Supplying it avoids signing into the wrong tenant.

.PARAMETER WorkspaceId
    Optional Log Analytics workspace customer ID. When supplied, successful interactive
    SAML, OAuth/OIDC, and WS-Federation sign-ins are aggregated by application.

.PARAMETER LookbackDays
    Sign-in activity window. The default is 90 days.

.PARAMETER Top
    Maximum number of service principals to retrieve for a test. Zero retrieves all.

.PARAMETER IncludeDisabled
    Includes disabled service principals.

.PARAMETER OutputPath
    CSV output path. Defaults to a timestamped file in the reports subfolder.

.EXAMPLE
    .\get-ssoapps.ps1 -TenantId '00000000-0000-0000-0000-000000000000'

    Creates a configuration-only SSO report.

.EXAMPLE
    .\get-ssoapps.ps1 -TenantId '00000000-0000-0000-0000-000000000000' `
        -WorkspaceId '11111111-1111-1111-1111-111111111111' -LookbackDays 90

    Adds SSO protocols observed in the Log Analytics SigninLogs table.

.EXAMPLE
    .\get-ssoapps.ps1 -Top 25

    Runs a 25-application test.

.NOTES
    Required:
    - Microsoft.Graph.Authentication
    - Delegated Application.Read.All permission (admin consent required)

    Optional activity enrichment:
    - Az.Accounts and Az.OperationalInsights
    - Query access to a Log Analytics workspace receiving Entra SigninLogs

    Microsoft Graph documents that preferredSingleSignOnMode can be null for older SAML
    applications and OIDC applications. The script reports that case as Not verified
    rather than inventing a Yes or No answer.

    Author: Jose Guajardo
    Revised: 2026-07-24
    Version: 9.1.0 - Module compatibility checks and actionable diagnostics
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
    [switch]$IncludeDisabled,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPath = (Join-Path (Join-Path $PSScriptRoot 'reports') ("Report_SSO_Applications_{0}.csv" -f (Get-Date -Format 'yyyy-MM-dd-HHmm')))
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$scriptVersion = '9.1.0'
$minimumGraphAuthenticationVersion = [version]'2.0.0'
$processingStage = 'initialization'

function Test-CommandParameterSet {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [System.Management.Automation.CommandInfo]$Command,

        [Parameter(Mandatory)]
        [string[]]$ParameterNames
    )

    foreach ($parameterSet in $Command.ParameterSets) {
        $availableNames = @($parameterSet.Parameters | ForEach-Object { $_.Name })
        $missingNames = @($ParameterNames | Where-Object { $_ -notin $availableNames })
        if ($missingNames.Count -eq 0) {
            return $true
        }
    }

    return $false
}

function Import-CompatibleGraphAuthenticationModule {
    [CmdletBinding()]
    [OutputType([System.Management.Automation.CommandInfo])]
    param(
        [Parameter(Mandatory)]
        [version]$MinimumVersion
    )

    $compatibleModules = @(Get-Module -ListAvailable -Name Microsoft.Graph.Authentication |
            Where-Object { $_.Version -ge $MinimumVersion } |
            Sort-Object Version -Descending)

    if ($compatibleModules.Count -eq 0) {
        throw "Microsoft.Graph.Authentication $MinimumVersion or later is required. Install the latest version for the current user, restart PowerShell, and retry."
    }

    $selectedModule = $compatibleModules[0]
    $null = Import-Module -Name $selectedModule.Path -ErrorAction Stop

    $connectCommand = Get-Command Connect-MgGraph -ErrorAction Stop
    if ($connectCommand.Module.Version -lt $MinimumVersion) {
        throw "PowerShell loaded Microsoft.Graph.Authentication $($connectCommand.Module.Version) from '$($connectCommand.Module.Path)', but version $MinimumVersion or later is required. Start a new PowerShell 7 session and retry."
    }

    foreach ($commandName in 'Get-MgContext', 'Invoke-MgGraphRequest', 'Disconnect-MgGraph') {
        $command = Get-Command $commandName -ErrorAction Stop
        if ($command.Module.Version -ne $connectCommand.Module.Version) {
            throw "Mixed Microsoft.Graph.Authentication command versions were loaded: Connect-MgGraph is $($connectCommand.Module.Version), while $commandName is $($command.Module.Version). Start a new PowerShell 7 session and retry."
        }
    }

    return $connectCommand
}

function Connect-GraphForReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Management.Automation.CommandInfo]$ConnectCommand,

        [Parameter()]
        [AllowEmptyString()]
        [string]$TenantId
    )

    $connectParameters = @{
        Scopes = [string[]]@('Application.Read.All')
        ErrorAction = 'Stop'
    }
    $parameterNames = [System.Collections.Generic.List[string]]::new()
    $parameterNames.AddRange([string[]]@('Scopes', 'ErrorAction'))

    if (-not [string]::IsNullOrWhiteSpace($TenantId)) {
        $connectParameters.TenantId = $TenantId
        $parameterNames.Add('TenantId')
    }

    foreach ($optionalParameter in @(
            @{ Name = 'ContextScope'; Value = 'Process' }
            @{ Name = 'NoWelcome'; Value = $true }
        )) {
        $candidateNames = @($parameterNames) + $optionalParameter.Name
        if ($ConnectCommand.Parameters.ContainsKey($optionalParameter.Name) -and
            (Test-CommandParameterSet -Command $ConnectCommand -ParameterNames $candidateNames)) {
            $connectParameters[$optionalParameter.Name] = $optionalParameter.Value
            $parameterNames.Add($optionalParameter.Name)
        }
    }

    if (-not (Test-CommandParameterSet -Command $ConnectCommand -ParameterNames @($parameterNames))) {
        $attemptedParameters = @($parameterNames) -join ', '
        throw "Connect-MgGraph $($ConnectCommand.Module.Version) has no delegated parameter set supporting: $attemptedParameters. Install the latest Microsoft.Graph.Authentication module, restart PowerShell, and retry."
    }

    try {
        & $ConnectCommand @connectParameters | Out-Null
    }
    catch [System.Management.Automation.ParameterBindingException] {
        $attemptedParameters = @($parameterNames) -join ', '
        throw "Connect-MgGraph parameter binding failed in Microsoft.Graph.Authentication $($ConnectCommand.Module.Version) from '$($ConnectCommand.Module.Path)'. Parameters used: $attemptedParameters. Install the latest module, restart PowerShell 7, and retry. Original error: $($_.Exception.Message)"
    }
}

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
        return 'Not recorded'
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

function Get-SsoDetermination {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [bool]$AccountEnabled,

        [Parameter(Mandatory)]
        [string]$ConfiguredMode,

        [Parameter(Mandatory)]
        [bool]$ActivityChecked,

        [Parameter(Mandatory)]
        [bool]$ObservedSso
    )

    if (-not $AccountEnabled) {
        return [PSCustomObject]@{
            Result = 'No'
            Basis = 'The service principal is disabled, so users cannot currently sign in.'
        }
    }

    if ($ObservedSso) {
        return [PSCustomObject]@{
            Result = 'Yes'
            Basis = 'A successful SSO sign-in was observed in Log Analytics.'
        }
    }

    if ($ConfiguredMode -in 'SAML', 'OIDC', 'Password') {
        return [PSCustomObject]@{
            Result = 'Yes'
            Basis = "Microsoft Graph records the configured SSO mode as $ConfiguredMode."
        }
    }

    if ($ConfiguredMode -eq 'Not supported') {
        return [PSCustomObject]@{
            Result = 'No'
            Basis = 'Microsoft Graph explicitly records the SSO mode as notSupported.'
        }
    }

    $basis = if ($ActivityChecked) {
        'Microsoft Graph has no SSO mode recorded, and no successful SSO sign-in was observed during the selected period.'
    }
    else {
        'Microsoft Graph has no SSO mode recorded, and sign-in activity was not checked.'
    }

    return [PSCustomObject]@{
        Result = 'Not verified'
        Basis = $basis
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
    Write-Host "Get-SSOApps v$scriptVersion" -ForegroundColor Cyan
    Write-Verbose "Script path: $PSCommandPath"

    $processingStage = 'Microsoft Graph module validation'
    $connectMgGraphCommand = Import-CompatibleGraphAuthenticationModule `
        -MinimumVersion $minimumGraphAuthenticationVersion
    Write-Host "Microsoft.Graph.Authentication $($connectMgGraphCommand.Module.Version)" -ForegroundColor DarkGray

    $processingStage = 'Microsoft Graph context inspection'
    $graphContext = Get-MgContext -ErrorAction SilentlyContinue
    $hasRequiredScope = $null -ne $graphContext -and (
        $graphContext.Scopes -contains 'Application.Read.All' -or
        $graphContext.Scopes -contains 'Directory.Read.All'
    )
    $isRequestedTenant = [string]::IsNullOrWhiteSpace($TenantId) -or (
        $null -ne $graphContext -and $graphContext.TenantId -eq $TenantId
    )

    if ($null -eq $graphContext -or -not $hasRequiredScope -or -not $isRequestedTenant) {
        $processingStage = 'Microsoft Graph authentication'
        Write-Host 'Connecting to Microsoft Graph...' -ForegroundColor Cyan
        Connect-GraphForReport -ConnectCommand $connectMgGraphCommand -TenantId $TenantId
        $graphConnectionCreated = $true
        $graphContext = Get-MgContext -ErrorAction Stop
    }

    if ([string]::IsNullOrWhiteSpace($TenantId)) {
        $TenantId = $graphContext.TenantId
    }

    Write-Host "Connected to tenant $TenantId." -ForegroundColor Green
    Write-Host 'Retrieving Application and Legacy service principals...' -ForegroundColor Cyan

    $processingStage = 'service principal retrieval'
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
    $activityChecked = $false

    if (-not [string]::IsNullOrWhiteSpace($WorkspaceId)) {
        $processingStage = 'optional Log Analytics activity query'
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
            $activityChecked = $true
            Write-Host "Observed SSO activity found for $($observedByAppId.Count) applications." -ForegroundColor Green
        }
        catch {
            $activitySource = 'Log Analytics unavailable'
            Write-Warning "Activity enrichment failed; continuing with configuration data. $($_.Exception.Message)"
        }
    }
    else {
        Write-Warning 'No WorkspaceId supplied. The report will show Graph configuration, but observed SSO activity will be Not checked.'
    }

    $processingStage = 'SSO determination'
    $reportData = foreach ($app in $enterpriseApps) {
        $isEnabled = $app.AccountEnabled -eq $true
        if (-not $IncludeDisabled -and -not $isEnabled) {
            continue
        }

        $configuredMode = Get-ConfiguredSsoMode -Mode ([string]$app.PreferredSingleSignOnMode)

        $appId = [string]$app.AppId
        $observed = if (-not [string]::IsNullOrWhiteSpace($appId)) {
            $observedByAppId[$appId.ToLowerInvariant()]
        }
        else {
            $null
        }
        $hasObservedSso = $null -ne $observed -and $observed.Protocols.Count -gt 0

        $configurationConflict = $configuredMode -eq 'Not supported' -and $hasObservedSso
        $lastObservedSignIn = if ($hasObservedSso) {
            $observed.LastSignInUtc.UtcDateTime.ToString('o')
        }
        else {
            $null
        }
        $ssoDetermination = Get-SsoDetermination `
            -AccountEnabled $isEnabled `
            -ConfiguredMode $configuredMode `
            -ActivityChecked $activityChecked `
            -ObservedSso $hasObservedSso
        $activityObserved = if (-not $activityChecked) {
            'Not checked'
        }
        elseif ($hasObservedSso) {
            'Yes'
        }
        else {
            'No'
        }

        [PSCustomObject][ordered]@{
            'Application Name' = $app.DisplayName
            'Application (Client) ID' = $app.AppId
            'Service Principal Object ID' = $app.Id
            'Service Principal Type' = $app.ServicePrincipalType
            'Status' = if ($isEnabled) { 'Enabled' } else { 'Disabled' }
            'SSO Determination' = $ssoDetermination.Result
            'SSO Determination Basis' = $ssoDetermination.Basis
            'Configured SSO Mode' = $configuredMode
            'SSO Activity Observed' = $activityObserved
            'Observed Protocols' = if ($hasObservedSso) { (@($observed.Protocols) | Sort-Object) -join ', ' } else { $null }
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
        Write-Warning 'No Application or Legacy service principals matched the selected options.'
        return
    }

    $processingStage = 'CSV export'
    $resolvedOutputPath = [System.IO.Path]::GetFullPath($OutputPath)
    $outputDirectory = Split-Path -Path $resolvedOutputPath -Parent
    if (-not (Test-Path -LiteralPath $outputDirectory)) {
        $null = New-Item -ItemType Directory -Path $outputDirectory -Force
    }

    $reportData | Export-Csv -LiteralPath $resolvedOutputPath -NoTypeInformation -Encoding UTF8 -Delimiter ';'

    $ssoYesCount = @($reportData | Where-Object { $_.'SSO Determination' -eq 'Yes' }).Count
    $ssoNoCount = @($reportData | Where-Object { $_.'SSO Determination' -eq 'No' }).Count
    $ssoNotVerifiedCount = @($reportData | Where-Object { $_.'SSO Determination' -eq 'Not verified' }).Count

    Write-Host '--------------------------------------------------------' -ForegroundColor Cyan
    Write-Host "Report complete: $($reportData.Count) applications" -ForegroundColor Green
    Write-Host "SSO determination: Yes $ssoYesCount | No $ssoNoCount | Not verified $ssoNotVerifiedCount" -ForegroundColor White
    Write-Host "Activity source: $activitySource" -ForegroundColor White
    Write-Host $resolvedOutputPath -ForegroundColor White
    Write-Host '--------------------------------------------------------' -ForegroundColor Cyan

    $resolvedOutputPath
}
catch {
    $failureMessage = $_.Exception.Message
    if ($failureMessage -match 'consent|approval|AADSTS65001') {
        $failureMessage = 'Admin consent is required for Application.Read.All. Ask a tenant administrator to approve Microsoft Graph Command Line Tools, then retry.'
    }

    $errorType = $_.Exception.GetType().FullName
    $errorId = if ([string]::IsNullOrWhiteSpace($_.FullyQualifiedErrorId)) { 'Unavailable' } else { $_.FullyQualifiedErrorId }
    $lineNumber = $_.InvocationInfo.ScriptLineNumber
    $diagnosticMessage = "Get-SSOApps v$scriptVersion failed during $processingStage at script line $lineNumber. [$errorType; $errorId] $failureMessage"
    throw [System.InvalidOperationException]::new($diagnosticMessage, $_.Exception)
}
finally {
    if ($graphConnectionCreated -and $null -ne (Get-MgContext -ErrorAction SilentlyContinue)) {
        Write-Host 'Disconnecting the process-scoped Microsoft Graph session.' -ForegroundColor DarkGray
        Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
    }
}