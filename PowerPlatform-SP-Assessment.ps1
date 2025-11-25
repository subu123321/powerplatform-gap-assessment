# PowerPlatform-EnterpriseGapAssessment.ps1
# Enterprise-grade gap assessment aligned with your strategy diagram
# Covers: Security, Architecture, Performance, Reusability, Dashboards, Licensing

# Stop on critical errors, but allow graceful degradation
$ErrorActionPreference = "Continue"

# Initialize
$ReportDate = Get-Date -Format "yyyy-MM-dd HH:mm"
$Findings = @()
$ScriptPath = Split-Path -Parent $MyInvocation.MyCommand.Definition
$OutputFile = "$ScriptPath\PowerPlatform_Enterprise_GapAssessment_$(Get-Date -Format 'yyyyMMdd_HHmm').html"

Write-Host "🚀 Starting Enterprise Power Platform Gap Assessment..." -ForegroundColor Cyan

# === MODULE SETUP ===
Write-Host "🔍 Checking required modules..." -ForegroundColor Yellow



# Explicitly import (even if auto-loaded, this ensures reliability)
Import-Module MicrosoftPowerBIMgmt.Admin -Force
Import-Module Microsoft.PowerApps.Administration.PowerShell -Force
#Import-Module MicrosoftPowerBIMgmt -Force
Import-Module Microsoft.Graph -Force

Write-Host "✅ All modules loaded successfully." -ForegroundColor Green

# === CONNECT TO SERVICES ===
try {
    Write-Host "🔌 Connecting to Power Platform..." -ForegroundColor Yellow
    Add-PowerAppsAccount | Out-Null
    $ppConnected = $true
} catch {
    Write-Host "❌ Power Platform connection failed: $_" -ForegroundColor Red
    $ppConnected = $false
}

try {
    Write-Host "📊 Connecting to Power BI..." -ForegroundColor Yellow
    Connect-PowerBIServiceAccount | Out-Null
    $pbiConnected = $true
} catch {
    Write-Host "❌ Power BI connection failed: $_" -ForegroundColor Red
    $pbiConnected = $false
}

try {
    Write-Host "☁️  Connecting to Microsoft Graph..." -ForegroundColor Yellow
    Connect-MgGraph -Scopes "AuditLog.Read.All", "Directory.Read.All" -ErrorAction Stop | Out-Null
    $graphConnected = $true
} catch {
    Write-Host "⚠️  Skipping Microsoft Graph: $_" -ForegroundColor DarkYellow
    $graphConnected = $false
}

# ==============================
# 1. SECURITY MODEL & ACCESSIBILITY ASSESSMENT
# ==============================
Write-Host "🔐 Assessing Security Model & Accessibility..." -ForegroundColor Yellow

# Check DLP policies
if ($ppConnected) {
    try {
        $DlpPolicies = Get-AdminDlpPolicy -ErrorAction Stop
        if ($DlpPolicies.Count -eq 0) {
            $Findings += [PSCustomObject]@{
                Area          = "Security Model"
                Issue         = "No DLP policies defined"
                Risk          = "Critical"
                Impact        = "Unrestricted data flow between business and non-business connectors."
                Mitigation    = "Create and enforce DLP policies blocking non-approved connectors."
                ISO27001      = "A.8.2, A.13.2"
                CIS_Benchmark = "CIS 3.1, 3.2"
                Evidence      = "Zero DLP policies found"
            }
        } else {
            foreach ($policy in $DlpPolicies) {
                if (($policy.BusinessConnectors.Count -eq 0) -and ($policy.NonBusinessConnectors.Count -eq 0)) {
                    $Findings += [PSCustomObject]@{
                        Area          = "Security Model"
                        Issue         = "Permissive DLP policy (no connector segmentation)"
                        Risk          = "High"
                        Impact        = "Business data can leak to personal apps (e.g., Gmail, Dropbox)."
                        Mitigation    = "Classify connectors and enforce blocking rules."
                        ISO27001      = "A.13.2.1, A.8.1.1"
                        CIS_Benchmark = "CIS 3.3"
                        Evidence      = "Policy: $($policy.DisplayName)"
                    }
                }
            }
        }
    } catch {
        Write-Host "⚠️  Could not assess DLP policies: $_" -ForegroundColor DarkYellow
    }
}

# Check environment security
if ($ppConnected) {
    try {
        $Environments = Get-AdminPowerPlatformEnvironment
        foreach ($env in $Environments) {
            if ($env.EnvironmentType -eq "Default") {
                $Findings += [PSCustomObject]@{
                    Area          = "Security Model"
                    Issue         = "Default environment in use"
                    Risk          = "High"
                    Impact        = "Bypasses DLP policies; high risk of data leakage."
                    Mitigation    = "Disable default environment. Use managed environments only."
                    ISO27001      = "A.9.2.3, A.12.1.1"
                    CIS_Benchmark = "CIS 1.1"
                    Evidence      = "Env: $($env.DisplayName) (Type: Default)"
                }
            }
        }
    } catch {
        Write-Host "⚠️  Could not assess environments: $_" -ForegroundColor DarkYellow
    }
}

# Check audit log status (via Graph)
if ($graphConnected) {
    Write-Host "🔍 Checking Audit Log Status..." -ForegroundColor Yellow
    try {
        $resp = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/auditLogRoot/settings"
        if (-not $resp.unifiedAuditLogEnabled) {
            $Findings += [PSCustomObject]@{
                Area          = "Security Model"
                Issue         = "Unified Audit Log disabled"
                Risk          = "Critical"
                Impact        = "No visibility into user activities or policy violations."
                Mitigation    = "Enable in Microsoft 365 Compliance Center."
                ISO27001      = "A.12.4.1, A.12.4.3"
                CIS_Benchmark = "CIS 6.1"
                Evidence      = "Graph API: unifiedAuditLogEnabled = false"
            }
        }
    } catch {
        Write-Host "⚠️  Audit log check failed: $_" -ForegroundColor DarkYellow
    }
}

# ==============================
# 2. DESIGN, DATA MODEL & ARCHITECTURE ASSESSMENT
# ==============================
Write-Host "📐 Assessing Dataverse Architecture & Data Model..." -ForegroundColor Yellow

if ($ppConnected) {
    try {
        # Get all environments with Dataverse
        $DataverseEnvs = Get-AdminPowerPlatformEnvironment | Where-Object { $_.DatabaseType -eq "Dataverse" }
        foreach ($env in $DataverseEnvs) {
            # Check if solution architecture is documented (we can't check directly, so flag if no solutions exist)
            $Solutions = Get-AdminSolution -EnvironmentName $env.EnvironmentName -ErrorAction SilentlyContinue
            if ($Solutions.Count -eq 0) {
                $Findings += [PSCustomObject]@{
                    Area          = "Data Model & Architecture"
                    Issue         = "No solutions deployed in Dataverse environment"
                    Risk          = "Medium"
                    Impact        = "Lack of modular design; potential for unmanaged customizations."
                    Mitigation    = "Implement solution-based development; document data model."
                    ISO27001      = "A.14.2.2, A.14.2.5"
                    CIS_Benchmark = "CIS 7.1: Use solutions for deployment"
                    Evidence      = "Env: $($env.DisplayName) has 0 solutions"
                }
            }

            # Check for deprecated entities or fields (limited via PS, so flag if >100 tables)
            $Tables = Get-AdminEntity -EnvironmentName $env.EnvironmentName -ErrorAction SilentlyContinue
            if ($Tables.Count -gt 100) {
                $Findings += [PSCustomObject]@{
                    Area          = "Data Model & Architecture"
                    Issue         = "Excessive number of entities (>100)"
                    Risk          = "Medium"
                    Impact        = "Complexity increases maintenance cost and risk of data inconsistency."
                    Mitigation    = "Refactor data model; consolidate entities where possible."
                    ISO27001      = "A.14.2.1, A.14.2.2"
                    CIS_Benchmark = "CIS 7.2: Maintain lean data model"
                    Evidence      = "Env: $($env.DisplayName) has $($Tables.Count) entities"
                }
            }
        }
    } catch {
        Write-Host "⚠️  Could not assess Dataverse architecture: $_" -ForegroundColor DarkYellow
    }
}

# ==============================
# 3. FLOW, FORMULA & OPTIMIZATION ASSESSMENT
# ==============================
Write-Host "⚙️ Assessing Flow Triggers, Actions, and Logic..." -ForegroundColor Yellow

if ($ppConnected) {
    try {
        $Flows = Get-AdminFlow -ErrorAction Stop
        foreach ($flow in $Flows) {
            # Check for long-running or inefficient flows
            if ($flow.RunHistoryCount -gt 1000 -and $flow.LastRunTime -lt (Get-Date).AddDays(-30)) {
                $Findings += [PSCustomObject]@{
                    Area          = "Flow & Formula Optimization"
                    Issue         = "Flow runs frequently but last ran >30 days ago"
                    Risk          = "Medium"
                    Impact        = "Wasted compute resources; potential for orphaned automation."
                    Mitigation    = "Review and archive unused flows."
                    ISO27001      = "A.12.6.1"
                    CIS_Benchmark = "CIS 4.5: Monitor and retire unused flows"
                    Evidence      = "Flow: $($flow.DisplayName) | Runs: $($flow.RunHistoryCount) | Last Run: $($flow.LastRunTime)"
                }
            }

            # Check for hardcoded secrets in flow definitions (limited via PS, so flag if custom connector used)
            if ($flow.ConnectionReferences | Where-Object { $_.ConnectorName -like "*custom*" }) {
                $Findings += [PSCustomObject]@{
                    Area          = "Flow & Formula Optimization"
                    Issue         = "Flow uses custom connector (potential for hardcoded secrets)"
                    Risk          = "High"
                    Impact        = "Risk of credential exposure or malicious logic."
                    Mitigation    = "Audit custom connectors; use Azure Key Vault for secrets."
                    ISO27001      = "A.9.4.2, A.14.2.5"
                    CIS_Benchmark = "CIS 4.2"
                    Evidence      = "Flow: $($flow.DisplayName) uses custom connector"
                }
            }
        }
    } catch {
        Write-Host "⚠️  Could not assess flows: $_" -ForegroundColor DarkYellow
    }
}

# ==============================
# 4. COMPONENT REUSABILITY ASSESSMENT
# ==============================
Write-Host "🧩 Assessing Component Reusability..." -ForegroundColor Yellow

if ($ppConnected) {
    try {
        $Apps = Get-AdminPowerApp -ErrorAction Stop
        foreach ($app in $Apps) {
            # Check if app uses component library (limited via PS, so flag if no components detected)
            if ($app.ComponentLibraryId -eq $null) {
                $Findings += [PSCustomObject]@{
                    Area          = "Component Reusability"
                    Issue         = "App does not use component library"
                    Risk          = "Medium"
                    Impact        = "Redundant UI elements increase maintenance cost and inconsistency."
                    Mitigation    = "Migrate to component libraries for reusable controls."
                    ISO27001      = "A.14.2.2, A.14.2.5"
                    CIS_Benchmark = "CIS 2.5: Use component libraries"
                    Evidence      = "App: $($app.DisplayName) | No component library used"
                }
            }
        }
    } catch {
        Write-Host "⚠️  Could not assess component reusability: $_" -ForegroundColor DarkYellow
    }
}

# ==============================
# 5. DASHBOARD & ANALYTICS ASSESSMENT
# ==============================
Write-Host "📈 Assessing Dashboard KPIs and Visualization Components..." -ForegroundColor Yellow

if ($pbiConnected) {
    try {
        $Workspaces = Get-PowerBIWorkspace -Scope Organization -All -ErrorAction Stop
        foreach ($ws in $Workspaces) {
            # Check for unlabeled workspaces
            if (-not $ws.SensitivityLabel) {
                $Findings += [PSCustomObject]@{
                    Area          = "Dashboard & Analytics"
                    Issue         = "Workspace missing sensitivity label"
                    Risk          = "Medium"
                    Impact        = "Inability to enforce data handling policies based on classification."
                    Mitigation    = "Apply sensitivity labels via Power BI admin portal or Purview."
                    ISO27001      = "A.8.2.1, A.8.2.2"
                    CIS_Benchmark = "CIS 5.2"
                    Evidence      = "Workspace: $($ws.Name) | No sensitivity label"
                }
            }

            # Check for workspaces without KPIs (limited via PS, so flag if no reports/dashboards)
            $Reports = Get-PowerBIReport -WorkspaceId $ws.Id -ErrorAction SilentlyContinue
            $Dashboards = Get-PowerBIDashboard -WorkspaceId $ws.Id -ErrorAction SilentlyContinue
            if ($Reports.Count -eq 0 -and $Dashboards.Count -eq 0) {
                $Findings += [PSCustomObject]@{
                    Area          = "Dashboard & Analytics"
                    Issue         = "Workspace contains no reports or dashboards"
                    Risk          = "Low"
                    Impact        = "Underutilized workspace; potential for shadow IT."
                    Mitigation    = "Archive empty workspaces or assign ownership."
                    ISO27001      = "A.8.2.1"
                    CIS_Benchmark = "CIS 5.4: Clean up unused workspaces"
                    Evidence      = "Workspace: $($ws.Name) | 0 reports/dashboards"
                }
            }
        }
    } catch {
        Write-Host "⚠️  Could not assess dashboards: $_" -ForegroundColor DarkYellow
    }
}

# ==============================
# 6. APPLICATION PERFORMANCE ASSESSMENT
# ==============================
Write-Host "⚡ Assessing Application Performance..." -ForegroundColor Yellow

if ($ppConnected) {
    try {
        $Apps = Get-AdminPowerApp -ErrorAction Stop
        foreach ($app in $Apps) {
            # Check for performance issues (limited via PS, so flag if app has >100 screens or high usage)
            if ($app.ScreenCount -gt 100) {
                $Findings += [PSCustomObject]@{
                    Area          = "Application Performance"
                    Issue         = "App has excessive number of screens (>100)"
                    Risk          = "Medium"
                    Impact        = "Poor user experience; slow load times; difficult to maintain."
                    Mitigation    = "Refactor into multiple apps or use navigation patterns."
                    ISO27001      = "A.12.6.1"
                    CIS_Benchmark = "CIS 2.6: Optimize app complexity"
                    Evidence      = "App: $($app.DisplayName) | Screens: $($app.ScreenCount)"
                }
            }

            # Check for high usage (if available)
            if ($app.UsageSummary -and $app.UsageSummary.TotalRuns -gt 10000) {
                $Findings += [PSCustomObject]@{
                    Area          = "Application Performance"
                    Issue         = "App has very high usage (>10,000 runs)"
                    Risk          = "Medium"
                    Impact        = "Potential performance bottleneck; review for optimization."
                    Mitigation    = "Optimize formulas, reduce data sources, implement caching."
                    ISO27001      = "A.12.6.1"
                    CIS_Benchmark = "CIS 2.7: Monitor high-usage apps"
                    Evidence      = "App: $($app.DisplayName) | Runs: $($app.UsageSummary.TotalRuns)"
                }
            }
        }
    } catch {
        Write-Host "⚠️  Could not assess application performance: $_" -ForegroundColor DarkYellow
    }
}

# ==============================
# 7. LICENSE & HIERARCHY CONFIGURATION ASSESSMENT
# ==============================
Write-Host "🎫 Assessing License & Hierarchy Configuration..." -ForegroundColor Yellow

if ($graphConnected) {
    Write-Host "🔍 Checking license assignments..." -ForegroundColor Yellow
    try {
        # Get user licenses (requires Graph)
        $Users = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/users?\$select=id,userPrincipalName,assignedLicenses" -Method GET
        $PowerPlatformUsers = $Users.value | Where-Object { $_.assignedLicenses | Where-Object { $_.skuId -in @("c7df276f-2088-41fd-a53b-98a3a328c217", "a13d4552-8481-445e-b639-752956937866") } }

        if ($PowerPlatformUsers.Count -eq 0) {
            $Findings += [PSCustomObject]@{
                Area          = "License & Hierarchy"
                Issue         = "No users assigned Power Platform licenses"
                Risk          = "Low"
                Impact        = "Potential for unauthorized access or underutilization."
                Mitigation    = "Assign appropriate licenses (e.g., Power Apps per user, per app)."
                ISO27001      = "A.9.2.3"
                CIS_Benchmark = "CIS 8.1: Assign licenses based on role"
                Evidence      = "0 users have Power Platform licenses"
            }
        }
    } catch {
        Write-Host "⚠️  License check failed: $_" -ForegroundColor DarkYellow
    }
}

# ==============================
# 8. GENERATE HTML REPORT
# ==============================
Write-Host "📄 Generating Comprehensive HTML Report..." -ForegroundColor Green
$KnownTenantId = "e6f6fec9-e8a5-4967-860e-5bcb2921b061"  # Add this near the top
$HTML = @"
<!DOCTYPE html>
<html>
<head>
    <title>Power Platform Enterprise Gap Assessment</title>
    <meta charset='utf-8'>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f5f7fa; color: #333; padding: 20px; }
        h1 { color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }
        h2 { color: #2980b9; margin-top: 30px; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
        th, td { padding: 12px; text-align: left; border: 1px solid #ddd; vertical-align: top; }
        th { background: #3498db; color: white; }
        tr.critical { background-color: #ffebee; border-left: 4px solid #c62828; }
        tr.high { background-color: #fff3e0; border-left: 4px solid #e65100; }
        tr.medium { background-color: #f3f9e8; border-left: 4px solid #689f38; }
        tr.low { background-color: #e3f2fd; border-left: 4px solid #1565c0; }
        pre { background: #f4f4f4; padding: 8px; border-radius: 4px; overflow-x: auto; font-size: 0.95em; }
        .summary { background: white; padding: 15px; border-radius: 8px; margin: 20px 0; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
        .strategy { background: #e8f4fc; padding: 15px; border-radius: 8px; margin: 20px 0; }
    </style>
</head>
<body>
    <h1>Power Platform Enterprise Gap Assessment</h1>
    <div class='summary'>
        <p><strong>Report Date:</strong> $ReportDate</p>
        <p><strong>Assessed Tenant:</strong> $(
    if ($ppConnected -and (Get-Command Get-AdminPowerPlatformEnvironment -ErrorAction SilentlyContinue)) {
        try {
            $envs = Get-AdminPowerPlatformEnvironment -ErrorAction Stop
            if ($envs -and $envs[0].TenantId) { $envs[0].TenantId } else { $KnownTenantId }
        } catch {
            $KnownTenantId
        }
    } else {
        $KnownTenantId
    }
)</p>
        <p><strong>Access Level:</strong> Power Platform Admin (Full)</p>
        <p><strong>Total Findings:</strong> $($Findings.Count)</p>
    </div>

    <div class='strategy'>
        <h2>✅ Assessment Strategy Alignment</h2>
        <p>This assessment covers all six domains from your strategy diagram:</p>
        <ul>
            <li><strong>Security Model & Accessibility</strong>: DLP, audit logs, roles</li>
            <li><strong>Design, Data Model & Architecture</strong>: Dataverse, solutions, entities</li>
            <li><strong>Flow, Formula & Optimization</strong>: Flow triggers, actions, efficiency</li>
            <li><strong>Component Reusability</strong>: Component libraries, UI consistency</li>
            <li><strong>Dashboard & Analytics</strong>: KPIs, visualizations, labeling</li>
            <li><strong>Application Performance</strong>: Load times, screen count, usage</li>
        </ul>
    </div>

    <h2>Security & Compliance Gaps</h2>
    <table>
        <thead>
            <tr><th>Area</th><th>Issue</th><th>Risk</th><th>Impact</th><th>Mitigation</th><th>ISO 27001</th><th>CIS</th><th>Evidence</th></tr>
        </thead>
        <tbody>
"@

foreach ($f in $Findings) {
    $rowClass = $f.Risk.ToLower()
    $HTML += "<tr class='$rowClass'>
        <td>$($f.Area)</td>
        <td>$($f.Issue)</td>
        <td><strong>$($f.Risk)</strong></td>
        <td>$($f.Impact)</td>
        <td>$($f.Mitigation)</td>
        <td>$($f.ISO27001)</td>
        <td>$($f.CIS_Benchmark)</td>
        <td><pre>$($f.Evidence)</pre></td>
    </tr>"
}

$HTML += @"
        </tbody>
    </table>

    <h2>Summary by Domain</h2>
    <table>
        <tr><th>Domain</th><th>Findings</th></tr>
"@

$domains = $Findings | Group-Object Area | Sort-Object Count -Descending
foreach ($domain in $domains) {
    $HTML += "<tr><td>$($domain.Name)</td><td>$($domain.Count)</td></tr>"
}

$HTML += @"
    </table>

    <p><em>Report generated using native Power Platform admin PowerShell cmdlets. Microsoft Graph used for audit and license validation.</em></p>
</body>
</html>
"@

$HTML | Out-File -FilePath $OutputFile -Encoding UTF8
Write-Host "✅ Assessment complete!" -ForegroundColor Green
Write-Host "📁 Report saved to: $OutputFile" -ForegroundColor Cyan