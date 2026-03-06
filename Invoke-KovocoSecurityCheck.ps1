<#
.SYNOPSIS
    Kovoco SQL Server Security Assessment Tool v2.0
    An interactive web-based GUI wrapper for sp_CheckSecurity by Straight Path Solutions (MIT License)

.DESCRIPTION
    This script launches a local web server with a full security assessment dashboard.
    Connect to any SQL Server instance through the browser UI, run sp_CheckSecurity,
    and interactively explore findings — all from a single portable PowerShell script.

    sp_CheckSecurity is copyright Straight Path IT Solutions, LLC under the MIT License.
    See: https://github.com/StraightPathSolutions/sp_CheckSecurity

.PARAMETER Port
    The local port for the web UI. Defaults to 18642.

.PARAMETER SqlFilePath
    Path to sp_CheckSecurity.sql for optional installation on target instances.

.PARAMETER NoBrowser
    If set, does not auto-open the browser.

.EXAMPLE
    .\Invoke-KovocoSecurityCheck.ps1

.EXAMPLE
    .\Invoke-KovocoSecurityCheck.ps1 -Port 9090 -SqlFilePath ".\sp_CheckSecurity.sql"

.NOTES
    Requirements:
    - PowerShell 5.1 or later (PowerShell 7+ recommended)
    - SqlServer module (will attempt to install if missing)
    - sysadmin role on target SQL Server instances
    - sp_CheckSecurity installed on target instances (or provide -SqlFilePath to install)
#>

[CmdletBinding()]
param(
    [int]$Port = 18642,
    [string]$SqlFilePath,
    [switch]$NoBrowser
)

$KovocoVersion = "2.0.0"

# ============================================================================
# BANNER
# ============================================================================
$banner = @"

    +=================================================================+
    |                                                                 |
    |         K O V O C O                                             |
    |         SQL Server Security Assessment Tool v$KovocoVersion               |
    |                                                                 |
    |         Powered by sp_CheckSecurity                             |
    |         by Straight Path Solutions (MIT License)                 |
    |                                                                 |
    +=================================================================+

"@
Write-Host $banner -ForegroundColor Cyan

# ============================================================================
# PREREQS
# ============================================================================
Write-Host "  [*] Checking prerequisites..." -ForegroundColor DarkGray

if (-not (Get-Module -ListAvailable -Name SqlServer)) {
    Write-Host "  [!] SqlServer module not found. Installing..." -ForegroundColor Yellow
    try {
        Install-Module -Name SqlServer -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
        Write-Host "  [+] SqlServer module installed." -ForegroundColor Green
    }
    catch {
        Write-Host "  [X] Failed to install SqlServer module: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "      Run: Install-Module SqlServer -Scope CurrentUser" -ForegroundColor Yellow
        exit 1
    }
}
Import-Module SqlServer -ErrorAction Stop
Write-Host "  [+] SqlServer module loaded." -ForegroundColor Green

# Store the sql file path for later use
$script:SpCheckSecurityPath = $SqlFilePath

# ============================================================================
# HTML DASHBOARD (embedded)
# ============================================================================

$HTML_DASHBOARD = @'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Kovoco - SQL Server Security Assessment</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=DM+Sans:ital,opsz,wght@0,9..40,300;0,9..40,500;0,9..40,700;0,9..40,800;1,9..40,400&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
<style>
:root {
  --bg-primary: #06090f;
  --bg-card: rgba(14, 20, 33, 0.85);
  --bg-card-hover: rgba(20, 28, 45, 0.95);
  --border: rgba(56, 78, 119, 0.25);
  --border-active: rgba(99, 149, 255, 0.4);
  --text-primary: #d8e2f0;
  --text-secondary: #7a8ba8;
  --text-muted: #4a5873;
  --accent: #5b8af5;
  --accent-glow: rgba(91, 138, 245, 0.15);
  --high: #f04848;
  --high-bg: rgba(240, 72, 72, 0.08);
  --medium: #e8a020;
  --medium-bg: rgba(232, 160, 32, 0.08);
  --low: #4499dd;
  --low-bg: rgba(68, 153, 221, 0.08);
  --info: #607088;
  --info-bg: rgba(96, 112, 136, 0.08);
  --success: #38b060;
  --font-body: 'DM Sans', -apple-system, sans-serif;
  --font-mono: 'JetBrains Mono', monospace;
}

* { margin: 0; padding: 0; box-sizing: border-box; }

body {
  font-family: var(--font-body);
  background: var(--bg-primary);
  color: var(--text-primary);
  min-height: 100vh;
  overflow-x: hidden;
}

body::before {
  content: '';
  position: fixed; inset: 0;
  background-image:
    linear-gradient(rgba(56,78,119,0.04) 1px, transparent 1px),
    linear-gradient(90deg, rgba(56,78,119,0.04) 1px, transparent 1px);
  background-size: 48px 48px;
  pointer-events: none; z-index: 0;
}

.header {
  position: sticky; top: 0; z-index: 100;
  background: rgba(6, 9, 15, 0.92);
  backdrop-filter: blur(16px);
  border-bottom: 1px solid var(--border);
  padding: 0 28px; height: 56px;
  display: flex; align-items: center; justify-content: space-between;
}
.logo-group { display: flex; align-items: center; gap: 12px; }
.logo-mark {
  width: 32px; height: 32px;
  background: linear-gradient(135deg, #5b8af5 0%, #3a5fc0 100%);
  border-radius: 7px;
  display: flex; align-items: center; justify-content: center;
  font-weight: 800; font-size: 15px; color: white;
  box-shadow: 0 2px 12px rgba(91,138,245,0.25);
}
.logo-text { font-weight: 700; font-size: 15px; letter-spacing: 0.08em; color: #fff; }
.logo-sub { font-size: 9.5px; color: var(--accent); letter-spacing: 0.18em; text-transform: uppercase; margin-top: -1px; }
.header-status { font-family: var(--font-mono); font-size: 11px; padding: 3px 10px; border-radius: 4px; }
.status-disconnected { background: rgba(240,72,72,0.1); color: var(--high); border: 1px solid rgba(240,72,72,0.2); }
.status-connected { background: rgba(56,176,96,0.1); color: var(--success); border: 1px solid rgba(56,176,96,0.2); }

.container { position: relative; z-index: 1; max-width: 1160px; margin: 0 auto; padding: 24px; }

.connect-screen {
  display: flex; align-items: center; justify-content: center;
  min-height: calc(100vh - 56px); padding-bottom: 80px;
}
.connect-box {
  background: var(--bg-card); border: 1px solid var(--border);
  border-radius: 12px; padding: 36px 40px;
  width: 100%; max-width: 480px;
  box-shadow: 0 8px 40px rgba(0,0,0,0.3);
}
.connect-box h2 { font-size: 18px; font-weight: 700; color: #fff; margin-bottom: 4px; }
.connect-box .subtitle { font-size: 13px; color: var(--text-secondary); margin-bottom: 24px; }

.form-group { margin-bottom: 16px; }
.form-group label {
  display: block; font-size: 11px; font-weight: 600;
  color: var(--text-secondary); text-transform: uppercase;
  letter-spacing: 0.08em; margin-bottom: 6px;
}
.form-group input, .form-group select {
  width: 100%; padding: 9px 12px;
  background: rgba(6,9,15,0.6); border: 1px solid var(--border);
  border-radius: 6px; color: var(--text-primary);
  font-family: var(--font-mono); font-size: 13px;
  outline: none; transition: border-color 0.2s;
}
.form-group input:focus, .form-group select:focus {
  border-color: var(--accent); box-shadow: 0 0 0 3px var(--accent-glow);
}
.form-group input::placeholder { color: var(--text-muted); }
.form-group select option { background: #0a0e1a; color: var(--text-primary); }
.form-row { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }

.checkbox-row {
  display: flex; align-items: center; gap: 8px;
  margin-bottom: 16px; cursor: pointer;
}
.checkbox-row input[type="checkbox"] { width: 16px; height: 16px; accent-color: var(--accent); cursor: pointer; }
.checkbox-row span { font-size: 13px; color: var(--text-secondary); }

.btn {
  display: inline-flex; align-items: center; justify-content: center; gap: 8px;
  padding: 10px 20px; border-radius: 7px; font-size: 13px; font-weight: 600;
  border: none; cursor: pointer; transition: all 0.2s; font-family: var(--font-body);
}
.btn-primary {
  background: linear-gradient(135deg, #5b8af5, #3a6ae0);
  color: white; width: 100%;
  box-shadow: 0 2px 12px rgba(91,138,245,0.25);
}
.btn-primary:hover { box-shadow: 0 4px 20px rgba(91,138,245,0.4); transform: translateY(-1px); }
.btn-primary:disabled { opacity: 0.5; cursor: not-allowed; transform: none; box-shadow: none; }
.btn-outline { background: transparent; border: 1px solid var(--border); color: var(--text-secondary); }
.btn-outline:hover { border-color: var(--accent); color: var(--accent); }

.error-msg {
  background: var(--high-bg); border: 1px solid rgba(240,72,72,0.2);
  border-radius: 6px; padding: 10px 14px; font-size: 12px; color: var(--high);
  margin-bottom: 16px; display: none;
}
.install-note { font-size: 11px; color: var(--text-muted); margin-top: 12px; text-align: center; line-height: 1.5; }

.tab-bar { display: flex; gap: 0; border-bottom: 1px solid var(--border); margin-bottom: 24px; }
.tab-btn {
  padding: 10px 20px; font-size: 12.5px; font-weight: 500;
  color: var(--text-muted); background: none; border: none;
  border-bottom: 2px solid transparent; cursor: pointer;
  transition: all 0.15s; font-family: var(--font-body);
}
.tab-btn:hover { color: var(--text-secondary); }
.tab-btn.active { color: var(--accent); border-bottom-color: var(--accent); font-weight: 700; }

.summary-grid { display: grid; grid-template-columns: 200px 1fr; gap: 16px; margin-bottom: 24px; }
.score-card {
  background: var(--bg-card); border: 1px solid var(--border);
  border-radius: 10px; padding: 24px;
  display: flex; flex-direction: column; align-items: center; justify-content: center;
}
.score-label { font-size: 10px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.12em; margin-bottom: 10px; }
.score-ring { position: relative; width: 110px; height: 110px; }
.score-ring svg { transform: rotate(-90deg); }
.score-value { position: absolute; inset: 0; display: flex; align-items: center; justify-content: center; flex-direction: column; }
.score-value .num { font-size: 30px; font-weight: 800; }
.score-value .denom { font-size: 9px; color: var(--text-muted); }
.score-verdict { font-size: 10px; color: var(--text-secondary); margin-top: 6px; }

.severity-cards { display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; }
.sev-card {
  background: var(--bg-card); border: 1px solid var(--border);
  border-radius: 10px; padding: 16px 18px; cursor: pointer;
  transition: all 0.15s; position: relative; overflow: hidden;
}
.sev-card:hover { border-color: var(--border-active); background: var(--bg-card-hover); }
.sev-card .bar { position: absolute; top: 0; left: 0; right: 0; height: 2px; }
.sev-card .sev-label { font-size: 10px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.08em; margin-bottom: 6px; }
.sev-card .sev-count { font-size: 32px; font-weight: 800; line-height: 1; }
.sev-card .sev-unit { font-size: 10px; color: var(--text-muted); margin-top: 3px; }

.meta-card {
  background: var(--bg-card); border: 1px solid var(--border);
  border-radius: 10px; padding: 18px 20px; margin-bottom: 20px;
}
.meta-card .meta-title { font-size: 11px; font-weight: 700; color: var(--accent); text-transform: uppercase; letter-spacing: 0.1em; margin-bottom: 10px; }
.meta-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(240px, 1fr)); gap: 6px; font-size: 12.5px; }
.meta-grid .mk { color: var(--text-muted); min-width: 85px; display: inline-block; }
.meta-grid .mv { color: var(--text-secondary); font-family: var(--font-mono); font-size: 11.5px; }

.filter-bar { display: flex; gap: 6px; margin-bottom: 14px; flex-wrap: wrap; align-items: center; }
.filter-btn {
  padding: 5px 12px; border-radius: 5px; font-size: 11.5px; font-weight: 600;
  border: 1px solid var(--border); background: transparent;
  color: var(--text-muted); cursor: pointer; transition: all 0.12s; font-family: var(--font-body);
}
.filter-btn:hover { border-color: var(--border-active); color: var(--text-secondary); }
.filter-btn.active { border-color: var(--accent); background: var(--accent-glow); color: var(--accent); }
.search-input {
  margin-left: auto; padding: 5px 12px; border-radius: 5px;
  border: 1px solid var(--border); background: rgba(6,9,15,0.5);
  color: var(--text-primary); font-size: 12px; width: 200px; outline: none;
  font-family: var(--font-mono);
}
.search-input:focus { border-color: var(--accent); box-shadow: 0 0 0 3px var(--accent-glow); }

.finding-row {
  background: var(--bg-card); border: 1px solid var(--border);
  border-radius: 8px; margin-bottom: 4px; cursor: pointer;
  transition: all 0.12s; overflow: hidden;
}
.finding-row:hover { border-color: var(--border-active); background: var(--bg-card-hover); }
.finding-header { padding: 10px 14px; display: flex; align-items: center; gap: 10px; }
.sev-dot { width: 6px; height: 6px; border-radius: 50%; flex-shrink: 0; }
.finding-sev { font-size: 9.5px; font-weight: 700; text-transform: uppercase; min-width: 72px; }
.finding-name { font-weight: 600; font-size: 12.5px; color: #eef2f8; flex: 1; }
.finding-db { font-size: 10.5px; color: var(--accent); background: var(--accent-glow); padding: 1px 7px; border-radius: 3px; font-family: var(--font-mono); }
.finding-id { font-size: 10px; color: var(--text-muted); font-family: var(--font-mono); }
.finding-arrow { color: var(--text-muted); font-size: 12px; transition: transform 0.2s; }
.finding-row.expanded .finding-arrow { transform: rotate(180deg); }

.finding-detail { display: none; padding: 0 14px 14px 28px; border-top: 1px solid rgba(56,78,119,0.12); }
.finding-row.expanded .finding-detail { display: block; }
.detail-section { margin-top: 10px; font-size: 12.5px; line-height: 1.6; }
.detail-section .dl { color: var(--text-muted); }
.detail-section .dv { color: var(--text-secondary); }
.action-box {
  background: rgba(56,176,96,0.06); border: 1px solid rgba(56,176,96,0.15);
  border-radius: 6px; padding: 9px 12px; margin-top: 10px;
}
.action-box .al { font-size: 10px; font-weight: 700; color: var(--success); text-transform: uppercase; letter-spacing: 0.06em; }
.action-box .av { font-size: 12px; color: #6cd992; margin-top: 2px; }
.read-more { color: var(--accent); font-size: 11.5px; text-decoration: none; margin-top: 8px; display: inline-block; }
.read-more:hover { text-decoration: underline; }

.empty-state { text-align: center; padding: 48px; color: var(--text-muted); font-size: 13px; }

.high-alert {
  background: var(--bg-card); border: 1px solid rgba(240,72,72,0.2);
  border-radius: 10px; padding: 18px 20px; margin-bottom: 20px;
}
.high-alert .ha-title { font-size: 11px; font-weight: 700; color: var(--high); text-transform: uppercase; letter-spacing: 0.1em; margin-bottom: 10px; }
.high-alert-item { padding: 8px 0; border-bottom: 1px solid rgba(240,72,72,0.06); display: flex; gap: 10px; align-items: flex-start; }
.high-alert-item:last-child { border-bottom: none; }
.ha-dot { color: var(--high); font-size: 8px; margin-top: 5px; }
.ha-name { font-weight: 600; color: #eef2f8; font-size: 12.5px; }
.ha-detail { color: var(--text-secondary); font-size: 11.5px; margin-top: 1px; }

.roadmap-intro {
  background: var(--bg-card); border: 1px solid var(--border);
  border-radius: 10px; padding: 18px 20px; margin-bottom: 20px;
}
.roadmap-intro h3 { font-size: 14px; color: var(--accent); font-weight: 700; margin-bottom: 6px; }
.roadmap-intro p { font-size: 12.5px; color: var(--text-secondary); line-height: 1.6; }
.roadmap-cat { font-size: 11px; font-weight: 700; color: var(--accent); text-transform: uppercase; letter-spacing: 0.1em; margin: 16px 0 8px 4px; }
.roadmap-item {
  background: var(--bg-card); border: 1px solid rgba(56,78,119,0.12);
  border-radius: 7px; padding: 11px 14px; margin-bottom: 3px;
  display: flex; gap: 10px; align-items: flex-start;
}
.ri-name { font-weight: 600; color: #eef2f8; font-size: 12.5px; }
.ri-desc { color: var(--text-secondary); font-size: 11.5px; margin-top: 1px; }
.ri-sev { font-size: 9px; font-weight: 700; text-transform: uppercase; flex-shrink: 0; }

.footer { text-align: center; padding: 24px; font-size: 10.5px; color: var(--text-muted); border-top: 1px solid var(--border); margin-top: 32px; }

.spinner {
  width: 18px; height: 18px; border: 2px solid rgba(255,255,255,0.2);
  border-top-color: white; border-radius: 50%;
  animation: spin 0.6s linear infinite; display: inline-block;
}
@keyframes spin { to { transform: rotate(360deg); } }
@keyframes fadeIn { from { opacity: 0; transform: translateY(8px); } to { opacity: 1; transform: translateY(0); } }
.fade-in { animation: fadeIn 0.3s ease; }

@media (max-width: 768px) {
  .summary-grid { grid-template-columns: 1fr; }
  .severity-cards { grid-template-columns: repeat(2, 1fr); }
  .form-row { grid-template-columns: 1fr; }
  .meta-grid { grid-template-columns: 1fr; }
}
</style>
</head>
<body>

<div class="header">
  <div class="logo-group">
    <div class="logo-mark">K</div>
    <div>
      <div class="logo-text">KOVOCO</div>
      <div class="logo-sub">Security Assessment</div>
    </div>
  </div>
  <div id="headerStatus" class="header-status status-disconnected">DISCONNECTED</div>
</div>

<div id="connectScreen" class="connect-screen">
  <div class="connect-box fade-in">
    <h2>Connect to SQL Server</h2>
    <div class="subtitle">Enter your connection details to begin the security assessment.</div>
    <div id="connectError" class="error-msg"></div>
    <div class="form-group">
      <label>Server Instance</label>
      <input type="text" id="serverInstance" placeholder="SERVER1\INSTANCE or server1,1433" autofocus />
    </div>
    <div class="form-group">
      <label>Authentication</label>
      <select id="authType" onchange="toggleAuth()">
        <option value="windows">Windows Authentication</option>
        <option value="sql">SQL Server Authentication</option>
      </select>
    </div>
    <div id="sqlAuthFields" style="display:none;">
      <div class="form-row">
        <div class="form-group">
          <label>Username</label>
          <input type="text" id="sqlUser" placeholder="sa" />
        </div>
        <div class="form-group">
          <label>Password</label>
          <input type="password" id="sqlPass" placeholder="password" />
        </div>
      </div>
    </div>
    <div class="form-group">
      <label>Database</label>
      <input type="text" id="database" placeholder="master" value="master" />
    </div>
    <div class="form-row">
      <div class="form-group">
        <label>Mode</label>
        <select id="mode">
          <option value="99">All findings (99)</option>
          <option value="0">Issues only (0)</option>
          <option value="1">High only (1)</option>
        </select>
      </div>
      <div class="form-group">
        <label>Preferred DB Owner</label>
        <input type="text" id="preferredOwner" placeholder="(optional)" />
      </div>
    </div>
    <div class="checkbox-row" onclick="this.querySelector('input').click()">
      <input type="checkbox" id="checkLocalAdmin" onclick="event.stopPropagation()" />
      <span>Check Local Administrators group</span>
    </div>
    <div class="checkbox-row" onclick="this.querySelector('input').click()">
      <input type="checkbox" id="overrideCheck" onclick="event.stopPropagation()" />
      <span>Override 50-database limit</span>
    </div>
    <div class="checkbox-row" onclick="this.querySelector('input').click()">
      <input type="checkbox" id="installProc" onclick="event.stopPropagation()" />
      <span>Install sp_CheckSecurity before running</span>
    </div>
    <button class="btn btn-primary" id="connectBtn" onclick="runAssessment()">
      Run Security Assessment
    </button>
    <div class="install-note">
      Requires sysadmin role &middot; sp_CheckSecurity by Straight Path Solutions (MIT License)
    </div>
  </div>
</div>

<div id="dashboardScreen" style="display:none;">
  <div class="container fade-in">
    <div class="tab-bar">
      <button class="tab-btn active" onclick="switchTab('dashboard',this)">Dashboard</button>
      <button class="tab-btn" onclick="switchTab('findings',this)" id="findingsTabBtn">Findings</button>
      <button class="tab-btn" onclick="switchTab('roadmap',this)">Additional Checks Roadmap</button>
      <button class="btn btn-outline" style="margin-left:auto;font-size:11px;padding:5px 14px;" onclick="showConnect()">New Assessment</button>
    </div>

    <div id="tab-dashboard">
      <div class="summary-grid">
        <div class="score-card">
          <div class="score-label">Security Score</div>
          <div class="score-ring">
            <svg viewBox="0 0 110 110" width="110" height="110">
              <circle cx="55" cy="55" r="48" fill="none" stroke="rgba(56,78,119,0.12)" stroke-width="7"/>
              <circle id="scoreArc" cx="55" cy="55" r="48" fill="none" stroke="var(--accent)" stroke-width="7" stroke-dasharray="0 302" stroke-linecap="round" style="transition:stroke-dasharray 0.8s ease,stroke 0.8s ease;"/>
            </svg>
            <div class="score-value">
              <span class="num" id="scoreNum">-</span>
              <span class="denom">/ 100</span>
            </div>
          </div>
          <div class="score-verdict" id="scoreVerdict"></div>
        </div>
        <div class="severity-cards">
          <div class="sev-card" onclick="filterBySev('High')"><div class="bar" style="background:var(--high)"></div><div class="sev-label">High</div><div class="sev-count" id="countHigh" style="color:var(--high)">0</div><div class="sev-unit">findings</div></div>
          <div class="sev-card" onclick="filterBySev('Medium')"><div class="bar" style="background:var(--medium)"></div><div class="sev-label">Medium</div><div class="sev-count" id="countMedium" style="color:var(--medium)">0</div><div class="sev-unit">findings</div></div>
          <div class="sev-card" onclick="filterBySev('Low')"><div class="bar" style="background:var(--low)"></div><div class="sev-label">Low</div><div class="sev-count" id="countLow" style="color:var(--low)">0</div><div class="sev-unit">findings</div></div>
          <div class="sev-card" onclick="filterBySev('Information')"><div class="bar" style="background:var(--info)"></div><div class="sev-label">Info</div><div class="sev-count" id="countInfo" style="color:var(--info)">0</div><div class="sev-unit">findings</div></div>
        </div>
      </div>
      <div class="meta-card"><div class="meta-title">Report Details</div><div class="meta-grid" id="metaGrid"></div></div>
      <div id="highAlertSection"></div>
    </div>

    <div id="tab-findings" style="display:none;">
      <div class="filter-bar" id="filterBar"></div>
      <div id="findingsList"></div>
    </div>

    <div id="tab-roadmap" style="display:none;">
      <div class="roadmap-intro">
        <h3>Proposed Additional Security Checks for Kovoco</h3>
        <p>These checks go beyond what sp_CheckSecurity currently covers. Implementing these would differentiate Kovoco as a security leader in the SQL Server and Microsoft Data Platform space, covering modern authentication, encryption depth, compliance auditing, network hardening, and vulnerability management.</p>
      </div>
      <div id="roadmapContent"></div>
    </div>

    <div class="footer">Kovoco SQL Server Security Assessment &mdash; Powered by sp_CheckSecurity by Straight Path Solutions (MIT License)</div>
  </div>
</div>

<script>
let reportData=null, currentFilter='All', searchTerm='', expandedId=null;

const SEV={High:{color:'var(--high)',w:4},Medium:{color:'var(--medium)',w:3},Low:{color:'var(--low)',w:2},Information:{color:'var(--info)',w:1}};

const ROADMAP=[
  {cat:"Authentication & Access",name:"Azure AD/Entra ID authentication gaps",desc:"Detect instances not leveraging modern authentication when Azure AD is available",sev:"High"},
  {cat:"Authentication & Access",name:"Service accounts with interactive login",desc:"Flag SQL service accounts that also have interactive login privileges on the host OS",sev:"High"},
  {cat:"Authentication & Access",name:"Excessive IMPERSONATE grants",desc:"Identify logins that can impersonate other principals beyond what is necessary",sev:"High"},
  {cat:"Authentication & Access",name:"Password expiration disabled",desc:"SQL logins with CHECK_EXPIRATION = OFF allowing passwords to never rotate",sev:"Medium"},
  {cat:"Authentication & Access",name:"Password policy not enforced",desc:"SQL logins with CHECK_POLICY = OFF bypassing Windows password complexity",sev:"Medium"},
  {cat:"Encryption & Data Protection",name:"Backup encryption not enabled",desc:"Database backups written without encryption exposing data at rest",sev:"High"},
  {cat:"Encryption & Data Protection",name:"Always Encrypted column gaps",desc:"Sensitive columns not using Always Encrypted when available",sev:"Medium"},
  {cat:"Encryption & Data Protection",name:"TLS version below 1.2",desc:"Connections allowed over TLS 1.0/1.1 which have known vulnerabilities",sev:"High"},
  {cat:"Encryption & Data Protection",name:"Self-signed certificates in use",desc:"Instance using auto-generated self-signed certs instead of CA-issued certificates",sev:"Medium"},
  {cat:"Auditing & Compliance",name:"No server-level audit specification",desc:"Instance lacks a formal SQL Server Audit for compliance tracking",sev:"High"},
  {cat:"Auditing & Compliance",name:"Audit file in unsecured location",desc:"SQL Server Audit output files stored in a directory writable by non-admins",sev:"Medium"},
  {cat:"Auditing & Compliance",name:"Schema change tracking missing",desc:"No DDL triggers or audit specs capturing ALTER/DROP/CREATE events",sev:"Medium"},
  {cat:"Auditing & Compliance",name:"Sensitive data access unaudited",desc:"SELECT on PII/PHI tables not captured in audit specifications",sev:"Medium"},
  {cat:"Network & Connectivity",name:"SQL Browser service running",desc:"SQL Server Browser exposes instance names and ports to the network",sev:"Low"},
  {cat:"Network & Connectivity",name:"Default port 1433 in use",desc:"Instance running on default port making it easier to discover and target",sev:"Low"},
  {cat:"Network & Connectivity",name:"Overly permissive firewall rules",desc:"Broad IP ranges in Windows Firewall rules for SQL Server ports",sev:"Medium"},
  {cat:"Vulnerability Management",name:"Vulnerability Assessment not configured",desc:"The built-in VA feature is not running scheduled scans",sev:"Medium"},
  {cat:"Vulnerability Management",name:"Dynamic Data Masking not applied",desc:"Columns with PII-type names lack masking rules for non-privileged users",sev:"Low"},
  {cat:"Vulnerability Management",name:"Row-Level Security opportunities",desc:"Multi-tenant databases without RLS where isolation depends on app logic only",sev:"Medium"},
  {cat:"Operational Security",name:"Agent proxy accounts misconfigured",desc:"Agent job steps running under proxies with excessive permissions",sev:"Medium"},
  {cat:"Operational Security",name:"Database Mail profile public access",desc:"Public database mail profiles could be used for phishing from the SQL instance",sev:"Medium"},
  {cat:"Operational Security",name:"EXECUTE AS LOGIN in procedures",desc:"Stored procedures using EXECUTE AS with elevated context that could be exploited",sev:"Medium"},
  {cat:"Operational Security",name:"Maintenance cleanup missing",desc:"Backup and maintenance files accumulating without cleanup risking disk exhaustion",sev:"Low"},
];

function toggleAuth(){document.getElementById('sqlAuthFields').style.display=document.getElementById('authType').value==='sql'?'block':'none';}
function showConnect(){document.getElementById('connectScreen').style.display='flex';document.getElementById('dashboardScreen').style.display='none';document.getElementById('headerStatus').className='header-status status-disconnected';document.getElementById('headerStatus').textContent='DISCONNECTED';}
function switchTab(id,btn){document.querySelectorAll('[id^="tab-"]').forEach(t=>t.style.display='none');document.getElementById('tab-'+id).style.display='block';document.querySelectorAll('.tab-btn').forEach(b=>b.classList.remove('active'));btn.classList.add('active');}
function filterBySev(s){currentFilter=s;document.getElementById('findingsTabBtn').click();renderFindings();}
function esc(s){if(!s)return'';return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}

async function runAssessment(){
  const btn=document.getElementById('connectBtn'),err=document.getElementById('connectError');
  err.style.display='none';
  const p={
    serverInstance:document.getElementById('serverInstance').value.trim(),
    database:document.getElementById('database').value.trim()||'master',
    authType:document.getElementById('authType').value,
    sqlUser:document.getElementById('sqlUser').value.trim(),
    sqlPass:document.getElementById('sqlPass').value,
    mode:parseInt(document.getElementById('mode').value),
    preferredOwner:document.getElementById('preferredOwner').value.trim(),
    checkLocalAdmin:document.getElementById('checkLocalAdmin').checked,
    override:document.getElementById('overrideCheck').checked,
    installProc:document.getElementById('installProc').checked
  };
  if(!p.serverInstance){err.textContent='Please enter a server instance name.';err.style.display='block';return;}
  if(p.authType==='sql'&&!p.sqlUser){err.textContent='Please enter a username for SQL Authentication.';err.style.display='block';return;}
  btn.disabled=true;btn.innerHTML='<span class="spinner"></span> Running assessment...';
  try{
    const r=await fetch('/api/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(p)});
    const d=await r.json();
    if(!d.success)throw new Error(d.error||'Assessment failed');
    reportData=d;showDashboard();
  }catch(e){err.textContent=e.message;err.style.display='block';}
  finally{btn.disabled=false;btn.innerHTML='Run Security Assessment';}
}

function showDashboard(){
  document.getElementById('connectScreen').style.display='none';
  document.getElementById('dashboardScreen').style.display='block';
  const st=document.getElementById('headerStatus');
  st.className='header-status status-connected';
  st.textContent=reportData.metadata.serverInstance||'CONNECTED';
  renderSummary();renderMeta();renderHighAlert();renderFindings();renderRoadmap();
  document.querySelectorAll('[id^="tab-"]').forEach(t=>t.style.display='none');
  document.getElementById('tab-dashboard').style.display='block';
  document.querySelectorAll('.tab-btn').forEach(b=>b.classList.remove('active'));
  document.querySelector('.tab-btn').classList.add('active');
}

function renderSummary(){
  const s=reportData.summary;
  document.getElementById('countHigh').textContent=s.High||0;
  document.getElementById('countMedium').textContent=s.Medium||0;
  document.getElementById('countLow').textContent=s.Low||0;
  document.getElementById('countInfo').textContent=s.Information||0;
  const ded=(s.High||0)*15+(s.Medium||0)*5+(s.Low||0)*1;
  const score=Math.max(0,Math.min(100,100-ded));
  const circ=2*Math.PI*48;
  const arc=document.getElementById('scoreArc');
  const sc=score>=80?'var(--success)':score>=50?'var(--medium)':'var(--high)';
  arc.setAttribute('stroke',sc);
  arc.setAttribute('stroke-dasharray',(score/100)*circ+' '+circ);
  document.getElementById('scoreNum').textContent=score;
  document.getElementById('scoreNum').style.color=sc;
  document.getElementById('scoreVerdict').textContent=score>=80?'Good posture':score>=50?'Needs attention':'Critical issues found';
  document.getElementById('findingsTabBtn').textContent='Findings ('+reportData.findings.length+')';
}

function renderMeta(){
  const m=reportData.metadata;
  const ml=m.mode==99?'All (99)':m.mode==0?'Issues only (0)':'High only (1)';
  document.getElementById('metaGrid').innerHTML=[
    ['Generated',m.generatedAt],['Instance',m.serverInstance],['Database',m.database],
    ['Mode',ml],['Executed By',m.executedBy],['Machine',m.machineName]
  ].map(function(kv){return '<div><span class="mk">'+kv[0]+':</span> <span class="mv">'+esc(kv[1]||'-')+'</span></div>';}).join('');
}

function renderHighAlert(){
  const h=reportData.findings.filter(function(f){return f.severity==='High';});
  if(!h.length){document.getElementById('highAlertSection').innerHTML='';return;}
  document.getElementById('highAlertSection').innerHTML='<div class="high-alert"><div class="ha-title">High Severity Findings - Immediate Action Required</div>'+
    h.slice(0,6).map(function(f){return '<div class="high-alert-item"><span class="ha-dot">&#9679;</span><div><div class="ha-name">'+esc((f.checkName||'').trim())+'</div><div class="ha-detail">'+esc(f.details)+'</div></div></div>';}).join('')+'</div>';
}

function renderFindings(){
  const ff=reportData.findings;
  const counts={All:ff.length,High:0,Medium:0,Low:0,Information:0};
  ff.forEach(function(f){counts[f.severity]=(counts[f.severity]||0)+1;});
  document.getElementById('filterBar').innerHTML=['All','High','Medium','Low','Information'].map(function(s){
    return '<button class="filter-btn '+(currentFilter===s?'active':'')+'" onclick="currentFilter=\''+s+'\';renderFindings();">'+s+' ('+counts[s]+')</button>';
  }).join('')+'<input class="search-input" placeholder="Search findings..." value="'+esc(searchTerm)+'" oninput="searchTerm=this.value;renderFindings();">';

  var filtered=ff.filter(function(f){
    if(currentFilter!=='All'&&f.severity!==currentFilter)return false;
    if(searchTerm){var t=searchTerm.toLowerCase();return[f.checkName,f.issue,f.details,f.databaseName,f.actionStep].filter(Boolean).some(function(v){return v.toLowerCase().indexOf(t)>=0;});}
    return true;
  });
  filtered.sort(function(a,b){return(SEV[b.severity]?SEV[b.severity].w:0)-(SEV[a.severity]?SEV[a.severity].w:0);});

  if(!filtered.length){document.getElementById('findingsList').innerHTML='<div class="empty-state">No findings match your filters.</div>';return;}

  document.getElementById('findingsList').innerHTML=filtered.map(function(f,i){
    var cfg=SEV[f.severity]||SEV.Information;
    var fid='f-'+i+'-'+f.checkId;
    var isExp=expandedId===fid;
    return '<div class="finding-row '+(isExp?'expanded':'')+'" onclick="expandedId=expandedId===\''+fid+'\'?null:\''+fid+'\';renderFindings();">'+
      '<div class="finding-header">'+
        '<div class="sev-dot" style="background:'+cfg.color+'"></div>'+
        '<span class="finding-sev" style="color:'+cfg.color+'">'+f.severity+'</span>'+
        '<span class="finding-name">'+esc((f.checkName||'').trim())+'</span>'+
        (f.databaseName?'<span class="finding-db">'+esc(f.databaseName)+'</span>':'')+
        '<span class="finding-id">#'+f.checkId+'</span>'+
        '<span class="finding-arrow">&#9660;</span>'+
      '</div>'+
      '<div class="finding-detail">'+
        '<div class="detail-section"><span class="dl">Issue: </span><span class="dv">'+esc(f.issue)+'</span></div>'+
        '<div class="detail-section"><span class="dl">Details: </span><span class="dv">'+esc(f.details)+'</span></div>'+
        (f.actionStep?'<div class="action-box"><div class="al">Recommended Action</div><div class="av">'+esc(f.actionStep)+'</div></div>':'')+
        (f.readMoreUrl?'<a class="read-more" href="'+esc(f.readMoreUrl)+'" target="_blank" rel="noopener" onclick="event.stopPropagation()">Read more &#8594;</a>':'')+
      '</div></div>';
  }).join('');
}

function renderRoadmap(){
  var grouped={};
  ROADMAP.forEach(function(c){(grouped[c.cat]=grouped[c.cat]||[]).push(c);});
  var html='';
  for(var cat in grouped){
    html+='<div class="roadmap-cat">'+esc(cat)+'</div>';
    html+=grouped[cat].map(function(c){
      var cfg=SEV[c.sev]||SEV.Low;
      return '<div class="roadmap-item"><div class="sev-dot" style="background:'+cfg.color+';margin-top:6px;"></div><div style="flex:1"><div class="ri-name">'+esc(c.name)+'</div><div class="ri-desc">'+esc(c.desc)+'</div></div><span class="ri-sev" style="color:'+cfg.color+'">'+c.sev+'</span></div>';
    }).join('');
  }
  document.getElementById('roadmapContent').innerHTML=html;
}

document.addEventListener('DOMContentLoaded',renderRoadmap);
</script>
</body>
</html>
'@

# ============================================================================
# HTTP SERVER + API
# ============================================================================

$url = "http://localhost:$Port/"
$listener = New-Object System.Net.HttpListener
$listener.Prefixes.Add($url)

try {
    $listener.Start()
}
catch {
    Write-Host "  [X] Failed to start listener on port $Port." -ForegroundColor Red
    Write-Host "      Try a different port with -Port, or run as Administrator." -ForegroundColor Yellow
    Write-Host "      Error: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

Write-Host "  [+] Web server running at " -ForegroundColor Green -NoNewline
Write-Host $url -ForegroundColor Cyan
Write-Host "  [*] Press Ctrl+C to stop the server." -ForegroundColor DarkGray
Write-Host ""

# Auto-open browser
if (-not $NoBrowser) {
    Start-Process $url
}

# ---- SQL Assessment Handler ----
function Invoke-SqlAssessment {
    param($Body)

    $params = $Body | ConvertFrom-Json

    $connParams = @{
        ServerInstance = $params.serverInstance
        Database       = $params.database
        QueryTimeout   = 600
        ErrorAction    = "Stop"
    }

    if ($params.authType -eq "sql") {
        $secPass = ConvertTo-SecureString $params.sqlPass -AsPlainText -Force
        $cred = New-Object System.Management.Automation.PSCredential($params.sqlUser, $secPass)
        $connParams["Credential"] = $cred
    }

    # Test connection
    $testResult = Invoke-Sqlcmd @connParams -Query "SELECT @@SERVERNAME AS SN, SYSTEM_USER AS SU, HOST_NAME() AS HN"

    # Install proc if requested
    if ($params.installProc) {
        if ($script:SpCheckSecurityPath -and (Test-Path $script:SpCheckSecurityPath)) {
            $sqlContent = Get-Content $script:SpCheckSecurityPath -Raw
            $batches = $sqlContent -split '\r?\nGO\r?\n'
            foreach ($batch in $batches) {
                $trimmed = $batch.Trim()
                if ($trimmed.Length -gt 0) {
                    Invoke-Sqlcmd @connParams -Query $trimmed
                }
            }
        }
        else {
            throw "Install requested but sp_CheckSecurity.sql not found. Provide -SqlFilePath when launching."
        }
    }

    # Verify proc exists
    $procCheck = Invoke-Sqlcmd @connParams -Query "SELECT OBJECT_ID('dbo.sp_CheckSecurity') AS ProcID"
    if ($null -eq $procCheck.ProcID) {
        throw "sp_CheckSecurity not found in [$($params.database)]. Check 'Install sp_CheckSecurity' or install it manually first."
    }

    # Build exec query
    $execParts = @("EXEC dbo.sp_CheckSecurity @Mode = $($params.mode)")
    if ($params.preferredOwner) {
        $safeOwner = $params.preferredOwner -replace "'", "''"
        $execParts += ", @PreferredDBOwner = N'$safeOwner'"
    }
    if ($params.checkLocalAdmin) { $execParts += ", @CheckLocalAdmin = 1" }
    if ($params.override) { $execParts += ", @Override = 1" }
    $execQuery = $execParts -join ""

    # Run it
    $results = Invoke-Sqlcmd @connParams -Query $execQuery

    # Process results
    $findings = @()
    $summary = @{ High = 0; Medium = 0; Low = 0; Information = 0 }

    foreach ($row in $results) {
        $sevText = switch -Regex ($row.Importance) {
            "1 - High"        { "High" }
            "2.*Medium"       { "Medium" }
            "3 - Low"         { "Low" }
            "0 - Information" { "Information" }
            default           { "Information" }
        }
        if ($summary.ContainsKey($sevText)) { $summary[$sevText]++ }

        $rmUrl = ""
        if ($row.ReadMoreURL) {
            try { $rmUrl = $row.ReadMoreURL.ToString() } catch { $rmUrl = "" }
        }

        $findings += @{
            importance   = [string]$row.Importance
            severity     = $sevText
            checkName    = [string]$row.CheckName
            issue        = [string]$row.Issue
            databaseName = if ($row.DatabaseName) { [string]$row.DatabaseName } else { $null }
            details      = [string]$row.Details
            actionStep   = [string]$row.ActionStep
            readMoreUrl  = $rmUrl
            checkId      = $row.CheckID
        }
    }

    return @{
        success  = $true
        metadata = @{
            toolName       = "Kovoco SQL Server Security Assessment"
            toolVersion    = $KovocoVersion
            generatedAt    = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ss")
            serverInstance = $params.serverInstance
            database       = $params.database
            mode           = $params.mode
            executedBy     = [string]$testResult.SU
            machineName    = [string]$testResult.HN
        }
        summary  = $summary
        findings = $findings
    }
}

# ---- Main request loop ----
try {
    while ($listener.IsListening) {
        $context = $listener.GetContext()
        $request = $context.Request
        $response = $context.Response

        $path = $request.Url.AbsolutePath
        $method = $request.HttpMethod

        try {
            if ($path -eq "/" -and $method -eq "GET") {
                $buffer = [System.Text.Encoding]::UTF8.GetBytes($HTML_DASHBOARD)
                $response.ContentType = "text/html; charset=utf-8"
                $response.ContentLength64 = $buffer.Length
                $response.OutputStream.Write($buffer, 0, $buffer.Length)
                Write-Host "  [>] Served dashboard to $($request.RemoteEndPoint)" -ForegroundColor DarkGray
            }
            elseif ($path -eq "/api/run" -and $method -eq "POST") {
                $reader = New-Object System.IO.StreamReader($request.InputStream)
                $body = $reader.ReadToEnd()
                $reader.Close()

                Write-Host "  [>] Assessment request received..." -ForegroundColor Cyan

                try {
                    $result = Invoke-SqlAssessment -Body $body
                    $json = $result | ConvertTo-Json -Depth 10 -Compress
                    Write-Host "  [+] Assessment complete: $($result.findings.Count) findings" -ForegroundColor Green
                }
                catch {
                    $errObj = @{ success = $false; error = $_.Exception.Message }
                    $json = $errObj | ConvertTo-Json -Compress
                    Write-Host "  [X] Assessment error: $($_.Exception.Message)" -ForegroundColor Red
                }

                $buffer = [System.Text.Encoding]::UTF8.GetBytes($json)
                $response.ContentType = "application/json; charset=utf-8"
                $response.ContentLength64 = $buffer.Length
                $response.OutputStream.Write($buffer, 0, $buffer.Length)
            }
            elseif ($path -eq "/api/health") {
                $buffer = [System.Text.Encoding]::UTF8.GetBytes('{"status":"ok"}')
                $response.ContentType = "application/json"
                $response.ContentLength64 = $buffer.Length
                $response.OutputStream.Write($buffer, 0, $buffer.Length)
            }
            else {
                $response.StatusCode = 404
                $buffer = [System.Text.Encoding]::UTF8.GetBytes("Not Found")
                $response.ContentLength64 = $buffer.Length
                $response.OutputStream.Write($buffer, 0, $buffer.Length)
            }
        }
        catch {
            Write-Host "  [X] Request error: $($_.Exception.Message)" -ForegroundColor Red
            try {
                $response.StatusCode = 500
                $errJson = (@{ error = $_.Exception.Message } | ConvertTo-Json -Compress)
                $buffer = [System.Text.Encoding]::UTF8.GetBytes($errJson)
                $response.ContentType = "application/json"
                $response.ContentLength64 = $buffer.Length
                $response.OutputStream.Write($buffer, 0, $buffer.Length)
            } catch {}
        }
        finally {
            $response.OutputStream.Close()
        }
    }
}
catch [System.OperationCanceledException] {
    # Ctrl+C shutdown - normal
}
finally {
    Write-Host ""
    Write-Host "  [*] Shutting down web server..." -ForegroundColor Yellow
    $listener.Stop()
    $listener.Close()
    Write-Host "  [+] Server stopped. Goodbye." -ForegroundColor Green
}
