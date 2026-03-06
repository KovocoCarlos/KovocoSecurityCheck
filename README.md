# Kovoco SQL Server Security Assessment

A single-file, interactive security assessment tool for SQL Server — built on top of the open-source [sp_CheckSecurity](https://github.com/StraightPathSolutions/sp_CheckSecurity) by [Straight Path Solutions](https://straightpathsql.com/).

Run one PowerShell script. A local web dashboard opens in your browser. Connect to any SQL Server instance, run 70+ security checks, and explore findings interactively — all without installing anything.

![Kovoco Security Dashboard](docs/screenshot-dashboard.png)

---

## How It Works

The PowerShell script does three things:

1. **Starts a local web server** on your machine (default port 18642)
2. **Serves an interactive dashboard** in your browser with a connection form
3. **Bridges your browser to SQL Server** using the PowerShell SqlServer module as the backend

You enter your server details in the browser, click "Run Security Assessment," and the script connects via `Invoke-Sqlcmd`, executes `sp_CheckSecurity`, and streams the results back to the dashboard in real time.

Everything is contained in a single `.ps1` file. The entire HTML/CSS/JS dashboard is embedded. Copy it to any Windows machine and go.

---

## Quick Start

```powershell
# Basic — opens the dashboard in your default browser
.\Invoke-KovocoSecurityCheck.ps1

# With ability to install sp_CheckSecurity on target instances
.\Invoke-KovocoSecurityCheck.ps1 -SqlFilePath ".\sp_CheckSecurity.sql"

# Custom port
.\Invoke-KovocoSecurityCheck.ps1 -Port 9090

# Don't auto-open browser
.\Invoke-KovocoSecurityCheck.ps1 -NoBrowser
```

Then fill in the connection form in your browser and click **Run Security Assessment**.

---

## Features

### Connection & Execution
- **Windows Authentication** or **SQL Server Authentication** from the browser UI
- All `sp_CheckSecurity` parameters exposed: Mode, Preferred DB Owner, Check Local Admin, Override
- Option to **install sp_CheckSecurity remotely** on target instances before running
- Works with SQL Server 2012 through 2022 (and Azure Managed Instances)

### Dashboard
- **Security Score** — weighted composite based on severity of findings
- **Severity breakdown** — High / Medium / Low / Information at a glance
- **Expandable findings** — click any row to see full details, recommended action, and reference links
- **Filter and search** — narrow results by severity level or free-text search
- **Report metadata** — instance name, version, who ran the assessment, and when

### Additional Checks Roadmap
The dashboard includes a **roadmap tab** with 23 proposed checks beyond what `sp_CheckSecurity` currently covers:

| Category | Examples |
|---|---|
| **Authentication & Access** | Entra ID gaps, IMPERSONATE abuse, password policy enforcement |
| **Encryption & Data Protection** | Backup encryption, TLS 1.2 enforcement, self-signed cert detection |
| **Auditing & Compliance** | Server-level audit specs, DDL change tracking, PII access auditing |
| **Network & Connectivity** | SQL Browser exposure, default port detection, firewall rule analysis |
| **Vulnerability Management** | Built-in VA configuration, Dynamic Data Masking, Row-Level Security |
| **Operational Security** | Agent proxy permissions, Database Mail exposure, EXECUTE AS risks |

---

## Requirements

- **PowerShell 5.1+** (PowerShell 7+ recommended)
- **SqlServer module** — the script will attempt to install it automatically if missing
- **sysadmin role** on the target SQL Server instance
- **sp_CheckSecurity** installed on the target (or use the `-SqlFilePath` option to install it)

---

## Parameters

| Parameter | Default | Description |
|---|---|---|
| `-Port` | `18642` | Local port for the web UI |
| `-SqlFilePath` | — | Path to `sp_CheckSecurity.sql` for remote installation |
| `-NoBrowser` | `$false` | Skip auto-opening the browser |

All other assessment options (server, auth, mode, etc.) are configured through the browser UI.

---

## Architecture

```
┌──────────────────────────────────────────────┐
│  Browser (localhost:18642)                    │
│  ┌────────────────────────────────────────┐   │
│  │  Connection Form → Dashboard → Export  │   │
│  └──────────────┬─────────────────────────┘   │
│                 │ POST /api/run                │
│                 ▼                              │
│  ┌────────────────────────────────────────┐   │
│  │  PowerShell HttpListener               │   │
│  │  ├─ GET /        → Serve HTML          │   │
│  │  ├─ POST /api/run → Invoke-Sqlcmd      │   │
│  │  └─ GET /api/health → Status check     │   │
│  └──────────────┬─────────────────────────┘   │
│                 │ TDS                         │
│                 ▼                              │
│  ┌────────────────────────────────────────┐   │
│  │  SQL Server Instance                   │   │
│  │  └─ sp_CheckSecurity (70+ checks)     │   │
│  └────────────────────────────────────────┘   │
└──────────────────────────────────────────────┘
```

---

## What Does sp_CheckSecurity Check?

Over 70 checks across four categories:

**Instance Information** — Server/instance identity, communication protocol, encryption status, service accounts, version support, security updates available

**Logins & Permissions** — sysadmin and securityadmin role members, CONTROL SERVER grants, sa account status, password vulnerabilities (blank, matching login name, common passwords), invalid Windows logins, local Administrators group

**Instance Settings** — CLR, xp_cmdshell, cross-database ownership chaining, ad hoc distributed queries, linked servers, startup procedures/jobs, TDE and backup certificate status, login audit configuration, C2 audit mode, contained database authentication, remote access, force encryption, extended protection, hide instance

**Database Settings** — TRUSTWORTHY databases, db_owner role members, unusual permissions, roles within roles, orphaned users, public role grants, database owner discrepancies

Each finding includes a severity level, explanation, recommended action, and a link to detailed documentation.

---

## Credits

- **[sp_CheckSecurity](https://github.com/StraightPathSolutions/sp_CheckSecurity)** by [Straight Path Solutions](https://straightpathsql.com/) — the core security assessment engine (MIT License)
- Inspired by community tools like [sp_WhoIsActive](https://github.com/amachanic/sp_whoisactive), [Brent Ozar's First Responder Kit](https://github.com/BrentOzarULTD/SQL-Server-First-Responder-Kit), and [Erik Darling's DarlingData](https://github.com/erikdarlingdata/DarlingData)

---

## License

MIT License — see [LICENSE](LICENSE) for details.

sp_CheckSecurity is copyright Straight Path IT Solutions, LLC and is provided under the MIT License. Portions are also derived from [Microsoft Tiger Toolbox](https://github.com/Microsoft/tigertoolbox) and [Brent Ozar's First Responder Kit](https://github.com/BrentOzarULTD/SQL-Server-First-Responder-Kit/), both under MIT.
