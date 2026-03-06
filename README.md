# Kovoco SQL Server Security Assessment

A single-file, standalone security assessment tool for SQL Server. Run one PowerShell script, connect through a browser dashboard, and get results — nothing is installed on the target instance.

![Kovoco Security Dashboard](docs/screenshot-dashboard.png)

---

## How It Works

```
.\Invoke-KovocoSecurityCheck.ps1
```

That's it. A browser opens with a connection form. Enter your SQL Server details, click **Run Security Assessment**, and the engine executes 30+ security checks directly against system DMVs and catalog views. Results appear in an interactive dashboard within seconds.

No stored procedures are deployed. No schema changes are made. No artifacts are left behind on the target instance.

---

## What It Checks

The engine covers two priority categories with checks across the full security surface:

### Permissions & Role Membership
- Enabled sa account
- sysadmin and securityadmin role members
- CONTROL SERVER permission grants
- IMPERSONATE permission grants (privilege escalation risk)
- Blank passwords, login-name-as-password, and common weak passwords
- Password policy (CHECK_POLICY) and expiration (CHECK_EXPIRATION) enforcement
- Invalid/orphaned Windows logins
- db_owner members in system databases
- VIEW ANY DATABASE granted to public role
- Service accounts running with built-in elevated privileges

### Configuration & Surface Area
- xp_cmdshell, CLR, Ole Automation Procedures
- Cross-database ownership chaining (server-level)
- Ad Hoc Distributed Queries
- TRUSTWORTHY databases (with sysadmin-owner escalation detection)
- Linked servers using sa or fixed logins
- Stored procedures and Agent jobs configured to run at startup
- Failed login audit settings and recent failed login detection
- Force Encryption and Hide Instance status
- Remote Access (deprecated), Database Mail XPs
- C2 audit mode, Contained Database Authentication
- Error log retention configuration
- Agent jobs owned by non-sa logins
- Unsupported SQL Server versions

### Instance Information
- Server/instance name, version, edition, build
- Service accounts for SQL Server and SQL Agent
- IP address, TDE encryption status

---

## Quick Start

```powershell
# Launch the dashboard (auto-opens browser)
.\Invoke-KovocoSecurityCheck.ps1

# Custom port
.\Invoke-KovocoSecurityCheck.ps1 -Port 9090

# Don't auto-open the browser
.\Invoke-KovocoSecurityCheck.ps1 -NoBrowser
```

The connection form supports Windows Authentication and SQL Server Authentication, plus a **Trust Server Certificate** option (enabled by default) for instances using self-signed certificates.

---

## Architecture

```
 Browser (localhost:18642)
 ┌──────────────────────────────────────┐
 │  Connection Form → Dashboard         │
 └──────────────┬───────────────────────┘
                │ POST /api/run
                ▼
 PowerShell HttpListener
 ┌──────────────────────────────────────┐
 │  Kovoco Assessment Engine            │
 │  ├─ 30+ checks defined as T-SQL     │
 │  ├─ Each runs via Invoke-Sqlcmd      │
 │  ├─ Results aggregated + scored      │
 │  └─ JSON returned to browser         │
 └──────────────┬───────────────────────┘
                │ TDS (read-only queries)
                ▼
 SQL Server Instance
 ┌──────────────────────────────────────┐
 │  sys.server_principals               │
 │  sys.configurations                  │
 │  sys.databases                       │
 │  sys.dm_server_services              │
 │  (no changes made)                   │
 └──────────────────────────────────────┘
```

Everything runs from a single `.ps1` file — the HTML/CSS/JS dashboard, the check definitions, and the web server are all embedded. Copy it to any Windows machine and go.

---

## Requirements

- **PowerShell 5.1+** (PowerShell 7+ recommended)
- **SqlServer module** (auto-installs if missing)
- **sysadmin role** on the target instance
- **SQL Server 2016+** on the target

---

## Parameters

| Parameter | Default | Description |
|---|---|---|
| `-Port` | `18642` | Local port for the web UI |
| `-NoBrowser` | `$false` | Skip auto-opening the browser |

---

## Dashboard Features

- **Security Score** — weighted composite (High findings penalized heavily)
- **Severity breakdown** — High / Medium / Low / Information cards
- **High severity alert panel** — critical findings surfaced immediately
- **Expandable finding rows** — details + recommended action for each finding
- **Category tags** — see which area each finding belongs to
- **Filter by severity** — click any severity card or use the filter bar
- **Free-text search** — search across all finding fields
- **Assessment metadata** — instance, version, who ran it, duration, checks executed

---

## Inspiration

This tool was inspired by the excellent work of the SQL Server community, particularly [sp_CheckSecurity](https://github.com/StraightPathSolutions/sp_CheckSecurity) by Straight Path Solutions, [sp_Blitz](https://github.com/BrentOzarULTD/SQL-Server-First-Responder-Kit) by Brent Ozar Unlimited, and [sp_WhoIsActive](https://github.com/amachanic/sp_whoisactive) by Adam Machanic. All checks in this tool are original implementations.

---

## License

MIT License — see [LICENSE](LICENSE) for details.

Copyright 2025 Kovoco
