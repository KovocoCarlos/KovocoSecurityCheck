<#
.SYNOPSIS
    Kovoco SQL Server Security Assessment Tool v3.0
    A standalone, interactive security assessment for SQL Server instances.

.DESCRIPTION
    This script launches a local web dashboard and runs its own security checks
    directly against SQL Server DMVs and system tables. No stored procedures need
    to be installed on the target instance.

    Simply run the script, connect through the browser, and get results.

    Inspired by community tools like sp_CheckSecurity, sp_Blitz, and others.
    All checks in this tool are original implementations by Kovoco.

.PARAMETER Port
    The local port for the web UI. Defaults to 18642.

.PARAMETER NoBrowser
    If set, does not auto-open the browser.

.EXAMPLE
    .\Invoke-KovocoSecurityCheck.ps1

.EXAMPLE
    .\Invoke-KovocoSecurityCheck.ps1 -Port 9090

.NOTES
    Requirements:
    - PowerShell 5.1+ (PowerShell 7+ recommended)
    - SqlServer module (auto-installs if missing)
    - sysadmin role on target SQL Server instances
    - SQL Server 2016 or later
#>

[CmdletBinding()]
param(
    [int]$Port = 18642,
    [switch]$NoBrowser
)

$KovocoVersion = "3.0.0"

# ============================================================================
# BANNER
# ============================================================================
Write-Host @"

    +=================================================================+
    |                                                                 |
    |         K O V O C O                                             |
    |         SQL Server Security Assessment Tool v$KovocoVersion               |
    |                                                                 |
    |         Standalone Security Engine                               |
    |         No installation required on target instances             |
    |                                                                 |
    +=================================================================+

"@ -ForegroundColor Cyan

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


# ============================================================================
# KOVOCO SECURITY CHECK DEFINITIONS
# ============================================================================
# Each check is a hashtable with:
#   id       - unique check ID
#   name     - short display name
#   category - grouping category
#   severity - High / Medium / Low / Information
#   query    - T-SQL that returns rows only when the issue IS found
#              Each row must have columns: details, actionStep
#              Optional columns: databaseName
#   minVersion - minimum SQL major version (default 13 = SQL 2016)

$script:SecurityChecks = @(

    # ========================================================================
    # CATEGORY: PERMISSIONS & ROLE MEMBERSHIP
    # ========================================================================

    @{
        id = 1001; name = "Enabled sa account"; category = "Permissions & Roles"; severity = "High"
        query = @"
SELECT
    'The [sa] account (or renamed original: [' + name + ']) is enabled. This is the most targeted account for brute-force attacks.' AS details,
    'Disable the sa login. It can still own databases and jobs while disabled — disabling only prevents interactive connections.' AS actionStep
FROM sys.sql_logins WHERE sid = 0x01 AND is_disabled = 0
"@
    }

    @{
        id = 1002; name = "sysadmin role members"; category = "Permissions & Roles"; severity = "High"
        query = @"
SELECT
    'Login [' + l.name + '] (' + l.type_desc + ') is a member of the sysadmin role with unrestricted access to the entire instance.' AS details,
    'Review whether this login requires sysadmin. Grant only the minimum permissions needed.' AS actionStep
FROM sys.server_principals l
INNER JOIN sys.server_role_members rm ON l.principal_id = rm.member_principal_id
INNER JOIN sys.server_principals r ON rm.role_principal_id = r.principal_id
WHERE r.name = 'sysadmin'
    AND l.name <> SUSER_SNAME(0x01)
    AND l.is_disabled = 0
    AND l.name NOT LIKE 'NT SERVICE\%'
    AND l.name NOT LIKE '##%##'
"@
    }

    @{
        id = 1003; name = "securityadmin role members"; category = "Permissions & Roles"; severity = "High"
        query = @"
SELECT
    'Login [' + l.name + '] is a securityadmin and can create/alter logins, effectively granting themselves or others sysadmin-equivalent access.' AS details,
    'Review whether this login requires securityadmin. This role can escalate privileges by creating new sysadmin logins.' AS actionStep
FROM sys.server_principals l
INNER JOIN sys.server_role_members rm ON l.principal_id = rm.member_principal_id
INNER JOIN sys.server_principals r ON rm.role_principal_id = r.principal_id
WHERE r.name = 'securityadmin'
    AND l.name <> SUSER_SNAME(0x01)
    AND l.is_disabled = 0
"@
    }

    @{
        id = 1004; name = "CONTROL SERVER permissions"; category = "Permissions & Roles"; severity = "High"
        query = @"
SELECT
    'Login [' + pri.name + '] has CONTROL SERVER permission, which is functionally equivalent to sysadmin.' AS details,
    'Review whether this login requires CONTROL SERVER. Consider granting more specific permissions instead.' AS actionStep
FROM sys.server_principals AS pri
WHERE pri.principal_id IN (
    SELECT p.grantee_principal_id
    FROM sys.server_permissions AS p
    WHERE p.[state] IN ('G','W') AND p.class = 100 AND p.[type] = 'CL'
) AND pri.name NOT LIKE '##%##'
"@
    }

    @{
        id = 1005; name = "IMPERSONATE grants"; category = "Permissions & Roles"; severity = "High"
        query = @"
SELECT
    'Login [' + grantee.name + '] can impersonate [' + grantor_prin.name + '], potentially escalating privileges to that identity.' AS details,
    'Review IMPERSONATE grants carefully. If the target principal has elevated permissions, this effectively grants those same permissions.' AS actionStep
FROM sys.server_permissions p
INNER JOIN sys.server_principals grantee ON p.grantee_principal_id = grantee.principal_id
INNER JOIN sys.server_principals grantor_prin ON p.major_id = grantor_prin.principal_id
WHERE p.[type] = 'IM' AND p.[state] IN ('G','W')
"@
    }

    @{
        id = 1006; name = "Password: blank"; category = "Permissions & Roles"; severity = "High"
        query = @"
SELECT
    'SQL login [' + name + '] has a blank password.' AS details,
    'Set a strong password immediately. Blank passwords are the easiest to exploit.' AS actionStep
FROM sys.sql_logins WHERE PWDCOMPARE('', password_hash) = 1
"@
    }

    @{
        id = 1007; name = "Password: same as login name"; category = "Permissions & Roles"; severity = "High"
        query = @"
SELECT
    'SQL login [' + name + '] has a password identical to the login name.' AS details,
    'Change the password. Attackers routinely test login-name-as-password combinations.' AS actionStep
FROM sys.sql_logins WHERE PWDCOMPARE(name, password_hash) = 1
"@
    }

    @{
        id = 1008; name = "Password: common weak password"; category = "Permissions & Roles"; severity = "High"
        query = @"
SELECT
    'SQL login [' + name + '] uses a commonly guessed password.' AS details,
    'Change the password to a strong, unique value. Common passwords appear in every brute-force dictionary.' AS actionStep
FROM sys.sql_logins
WHERE PWDCOMPARE('password', password_hash) = 1
   OR PWDCOMPARE('123456', password_hash) = 1
   OR PWDCOMPARE('Password1', password_hash) = 1
   OR PWDCOMPARE('admin', password_hash) = 1
   OR PWDCOMPARE('sqlserver', password_hash) = 1
"@
    }

    @{
        id = 1009; name = "Password policy not enforced"; category = "Permissions & Roles"; severity = "Medium"
        query = @"
SELECT
    'SQL login [' + name + '] has CHECK_POLICY = OFF, bypassing Windows password complexity requirements.' AS details,
    'Enable CHECK_POLICY unless there is a documented application compatibility reason not to.' AS actionStep
FROM sys.sql_logins
WHERE is_policy_checked = 0
    AND name NOT LIKE '##%##'
    AND is_disabled = 0
"@
    }

    @{
        id = 1010; name = "Password expiration disabled"; category = "Permissions & Roles"; severity = "Medium"
        query = @"
SELECT
    'SQL login [' + name + '] has CHECK_EXPIRATION = OFF. This password will never be forced to rotate.' AS details,
    'Enable CHECK_EXPIRATION to enforce periodic password changes, or implement a rotation policy externally.' AS actionStep
FROM sys.sql_logins
WHERE is_expiration_checked = 0
    AND is_policy_checked = 1
    AND name NOT LIKE '##%##'
    AND is_disabled = 0
    AND sid <> 0x01
"@
    }

    @{
        id = 1011; name = "Invalid Windows logins"; category = "Permissions & Roles"; severity = "Low"
        query = @"
CREATE TABLE #KovocoInvalidLogins (LoginSID VARBINARY(85), LoginName VARCHAR(256));
INSERT INTO #KovocoInvalidLogins EXEC sp_validatelogins;
SELECT
    '[' + LoginName + '] is an invalid/orphaned Windows login that no longer maps to an Active Directory account.' AS details,
    'Verify the account no longer exists, then carefully remove all SQL Server permissions and drop the login.' AS actionStep
FROM #KovocoInvalidLogins;
DROP TABLE #KovocoInvalidLogins;
"@
    }

    @{
        id = 1012; name = "db_owner in system databases"; category = "Permissions & Roles"; severity = "High"
        query = @"
SELECT
    'In [' + DB_NAME(db.database_id) + '], user [' + dp.name + '] has db_owner role — full control over a system database.' AS details,
    'Review whether this user requires db_owner in system databases. This grants extensive control over critical infrastructure.' AS actionStep,
    DB_NAME(db.database_id) AS databaseName
FROM sys.databases db
CROSS APPLY (
    SELECT dp2.name
    FROM sys.database_role_members rm
    INNER JOIN sys.database_principals dp2 ON rm.member_principal_id = dp2.principal_id
    INNER JOIN sys.database_principals rp ON rm.role_principal_id = rp.principal_id
    WHERE rp.name = 'db_owner' AND dp2.name <> 'dbo'
        AND DB_ID() = db.database_id
) dp
WHERE db.name IN ('master','msdb')
"@
    }

    @{
        id = 1013; name = "public role: VIEW ANY DATABASE"; category = "Permissions & Roles"; severity = "Medium"
        query = @"
SELECT
    'The [public] server role has been granted VIEW ANY DATABASE, allowing every login to enumerate all databases.' AS details,
    'Revoke VIEW ANY DATABASE from public unless there is a specific requirement for all users to see database names.' AS actionStep
FROM sys.server_permissions
WHERE grantee_principal_id = 2
    AND [type] = 'VD'
    AND [state] IN ('G','W')
"@
    }

    @{
        id = 1014; name = "Service account elevated privileges"; category = "Permissions & Roles"; severity = "High"
        query = @"
SELECT
    'SQL Server service is running as [' + service_account + '] which is a highly privileged built-in account.' AS details,
    'Use a dedicated, low-privilege domain service account or managed service account (gMSA) instead of LocalSystem or NT AUTHORITY\SYSTEM.' AS actionStep
FROM sys.dm_server_services
WHERE (UPPER(service_account) IN ('LOCALSYSTEM', 'NT AUTHORITY\SYSTEM'))
    AND servicename LIKE 'SQL Server%'
    AND servicename NOT LIKE 'SQL Server Agent%'
"@
    }


    # ========================================================================
    # CATEGORY: CONFIGURATION & SURFACE AREA
    # ========================================================================

    @{
        id = 2001; name = "xp_cmdshell enabled"; category = "Configuration & Surface Area"; severity = "Medium"
        query = @"
SELECT
    'xp_cmdshell is enabled, allowing any sysadmin to execute operating system commands from within SQL Server.' AS details,
    'Disable xp_cmdshell unless it is actively required. Use sp_configure to set it to 0.' AS actionStep
FROM sys.configurations WHERE name = 'xp_cmdshell' AND value_in_use = 1
"@
    }

    @{
        id = 2002; name = "CLR enabled"; category = "Configuration & Surface Area"; severity = "Medium"
        query = @"
SELECT
    'CLR integration is enabled, permitting .NET assemblies to execute in the SQL Server process.' AS details,
    CASE WHEN CAST(SERVERPROPERTY('ProductMajorVersion') AS INT) >= 14
        THEN 'For SQL Server 2017+, consider using clr strict security instead. Disable CLR if no assemblies require it.'
        ELSE 'A CLR assembly with PERMISSION_SET = SAFE may still access external resources. Disable if not required.'
    END AS actionStep
FROM sys.configurations
WHERE name = 'clr enabled' AND value_in_use = 1
    AND NOT EXISTS (SELECT 1 FROM sys.databases WHERE name = 'SSISDB')
"@
    }

    @{
        id = 2003; name = "Cross-database ownership chaining"; category = "Configuration & Surface Area"; severity = "Medium"
        query = @"
SELECT
    'Server-level cross-database ownership chaining is enabled, allowing objects in one database to reference objects in another without permission checks on the target.' AS details,
    'Disable at the server level. Enable it only at the individual database level where explicitly required.' AS actionStep
FROM sys.configurations WHERE name = 'cross db ownership chaining' AND value_in_use = 1
"@
    }

    @{
        id = 2004; name = "Ad Hoc Distributed Queries enabled"; category = "Configuration & Surface Area"; severity = "Medium"
        query = @"
SELECT
    'Ad Hoc Distributed Queries are enabled, permitting OPENROWSET and OPENDATASOURCE calls to arbitrary external data sources.' AS details,
    'Disable unless actively required. If an attacker achieves SQL injection, this lets them read external files and data sources.' AS actionStep
FROM sys.configurations WHERE name = 'Ad Hoc Distributed Queries' AND value_in_use = 1
"@
    }

    @{
        id = 2005; name = "Ole Automation Procedures enabled"; category = "Configuration & Surface Area"; severity = "Medium"
        query = @"
SELECT
    'Ole Automation Procedures are enabled, allowing creation and execution of OLE objects within SQL Server.' AS details,
    'Disable unless actively required. These procedures can be used to interact with the file system and network.' AS actionStep
FROM sys.configurations WHERE name = 'Ole Automation Procedures' AND value_in_use = 1
"@
    }

    @{
        id = 2006; name = "Remote Access enabled"; category = "Configuration & Surface Area"; severity = "Medium"
        query = @"
SELECT
    'The deprecated Remote Access configuration is enabled, allowing remote stored procedure calls between linked servers.' AS details,
    'Disable Remote Access. It is deprecated since SQL 2008 and will be removed in a future version.' AS actionStep
FROM sys.configurations WHERE name = 'remote access' AND value_in_use = 1
"@
    }

    @{
        id = 2007; name = "Database Mail XPs enabled"; category = "Configuration & Surface Area"; severity = "Low"
        query = @"
SELECT
    'Database Mail XPs are enabled. While useful for notifications, a compromised instance could abuse mail for phishing or denial-of-service.' AS details,
    'Verify Database Mail is actively needed. If so, ensure mail profiles are restricted to appropriate principals.' AS actionStep
FROM sys.configurations WHERE name = 'Database Mail XPs' AND value_in_use = 1
"@
    }

    @{
        id = 2008; name = "TRUSTWORTHY database (sysadmin owner)"; category = "Configuration & Surface Area"; severity = "High"
        query = @"
SELECT
    'Database [' + d.name + '] has TRUSTWORTHY enabled and is owned by sysadmin member [' + sp.name + ']. Any db_owner in this database can escalate to sysadmin.' AS details,
    'Set TRUSTWORTHY to OFF, or change the database owner to a login that is not a sysadmin.' AS actionStep,
    d.name AS databaseName
FROM sys.databases d
INNER JOIN sys.server_principals sp ON d.owner_sid = sp.sid
WHERE d.database_id > 4
    AND d.is_trustworthy_on = 1
    AND IS_SRVROLEMEMBER('sysadmin', sp.name) = 1
"@
    }

    @{
        id = 2009; name = "TRUSTWORTHY database"; category = "Configuration & Surface Area"; severity = "Medium"
        query = @"
SELECT
    'Database [' + name + '] has TRUSTWORTHY enabled, allowing code inside to be trusted outside the database context.' AS details,
    'Disable TRUSTWORTHY unless there is a documented requirement. Consider using certificate-based code signing instead.' AS actionStep,
    name AS databaseName
FROM sys.databases
WHERE database_id > 4 AND is_trustworthy_on = 1
    AND IS_SRVROLEMEMBER('sysadmin', SUSER_SNAME(owner_sid)) = 0
"@
    }

    @{
        id = 2010; name = "Failed login audit not enabled"; category = "Configuration & Surface Area"; severity = "High"
        query = @"
DECLARE @AuditLevel INT;
EXEC master..xp_instance_regread
    'HKEY_LOCAL_MACHINE',
    'SOFTWARE\Microsoft\MSSQLServer\MSSQLServer',
    'AuditLevel',
    @AuditLevel OUTPUT;
IF ISNULL(@AuditLevel, 0) < 2
    SELECT
        'Login auditing does not capture failed login attempts. Brute-force attacks and unauthorized access attempts will go undetected.' AS details,
        'Set the Login Auditing level to "Failed logins only" or "Both failed and successful logins" in SQL Server properties.' AS actionStep;
"@
    }

    @{
        id = 2011; name = "Recent failed logins detected"; category = "Configuration & Surface Area"; severity = "Medium"
        query = @"
DECLARE @ErrLog TABLE (LogDate DATETIME, ProcessInfo NVARCHAR(50), [Text] NVARCHAR(MAX));
INSERT @ErrLog EXEC sp_readerrorlog 0, 1, 'Login failed';
DECLARE @cnt INT = (SELECT COUNT(*) FROM @ErrLog);
IF @cnt > 0
    SELECT
        'The current error log contains ' + CAST(@cnt AS VARCHAR(10)) + ' failed login entries, which may indicate brute-force attempts or misconfigured applications.' AS details,
        'Review the SQL Server error log for patterns: repeated logins, unusual source IPs, or off-hours attempts.' AS actionStep;
"@
    }

    @{
        id = 2012; name = "Too few error log files"; category = "Configuration & Surface Area"; severity = "Low"
        query = @"
DECLARE @NumLogs INT;
EXEC master.sys.xp_instance_regread
    N'HKEY_LOCAL_MACHINE',
    N'Software\Microsoft\MSSQLServer\MSSQLServer',
    N'NumErrorLogs',
    @NumLogs OUTPUT;
IF ISNULL(@NumLogs, 6) < 12
    SELECT
        'Only ' + CAST(ISNULL(@NumLogs, 6) AS VARCHAR(10)) + ' error log files are configured. Failed login history and security events may be lost during log recycling.' AS details,
        'Increase to at least 12-52 error log files to retain adequate security history for forensic review.' AS actionStep;
"@
    }

    @{
        id = 2013; name = "Linked server with sa"; category = "Configuration & Surface Area"; severity = "High"
        query = @"
SELECT
    'Linked server [' + s.name + '] connects to [' + s.data_source + '] using the [sa] login, granting any local user full admin rights on the remote server.' AS details,
    'Change the linked server security context to a least-privilege login or use the caller''s security context.' AS actionStep
FROM sys.servers s
INNER JOIN sys.linked_logins l ON s.server_id = l.server_id
WHERE s.is_linked = 1 AND l.local_principal_id = 0
    AND l.uses_self_credential = 0 AND l.remote_name = 'sa'
"@
    }

    @{
        id = 2014; name = "Linked server with fixed login"; category = "Configuration & Surface Area"; severity = "Medium"
        query = @"
SELECT
    'Linked server [' + s.name + '] connects to [' + s.data_source + '] using fixed login [' + l.remote_name + '].' AS details,
    'Verify the remote login has minimum required permissions. Consider using the caller''s security context instead.' AS actionStep
FROM sys.servers s
INNER JOIN sys.linked_logins l ON s.server_id = l.server_id
WHERE s.is_linked = 1 AND l.local_principal_id = 0
    AND l.uses_self_credential = 0 AND l.remote_name IS NOT NULL AND l.remote_name <> 'sa'
"@
    }

    @{
        id = 2015; name = "Startup stored procedures"; category = "Configuration & Surface Area"; severity = "Medium"
        query = @"
SELECT
    'Stored procedure [master].[' + SPECIFIC_SCHEMA + '].[' + SPECIFIC_NAME + '] executes automatically on every SQL Server startup.' AS details,
    'Verify you know exactly what this procedure does. Malicious startup procedures persist across restarts and run with elevated privileges.' AS actionStep
FROM master.INFORMATION_SCHEMA.ROUTINES
WHERE OBJECTPROPERTY(OBJECT_ID(ROUTINE_NAME), 'ExecIsStartup') = 1
"@
    }

    @{
        id = 2016; name = "Startup Agent jobs"; category = "Configuration & Surface Area"; severity = "Medium"
        query = @"
SELECT
    'SQL Agent job [' + j.name + '] runs automatically when SQL Server Agent starts.' AS details,
    'Verify you know what this job does and who created it. Startup jobs run before administrators can intervene.' AS actionStep
FROM msdb.dbo.sysschedules s
INNER JOIN msdb.dbo.sysjobschedules js ON s.schedule_id = js.schedule_id
INNER JOIN msdb.dbo.sysjobs j ON js.job_id = j.job_id
WHERE s.freq_type = 64 AND s.enabled = 1 AND j.enabled = 1
"@
    }

    @{
        id = 2017; name = "Force Encryption disabled"; category = "Configuration & Surface Area"; severity = "Medium"
        query = @"
DECLARE @ForceEnc INT;
EXEC xp_instance_regread
    'HKEY_LOCAL_MACHINE',
    'Software\Microsoft\Microsoft SQL Server\MSSQLServer\SuperSocketNetLib',
    'ForceEncryption',
    @ForceEnc OUTPUT;
IF ISNULL(@ForceEnc, 0) = 0
    SELECT
        'Force Encryption is DISABLED. Client connections may transmit data, including credentials, in cleartext.' AS details,
        'Enable Force Encryption in SQL Server Configuration Manager to require TLS for all connections.' AS actionStep;
"@
    }

    @{
        id = 2018; name = "Hide Instance disabled"; category = "Configuration & Surface Area"; severity = "Low"
        query = @"
DECLARE @HideInst INT;
EXEC xp_instance_regread
    'HKEY_LOCAL_MACHINE',
    'Software\Microsoft\Microsoft SQL Server\MSSQLServer\SuperSocketNetLib',
    'HideInstance',
    @HideInst OUTPUT;
IF ISNULL(@HideInst, 0) = 0
    SELECT
        'Hide Instance is DISABLED. The SQL Server Browser service will advertise this instance to anyone scanning the network.' AS details,
        'Enable Hide Instance in Configuration Manager. Clients will need to specify the port number explicitly.' AS actionStep;
"@
    }

    @{
        id = 2019; name = "C2 audit mode"; category = "Configuration & Surface Area"; severity = "Low"
        query = @"
SELECT
    'C2 audit mode is enabled. While this provides extensive auditing, the log volume can fill the data drive and cause SQL Server to shut down.' AS details,
    'Consider migrating to SQL Server Audit, which provides more granular control without the risk of filling the drive.' AS actionStep
FROM sys.configurations WHERE name = 'c2 audit mode' AND value_in_use = 1
"@
    }

    @{
        id = 2020; name = "Contained Database Authentication"; category = "Configuration & Surface Area"; severity = "Low"
        query = @"
SELECT
    'Contained Database Authentication is enabled. Contained databases have independent authentication that bypasses instance-level login controls.' AS details,
    'Verify this is intentional. Contained database users with ALTER can elevate themselves. Disable if no contained databases exist.' AS actionStep
FROM sys.configurations
WHERE name = 'contained database authentication' AND value_in_use = 1
"@
    }

    @{
        id = 2021; name = "Agent jobs owned by non-sa logins"; category = "Configuration & Surface Area"; severity = "Low"
        query = @"
SELECT
    'Enabled Agent job [' + j.name + '] is owned by [' + SUSER_SNAME(j.owner_sid) + ']. If this login is disabled or removed, the job will stop working.' AS details,
    'Consider changing job ownership to sa to avoid dependency on individual login accounts.' AS actionStep
FROM msdb.dbo.sysjobs j
WHERE j.enabled = 1
    AND SUSER_SNAME(j.owner_sid) <> SUSER_SNAME(0x01)
    AND SUSER_SNAME(j.owner_sid) NOT LIKE '##%'
"@
    }


    # ========================================================================
    # CATEGORY: INSTANCE INFORMATION (Severity = Information)
    # ========================================================================

    @{
        id = 9001; name = "Server name"; category = "Instance Information"; severity = "Information"
        query = @"
SELECT CAST(SERVERPROPERTY('ComputerNamePhysicalNetBIOS') AS NVARCHAR(128)) AS details, NULL AS actionStep
"@
    }

    @{
        id = 9002; name = "Instance name"; category = "Instance Information"; severity = "Information"
        query = @"
SELECT COALESCE(CAST(SERVERPROPERTY('InstanceName') AS NVARCHAR(128)), '(default instance)') AS details, NULL AS actionStep
"@
    }

    @{
        id = 9003; name = "SQL Server version"; category = "Instance Information"; severity = "Information"
        query = @"
SELECT CAST(SERVERPROPERTY('ProductVersion') AS NVARCHAR(128)) + ' - ' + CAST(SERVERPROPERTY('Edition') AS NVARCHAR(128)) AS details, NULL AS actionStep
"@
    }

    @{
        id = 9004; name = "SQL Server service account"; category = "Instance Information"; severity = "Information"
        query = @"
SELECT service_account AS details, NULL AS actionStep
FROM sys.dm_server_services WHERE servicename LIKE 'SQL Server (%'
"@
    }

    @{
        id = 9005; name = "SQL Agent service account"; category = "Instance Information"; severity = "Information"
        query = @"
SELECT service_account AS details, NULL AS actionStep
FROM sys.dm_server_services WHERE servicename LIKE 'SQL Server Agent%'
"@
    }

    @{
        id = 9006; name = "IP address"; category = "Instance Information"; severity = "Information"
        query = @"
SELECT COALESCE(CONVERT(VARCHAR(50), CONNECTIONPROPERTY('local_net_address')), 'UNKNOWN') AS details,
    'Verify this is not externally-facing.' AS actionStep
"@
    }

    @{
        id = 9007; name = "Encrypted databases"; category = "Instance Information"; severity = "Information"
        query = @"
SELECT
    CAST(COUNT(database_id) AS VARCHAR(10)) + ' database(s) encrypted with ' + key_algorithm + ' ' + CAST(key_length AS VARCHAR(5)) AS details,
    'Ensure encryption keys are backed up to a secure, offsite location.' AS actionStep
FROM sys.dm_database_encryption_keys
WHERE database_id > 4
GROUP BY key_algorithm, key_length
"@
    }

    @{
        id = 9008; name = "Unencrypted databases"; category = "Instance Information"; severity = "Information"
        query = @"
SELECT
    CAST(COUNT(database_id) AS VARCHAR(10)) + ' user database(s) are not encrypted with TDE.' AS details,
    'Evaluate whether TDE or Always Encrypted is appropriate for databases containing sensitive data.' AS actionStep
FROM sys.databases d
WHERE database_id > 4
    AND NOT EXISTS (SELECT 1 FROM sys.dm_database_encryption_keys dek WHERE d.database_id = dek.database_id)
HAVING COUNT(database_id) > 0
"@
    }

    @{
        id = 9009; name = "Unsupported SQL Server version"; category = "Instance Information"; severity = "High"
        query = @"
IF CAST(SERVERPROPERTY('ProductMajorVersion') AS INT) < 13
    AND SERVERPROPERTY('EngineEdition') <> 8
    SELECT
        'SQL Server ' + CAST(SERVERPROPERTY('ProductMajorVersion') AS VARCHAR(5)) + ' is no longer supported by Microsoft. No future security updates will be released.' AS details,
        'Upgrade to SQL Server 2016 or later as soon as possible.' AS actionStep;
"@
    }
)


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
  --medium: #e8a020;
  --low: #4499dd;
  --info: #607088;
  --success: #38b060;
  --font-body: 'DM Sans', -apple-system, sans-serif;
  --font-mono: 'JetBrains Mono', monospace;
}
* { margin:0; padding:0; box-sizing:border-box; }
body { font-family:var(--font-body); background:var(--bg-primary); color:var(--text-primary); min-height:100vh; overflow-x:hidden; }
body::before { content:''; position:fixed; inset:0; background-image:linear-gradient(rgba(56,78,119,0.04) 1px,transparent 1px),linear-gradient(90deg,rgba(56,78,119,0.04) 1px,transparent 1px); background-size:48px 48px; pointer-events:none; z-index:0; }

.header { position:sticky;top:0;z-index:100;background:rgba(6,9,15,0.92);backdrop-filter:blur(16px);border-bottom:1px solid var(--border);padding:0 28px;height:56px;display:flex;align-items:center;justify-content:space-between; }
.logo-group { display:flex;align-items:center;gap:12px; }
.logo-mark { width:32px;height:32px;background:linear-gradient(135deg,#5b8af5 0%,#3a5fc0 100%);border-radius:7px;display:flex;align-items:center;justify-content:center;font-weight:800;font-size:15px;color:white;box-shadow:0 2px 12px rgba(91,138,245,0.25); }
.logo-text { font-weight:700;font-size:15px;letter-spacing:0.08em;color:#fff; }
.logo-sub { font-size:9.5px;color:var(--accent);letter-spacing:0.18em;text-transform:uppercase;margin-top:-1px; }
.header-status { font-family:var(--font-mono);font-size:11px;padding:3px 10px;border-radius:4px; }
.status-disconnected { background:rgba(240,72,72,0.1);color:var(--high);border:1px solid rgba(240,72,72,0.2); }
.status-connected { background:rgba(56,176,96,0.1);color:var(--success);border:1px solid rgba(56,176,96,0.2); }

.container { position:relative;z-index:1;max-width:1160px;margin:0 auto;padding:24px; }
.connect-screen { display:flex;align-items:center;justify-content:center;min-height:calc(100vh - 56px);padding-bottom:80px; }
.connect-box { background:var(--bg-card);border:1px solid var(--border);border-radius:12px;padding:36px 40px;width:100%;max-width:460px;box-shadow:0 8px 40px rgba(0,0,0,0.3); }
.connect-box h2 { font-size:18px;font-weight:700;color:#fff;margin-bottom:4px; }
.connect-box .subtitle { font-size:13px;color:var(--text-secondary);margin-bottom:24px; }
.form-group { margin-bottom:16px; }
.form-group label { display:block;font-size:11px;font-weight:600;color:var(--text-secondary);text-transform:uppercase;letter-spacing:0.08em;margin-bottom:6px; }
.form-group input,.form-group select { width:100%;padding:9px 12px;background:rgba(6,9,15,0.6);border:1px solid var(--border);border-radius:6px;color:var(--text-primary);font-family:var(--font-mono);font-size:13px;outline:none;transition:border-color 0.2s; }
.form-group input:focus,.form-group select:focus { border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-glow); }
.form-group input::placeholder { color:var(--text-muted); }
.form-group select option { background:#0a0e1a;color:var(--text-primary); }
.form-row { display:grid;grid-template-columns:1fr 1fr;gap:12px; }
.checkbox-row { display:flex;align-items:center;gap:8px;margin-bottom:14px;cursor:pointer; }
.checkbox-row input[type="checkbox"] { width:16px;height:16px;accent-color:var(--accent);cursor:pointer; }
.checkbox-row span { font-size:13px;color:var(--text-secondary); }
.btn { display:inline-flex;align-items:center;justify-content:center;gap:8px;padding:10px 20px;border-radius:7px;font-size:13px;font-weight:600;border:none;cursor:pointer;transition:all 0.2s;font-family:var(--font-body); }
.btn-primary { background:linear-gradient(135deg,#5b8af5,#3a6ae0);color:white;width:100%;box-shadow:0 2px 12px rgba(91,138,245,0.25); }
.btn-primary:hover { box-shadow:0 4px 20px rgba(91,138,245,0.4);transform:translateY(-1px); }
.btn-primary:disabled { opacity:0.5;cursor:not-allowed;transform:none;box-shadow:none; }
.btn-outline { background:transparent;border:1px solid var(--border);color:var(--text-secondary); }
.btn-outline:hover { border-color:var(--accent);color:var(--accent); }
.error-msg { background:rgba(240,72,72,0.08);border:1px solid rgba(240,72,72,0.2);border-radius:6px;padding:10px 14px;font-size:12px;color:var(--high);margin-bottom:16px;display:none; }
.install-note { font-size:11px;color:var(--text-muted);margin-top:12px;text-align:center;line-height:1.5; }

.tab-bar { display:flex;gap:0;border-bottom:1px solid var(--border);margin-bottom:24px; }
.tab-btn { padding:10px 20px;font-size:12.5px;font-weight:500;color:var(--text-muted);background:none;border:none;border-bottom:2px solid transparent;cursor:pointer;transition:all 0.15s;font-family:var(--font-body); }
.tab-btn:hover { color:var(--text-secondary); }
.tab-btn.active { color:var(--accent);border-bottom-color:var(--accent);font-weight:700; }

.summary-grid { display:grid;grid-template-columns:200px 1fr;gap:16px;margin-bottom:24px; }
.score-card { background:var(--bg-card);border:1px solid var(--border);border-radius:10px;padding:24px;display:flex;flex-direction:column;align-items:center;justify-content:center; }
.score-label { font-size:10px;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.12em;margin-bottom:10px; }
.score-ring { position:relative;width:110px;height:110px; }
.score-ring svg { transform:rotate(-90deg); }
.score-value { position:absolute;inset:0;display:flex;align-items:center;justify-content:center;flex-direction:column; }
.score-value .num { font-size:30px;font-weight:800; }
.score-value .denom { font-size:9px;color:var(--text-muted); }
.score-verdict { font-size:10px;color:var(--text-secondary);margin-top:6px; }
.severity-cards { display:grid;grid-template-columns:repeat(4,1fr);gap:10px; }
.sev-card { background:var(--bg-card);border:1px solid var(--border);border-radius:10px;padding:16px 18px;cursor:pointer;transition:all 0.15s;position:relative;overflow:hidden; }
.sev-card:hover { border-color:var(--border-active);background:var(--bg-card-hover); }
.sev-card .bar { position:absolute;top:0;left:0;right:0;height:2px; }
.sev-card .sev-label { font-size:10px;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.08em;margin-bottom:6px; }
.sev-card .sev-count { font-size:32px;font-weight:800;line-height:1; }
.sev-card .sev-unit { font-size:10px;color:var(--text-muted);margin-top:3px; }

.meta-card { background:var(--bg-card);border:1px solid var(--border);border-radius:10px;padding:18px 20px;margin-bottom:20px; }
.meta-card .meta-title { font-size:11px;font-weight:700;color:var(--accent);text-transform:uppercase;letter-spacing:0.1em;margin-bottom:10px; }
.meta-grid { display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:6px;font-size:12.5px; }
.meta-grid .mk { color:var(--text-muted);min-width:85px;display:inline-block; }
.meta-grid .mv { color:var(--text-secondary);font-family:var(--font-mono);font-size:11.5px; }

.filter-bar { display:flex;gap:6px;margin-bottom:14px;flex-wrap:wrap;align-items:center; }
.filter-btn { padding:5px 12px;border-radius:5px;font-size:11.5px;font-weight:600;border:1px solid var(--border);background:transparent;color:var(--text-muted);cursor:pointer;transition:all 0.12s;font-family:var(--font-body); }
.filter-btn:hover { border-color:var(--border-active);color:var(--text-secondary); }
.filter-btn.active { border-color:var(--accent);background:var(--accent-glow);color:var(--accent); }
.search-input { margin-left:auto;padding:5px 12px;border-radius:5px;border:1px solid var(--border);background:rgba(6,9,15,0.5);color:var(--text-primary);font-size:12px;width:200px;outline:none;font-family:var(--font-mono); }
.search-input:focus { border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-glow); }

.finding-row { background:var(--bg-card);border:1px solid var(--border);border-radius:8px;margin-bottom:4px;cursor:pointer;transition:all 0.12s;overflow:hidden; }
.finding-row:hover { border-color:var(--border-active);background:var(--bg-card-hover); }
.finding-header { padding:10px 14px;display:flex;align-items:center;gap:10px; }
.sev-dot { width:6px;height:6px;border-radius:50%;flex-shrink:0; }
.finding-sev { font-size:9.5px;font-weight:700;text-transform:uppercase;min-width:72px; }
.finding-name { font-weight:600;font-size:12.5px;color:#eef2f8;flex:1; }
.finding-cat { font-size:10px;color:var(--text-muted);background:rgba(56,78,119,0.12);padding:1px 7px;border-radius:3px; }
.finding-db { font-size:10.5px;color:var(--accent);background:var(--accent-glow);padding:1px 7px;border-radius:3px;font-family:var(--font-mono); }
.finding-id { font-size:10px;color:var(--text-muted);font-family:var(--font-mono); }
.finding-arrow { color:var(--text-muted);font-size:12px;transition:transform 0.2s; }
.finding-row.expanded .finding-arrow { transform:rotate(180deg); }
.finding-detail { display:none;padding:0 14px 14px 28px;border-top:1px solid rgba(56,78,119,0.12); }
.finding-row.expanded .finding-detail { display:block; }
.detail-section { margin-top:10px;font-size:12.5px;line-height:1.6; }
.detail-section .dl { color:var(--text-muted); }
.detail-section .dv { color:var(--text-secondary); }
.action-box { background:rgba(56,176,96,0.06);border:1px solid rgba(56,176,96,0.15);border-radius:6px;padding:9px 12px;margin-top:10px; }
.action-box .al { font-size:10px;font-weight:700;color:var(--success);text-transform:uppercase;letter-spacing:0.06em; }
.action-box .av { font-size:12px;color:#6cd992;margin-top:2px; }
.empty-state { text-align:center;padding:48px;color:var(--text-muted);font-size:13px; }

.high-alert { background:var(--bg-card);border:1px solid rgba(240,72,72,0.2);border-radius:10px;padding:18px 20px;margin-bottom:20px; }
.high-alert .ha-title { font-size:11px;font-weight:700;color:var(--high);text-transform:uppercase;letter-spacing:0.1em;margin-bottom:10px; }
.high-alert-item { padding:8px 0;border-bottom:1px solid rgba(240,72,72,0.06);display:flex;gap:10px;align-items:flex-start; }
.high-alert-item:last-child { border-bottom:none; }
.ha-dot { color:var(--high);font-size:8px;margin-top:5px; }
.ha-name { font-weight:600;color:#eef2f8;font-size:12.5px; }
.ha-detail { color:var(--text-secondary);font-size:11.5px;margin-top:1px; }

.footer { text-align:center;padding:24px;font-size:10.5px;color:var(--text-muted);border-top:1px solid var(--border);margin-top:32px; }
.spinner { width:18px;height:18px;border:2px solid rgba(255,255,255,0.2);border-top-color:white;border-radius:50%;animation:spin 0.6s linear infinite;display:inline-block; }
@keyframes spin { to { transform:rotate(360deg); } }
@keyframes fadeIn { from { opacity:0;transform:translateY(8px); } to { opacity:1;transform:translateY(0); } }
.fade-in { animation:fadeIn 0.3s ease; }
@media (max-width:768px) { .summary-grid{grid-template-columns:1fr;} .severity-cards{grid-template-columns:repeat(2,1fr);} .form-row{grid-template-columns:1fr;} }
</style>
</head>
<body>

<div class="header">
  <div class="logo-group">
    <div class="logo-mark">K</div>
    <div><div class="logo-text">KOVOCO</div><div class="logo-sub">Security Assessment</div></div>
  </div>
  <div id="headerStatus" class="header-status status-disconnected">DISCONNECTED</div>
</div>

<div id="connectScreen" class="connect-screen">
  <div class="connect-box fade-in">
    <h2>Connect to SQL Server</h2>
    <div class="subtitle">No installation needed on the target instance. Checks run as read-only queries.</div>
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
        <div class="form-group"><label>Username</label><input type="text" id="sqlUser" placeholder="sa" /></div>
        <div class="form-group"><label>Password</label><input type="password" id="sqlPass" placeholder="password" /></div>
      </div>
    </div>
    <div class="checkbox-row" onclick="this.querySelector('input').click()">
      <input type="checkbox" id="trustCert" onclick="event.stopPropagation()" checked />
      <span>Trust server certificate (required for self-signed certs)</span>
    </div>
    <button class="btn btn-primary" id="connectBtn" onclick="runAssessment()">
      Run Security Assessment
    </button>
    <div class="install-note">
      Requires sysadmin role &middot; Nothing is installed on the target instance<br>
      Kovoco Security Assessment Engine v3.0
    </div>
  </div>
</div>

<div id="dashboardScreen" style="display:none;">
  <div class="container fade-in">
    <div class="tab-bar">
      <button class="tab-btn active" onclick="switchTab('dashboard',this)">Dashboard</button>
      <button class="tab-btn" onclick="switchTab('findings',this)" id="findingsTabBtn">Findings</button>
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
            <div class="score-value"><span class="num" id="scoreNum">-</span><span class="denom">/ 100</span></div>
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
      <div class="meta-card"><div class="meta-title">Assessment Details</div><div class="meta-grid" id="metaGrid"></div></div>
      <div id="highAlertSection"></div>
    </div>

    <div id="tab-findings" style="display:none;">
      <div class="filter-bar" id="filterBar"></div>
      <div id="findingsList"></div>
    </div>

    <div class="footer">Kovoco SQL Server Security Assessment Engine v3.0 &mdash; All checks are original implementations by Kovoco</div>
  </div>
</div>

<script>
var reportData=null,currentFilter='All',searchTerm='',expandedId=null;
var SEV={High:{color:'var(--high)',w:4},Medium:{color:'var(--medium)',w:3},Low:{color:'var(--low)',w:2},Information:{color:'var(--info)',w:1}};

function toggleAuth(){document.getElementById('sqlAuthFields').style.display=document.getElementById('authType').value==='sql'?'block':'none';}
function showConnect(){document.getElementById('connectScreen').style.display='flex';document.getElementById('dashboardScreen').style.display='none';document.getElementById('headerStatus').className='header-status status-disconnected';document.getElementById('headerStatus').textContent='DISCONNECTED';}
function switchTab(id,btn){document.querySelectorAll('[id^="tab-"]').forEach(function(t){t.style.display='none';});document.getElementById('tab-'+id).style.display='block';document.querySelectorAll('.tab-btn').forEach(function(b){b.classList.remove('active');});btn.classList.add('active');}
function filterBySev(s){currentFilter=s;document.getElementById('findingsTabBtn').click();renderFindings();}
function esc(s){if(!s)return'';return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}

function runAssessment(){
  var btn=document.getElementById('connectBtn'),err=document.getElementById('connectError');
  err.style.display='none';
  var p={
    serverInstance:document.getElementById('serverInstance').value.trim(),
    authType:document.getElementById('authType').value,
    sqlUser:document.getElementById('sqlUser').value.trim(),
    sqlPass:document.getElementById('sqlPass').value,
    trustCert:document.getElementById('trustCert').checked
  };
  if(!p.serverInstance){err.textContent='Please enter a server instance name.';err.style.display='block';return;}
  if(p.authType==='sql'&&!p.sqlUser){err.textContent='Please enter a username for SQL Authentication.';err.style.display='block';return;}
  btn.disabled=true;btn.innerHTML='<span class="spinner"></span> Running 30+ security checks...';
  fetch('/api/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(p)})
  .then(function(r){return r.json();})
  .then(function(d){
    if(!d.success)throw new Error(d.error||'Assessment failed');
    reportData=d;showDashboard();
  })
  .catch(function(e){err.textContent=e.message;err.style.display='block';})
  .finally(function(){btn.disabled=false;btn.innerHTML='Run Security Assessment';});
}

function showDashboard(){
  document.getElementById('connectScreen').style.display='none';
  document.getElementById('dashboardScreen').style.display='block';
  var st=document.getElementById('headerStatus');
  st.className='header-status status-connected';st.textContent=reportData.metadata.serverInstance||'CONNECTED';
  currentFilter='All';searchTerm='';expandedId=null;
  renderSummary();renderMeta();renderHighAlert();renderFindings();
  document.querySelectorAll('[id^="tab-"]').forEach(function(t){t.style.display='none';});
  document.getElementById('tab-dashboard').style.display='block';
  document.querySelectorAll('.tab-btn').forEach(function(b){b.classList.remove('active');});
  document.querySelector('.tab-btn').classList.add('active');
}

function renderSummary(){
  var s=reportData.summary;
  document.getElementById('countHigh').textContent=s.High||0;
  document.getElementById('countMedium').textContent=s.Medium||0;
  document.getElementById('countLow').textContent=s.Low||0;
  document.getElementById('countInfo').textContent=s.Information||0;
  var ded=(s.High||0)*15+(s.Medium||0)*5+(s.Low||0)*1;
  var score=Math.max(0,Math.min(100,100-ded));
  var circ=2*Math.PI*48;
  var arc=document.getElementById('scoreArc');
  var sc=score>=80?'var(--success)':score>=50?'var(--medium)':'var(--high)';
  arc.setAttribute('stroke',sc);arc.setAttribute('stroke-dasharray',(score/100)*circ+' '+circ);
  document.getElementById('scoreNum').textContent=score;document.getElementById('scoreNum').style.color=sc;
  document.getElementById('scoreVerdict').textContent=score>=80?'Good posture':score>=50?'Needs attention':'Critical issues found';
  document.getElementById('findingsTabBtn').textContent='Findings ('+reportData.findings.length+')';
}

function renderMeta(){
  var m=reportData.metadata;
  document.getElementById('metaGrid').innerHTML=[
    ['Generated',m.generatedAt],['Instance',m.serverInstance],['Version',m.sqlVersion],
    ['Checks Run',m.checksRun],['Executed By',m.executedBy],['Duration',m.duration]
  ].map(function(kv){return '<div><span class="mk">'+kv[0]+':</span> <span class="mv">'+esc(kv[1]||'-')+'</span></div>';}).join('');
}

function renderHighAlert(){
  var h=reportData.findings.filter(function(f){return f.severity==='High';});
  if(!h.length){document.getElementById('highAlertSection').innerHTML='';return;}
  document.getElementById('highAlertSection').innerHTML='<div class="high-alert"><div class="ha-title">High Severity Findings - Immediate Action Required</div>'+
    h.slice(0,8).map(function(f){return '<div class="high-alert-item"><span class="ha-dot">&#9679;</span><div><div class="ha-name">'+esc(f.name)+'</div><div class="ha-detail">'+esc(f.details)+'</div></div></div>';}).join('')+'</div>';
}

function renderFindings(){
  var ff=reportData.findings;
  var counts={All:ff.length,High:0,Medium:0,Low:0,Information:0};
  ff.forEach(function(f){counts[f.severity]=(counts[f.severity]||0)+1;});
  document.getElementById('filterBar').innerHTML=['All','High','Medium','Low','Information'].map(function(s){
    return '<button class="filter-btn '+(currentFilter===s?'active':'')+'" onclick="currentFilter=\''+s+'\';renderFindings();">'+s+' ('+counts[s]+')</button>';
  }).join('')+'<input class="search-input" placeholder="Search findings..." value="'+esc(searchTerm)+'" oninput="searchTerm=this.value;renderFindings();">';

  var filtered=ff.filter(function(f){
    if(currentFilter!=='All'&&f.severity!==currentFilter)return false;
    if(searchTerm){var t=searchTerm.toLowerCase();return[f.name,f.details,f.databaseName,f.actionStep,f.category].filter(Boolean).some(function(v){return v.toLowerCase().indexOf(t)>=0;});}
    return true;
  });
  filtered.sort(function(a,b){return(SEV[b.severity]?SEV[b.severity].w:0)-(SEV[a.severity]?SEV[a.severity].w:0);});
  if(!filtered.length){document.getElementById('findingsList').innerHTML='<div class="empty-state">No findings match your filters.</div>';return;}
  document.getElementById('findingsList').innerHTML=filtered.map(function(f,i){
    var cfg=SEV[f.severity]||SEV.Information;var fid='f'+i+'-'+f.checkId;var isExp=expandedId===fid;
    return '<div class="finding-row '+(isExp?'expanded':'')+'" onclick="expandedId=expandedId===\''+fid+'\'?null:\''+fid+'\';renderFindings();">'+
      '<div class="finding-header"><div class="sev-dot" style="background:'+cfg.color+'"></div><span class="finding-sev" style="color:'+cfg.color+'">'+f.severity+'</span><span class="finding-name">'+esc(f.name)+'</span>'+
      '<span class="finding-cat">'+esc(f.category)+'</span>'+
      (f.databaseName?'<span class="finding-db">'+esc(f.databaseName)+'</span>':'')+
      '<span class="finding-id">#'+f.checkId+'</span><span class="finding-arrow">&#9660;</span></div>'+
      '<div class="finding-detail"><div class="detail-section"><span class="dv">'+esc(f.details)+'</span></div>'+
      (f.actionStep?'<div class="action-box"><div class="al">Recommended Action</div><div class="av">'+esc(f.actionStep)+'</div></div>':'')+
      '</div></div>';
  }).join('');
}
</script>
</body>
</html>
'@


# ============================================================================
# HTTP SERVER + ASSESSMENT ENGINE
# ============================================================================

$url = "http://localhost:$Port/"
$listener = New-Object System.Net.HttpListener
$listener.Prefixes.Add($url)

try { $listener.Start() }
catch {
    Write-Host "  [X] Failed to start on port $Port. Try -Port or run as Admin." -ForegroundColor Red
    Write-Host "      $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

Write-Host "  [+] Web server running at " -ForegroundColor Green -NoNewline
Write-Host $url -ForegroundColor Cyan
Write-Host "  [*] Press Ctrl+C to stop." -ForegroundColor DarkGray
Write-Host ""

if (-not $NoBrowser) { Start-Process $url }

# ---- Assessment Engine ----
function Invoke-KovocoAssessment {
    param($Body)
    $startTime = Get-Date

    $params = $Body | ConvertFrom-Json

    $connParams = @{
        ServerInstance = $params.serverInstance
        Database       = "master"
        QueryTimeout   = 300
        ErrorAction    = "Stop"
    }
    if ($params.trustCert) { $connParams["TrustServerCertificate"] = $true }
    if ($params.authType -eq "sql") {
        $secPass = ConvertTo-SecureString $params.sqlPass -AsPlainText -Force
        $connParams["Credential"] = New-Object System.Management.Automation.PSCredential($params.sqlUser, $secPass)
    }

    # Test connection and get instance info
    $instanceInfo = Invoke-Sqlcmd @connParams -Query @"
SELECT
    @@SERVERNAME AS ServerName,
    SYSTEM_USER AS ExecutedBy,
    CAST(SERVERPROPERTY('ProductVersion') AS NVARCHAR(128)) AS SqlVersion,
    CAST(SERVERPROPERTY('Edition') AS NVARCHAR(128)) AS Edition,
    CAST(SERVERPROPERTY('ProductMajorVersion') AS INT) AS MajorVersion
"@

    Write-Host "  [+] Connected to $($instanceInfo.ServerName) ($($instanceInfo.SqlVersion))" -ForegroundColor Green

    # Verify sysadmin
    $isSysAdmin = Invoke-Sqlcmd @connParams -Query "SELECT IS_SRVROLEMEMBER('sysadmin') AS IsSA"
    if ($isSysAdmin.IsSA -ne 1) {
        throw "Current login is not a member of the sysadmin role. Kovoco requires sysadmin for a complete assessment."
    }

    # Run all checks
    $findings = @()
    $summary = @{ High = 0; Medium = 0; Low = 0; Information = 0 }
    $checksRun = 0
    $checksFailed = 0

    foreach ($check in $script:SecurityChecks) {
        # Skip checks that require a newer version
        $minVer = if ($check.minVersion) { $check.minVersion } else { 13 }
        if ($instanceInfo.MajorVersion -lt $minVer) { continue }

        $checksRun++
        try {
            $results = Invoke-Sqlcmd @connParams -Query $check.query -ErrorAction Stop

            foreach ($row in $results) {
                if ($null -eq $row.details -or [string]::IsNullOrWhiteSpace($row.details)) { continue }

                $sev = $check.severity
                if ($summary.ContainsKey($sev)) { $summary[$sev]++ }

                $findings += @{
                    checkId      = $check.id
                    name         = $check.name
                    category     = $check.category
                    severity     = $sev
                    details      = [string]$row.details
                    actionStep   = if ($row.actionStep) { [string]$row.actionStep } else { $null }
                    databaseName = if ($row.PSObject.Properties['databaseName'] -and $row.databaseName) { [string]$row.databaseName } else { $null }
                }
            }
        }
        catch {
            $checksFailed++
            Write-Host "  [!] Check $($check.id) ($($check.name)) failed: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }

    $elapsed = (Get-Date) - $startTime

    return @{
        success  = $true
        metadata = @{
            toolName       = "Kovoco SQL Server Security Assessment"
            toolVersion    = $KovocoVersion
            generatedAt    = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ss")
            serverInstance = $params.serverInstance
            sqlVersion     = "$($instanceInfo.SqlVersion) ($($instanceInfo.Edition))"
            executedBy     = [string]$instanceInfo.ExecutedBy
            checksRun      = "$checksRun checks executed" + $(if ($checksFailed -gt 0) { " ($checksFailed skipped)" } else { "" })
            duration       = "$([math]::Round($elapsed.TotalSeconds, 1)) seconds"
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

        try {
            if ($request.Url.AbsolutePath -eq "/" -and $request.HttpMethod -eq "GET") {
                $buffer = [System.Text.Encoding]::UTF8.GetBytes($HTML_DASHBOARD)
                $response.ContentType = "text/html; charset=utf-8"
                $response.ContentLength64 = $buffer.Length
                $response.OutputStream.Write($buffer, 0, $buffer.Length)
                Write-Host "  [>] Dashboard served to $($request.RemoteEndPoint)" -ForegroundColor DarkGray
            }
            elseif ($request.Url.AbsolutePath -eq "/api/run" -and $request.HttpMethod -eq "POST") {
                $reader = New-Object System.IO.StreamReader($request.InputStream)
                $body = $reader.ReadToEnd()
                $reader.Close()

                Write-Host "  [>] Assessment request received..." -ForegroundColor Cyan
                try {
                    $result = Invoke-KovocoAssessment -Body $body
                    $json = $result | ConvertTo-Json -Depth 10 -Compress
                    Write-Host "  [+] Complete: $($result.findings.Count) findings from $($result.metadata.checksRun)" -ForegroundColor Green
                }
                catch {
                    $json = (@{ success = $false; error = $_.Exception.Message } | ConvertTo-Json -Compress)
                    Write-Host "  [X] Error: $($_.Exception.Message)" -ForegroundColor Red
                }

                $buffer = [System.Text.Encoding]::UTF8.GetBytes($json)
                $response.ContentType = "application/json; charset=utf-8"
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
            Write-Host "  [X] $($_.Exception.Message)" -ForegroundColor Red
            try {
                $response.StatusCode = 500
                $buffer = [System.Text.Encoding]::UTF8.GetBytes((@{error=$_.Exception.Message}|ConvertTo-Json -Compress))
                $response.ContentType = "application/json"
                $response.ContentLength64 = $buffer.Length
                $response.OutputStream.Write($buffer, 0, $buffer.Length)
            } catch {}
        }
        finally { $response.OutputStream.Close() }
    }
}
catch [System.OperationCanceledException] {}
finally {
    Write-Host "`n  [*] Shutting down..." -ForegroundColor Yellow
    $listener.Stop(); $listener.Close()
    Write-Host "  [+] Stopped." -ForegroundColor Green
}
