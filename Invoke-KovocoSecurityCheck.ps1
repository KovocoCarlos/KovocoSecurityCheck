<#
.SYNOPSIS
    Kovoco SQL Server Security Assessment Tool v3.1

.DESCRIPTION
    Launches a local web dashboard and runs security checks directly against
    SQL Server DMVs. Nothing is installed on the target instance.

.PARAMETER Port
    Local port for the web UI. Defaults to 18642.

.PARAMETER NoBrowser
    Skip auto-opening the browser.

.EXAMPLE
    .\Invoke-KovocoSecurityCheck.ps1

.NOTES
    Requires: PowerShell 5.1+, SqlServer module, sysadmin on target, SQL Server 2016+
#>

[CmdletBinding()]
param([int]$Port = 18642, [switch]$NoBrowser)

$KovocoVersion = "3.1.0"

Write-Host @"

    +=================================================================+
    |         K O V O C O                                             |
    |         SQL Server Security Assessment v$KovocoVersion                  |
    |         Standalone Engine - No target installation required      |
    +=================================================================+

"@ -ForegroundColor Cyan

# -- Prereqs --
if (-not (Get-Module -ListAvailable -Name SqlServer)) {
    Write-Host "  [!] Installing SqlServer module..." -ForegroundColor Yellow
    try { Install-Module -Name SqlServer -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop }
    catch { Write-Host "  [X] $($_.Exception.Message)" -ForegroundColor Red; exit 1 }
}
Import-Module SqlServer -ErrorAction Stop
Write-Host "  [+] SqlServer module loaded." -ForegroundColor Green


# ============================================================================
# CHECK DEFINITIONS
# Each returns rows with: details, actionStep columns when issue IS found.
# Optional: databaseName column.
# "description" field explains what the check looks for (shown in inventory).
# ============================================================================
$script:SecurityChecks = @(

    # -- PERMISSIONS & ROLES --

    @{ id=1001; name="Enabled sa account"; category="Permissions & Roles"; severity="High"
       description="Checks whether the original sa login (SID 0x01) is enabled for connections. The sa account is the #1 target for brute-force attacks."
       query=@"
SELECT 'The [sa] account (or renamed: [' + name COLLATE DATABASE_DEFAULT + ']) is enabled for connections. This is the most targeted account for brute-force attacks.' AS details,
    'Disable the sa login. It can still own databases and jobs while disabled.' AS actionStep
FROM sys.sql_logins WHERE sid = 0x01 AND is_disabled = 0
"@ }

    @{ id=1002; name="sysadmin role members"; category="Permissions & Roles"; severity="High"
       description="Lists all enabled logins in the sysadmin server role (excluding sa, NT SERVICE accounts, and internal certificate logins)."
       query=@"
SELECT 'Login [' + l.name COLLATE DATABASE_DEFAULT + '] (' + l.type_desc COLLATE DATABASE_DEFAULT + ') is a sysadmin with unrestricted access to the entire instance.' AS details,
    'Review whether this login requires sysadmin. Grant only minimum permissions needed.' AS actionStep
FROM sys.server_principals l
INNER JOIN sys.server_role_members rm ON l.principal_id = rm.member_principal_id
INNER JOIN sys.server_principals r ON rm.role_principal_id = r.principal_id
WHERE r.name = 'sysadmin' AND l.name <> SUSER_SNAME(0x01) AND l.is_disabled = 0
    AND l.name NOT LIKE 'NT SERVICE\%' AND l.name NOT LIKE '##%##'
"@ }

    @{ id=1003; name="securityadmin role members"; category="Permissions & Roles"; severity="High"
       description="Lists enabled logins in the securityadmin role, which can create/alter logins and effectively escalate to sysadmin."
       query=@"
SELECT 'Login [' + l.name COLLATE DATABASE_DEFAULT + '] is a securityadmin and can create logins, effectively granting sysadmin-equivalent access.' AS details,
    'Review whether this login requires securityadmin.' AS actionStep
FROM sys.server_principals l
INNER JOIN sys.server_role_members rm ON l.principal_id = rm.member_principal_id
INNER JOIN sys.server_principals r ON rm.role_principal_id = r.principal_id
WHERE r.name = 'securityadmin' AND l.name <> SUSER_SNAME(0x01) AND l.is_disabled = 0
"@ }

    @{ id=1004; name="CONTROL SERVER permissions"; category="Permissions & Roles"; severity="High"
       description="Identifies logins granted CONTROL SERVER, which is functionally equivalent to sysadmin."
       query=@"
SELECT 'Login [' + pri.name COLLATE DATABASE_DEFAULT + '] has CONTROL SERVER permission, functionally equivalent to sysadmin.' AS details,
    'Review whether this login requires CONTROL SERVER. Consider more specific permissions.' AS actionStep
FROM sys.server_principals AS pri
WHERE pri.principal_id IN (
    SELECT p.grantee_principal_id FROM sys.server_permissions AS p
    WHERE p.[state] IN ('G','W') AND p.class = 100 AND p.[type] = 'CL'
) AND pri.name NOT LIKE '##%##'
"@ }

    @{ id=1005; name="IMPERSONATE grants"; category="Permissions & Roles"; severity="High"
       description="Finds logins that can impersonate other server principals, which can be used for privilege escalation."
       query=@"
SELECT 'Login [' + grantee.name COLLATE DATABASE_DEFAULT + '] can impersonate [' + target.name COLLATE DATABASE_DEFAULT + '], potentially escalating privileges.' AS details,
    'Review IMPERSONATE grants. If the target has elevated permissions, the grantee effectively gains them.' AS actionStep
FROM sys.server_permissions p
INNER JOIN sys.server_principals grantee ON p.grantee_principal_id = grantee.principal_id
INNER JOIN sys.server_principals target ON p.major_id = target.principal_id
WHERE p.[type] = 'IM' AND p.[state] IN ('G','W')
"@ }

    @{ id=1006; name="Blank passwords"; category="Permissions & Roles"; severity="High"
       description="Tests all SQL logins for blank (empty) passwords using PWDCOMPARE."
       query=@"
SELECT 'SQL login [' + name COLLATE DATABASE_DEFAULT + '] has a blank password.' AS details,
    'Set a strong password immediately.' AS actionStep
FROM sys.sql_logins WHERE PWDCOMPARE('', password_hash) = 1
"@ }

    @{ id=1007; name="Password same as login name"; category="Permissions & Roles"; severity="High"
       description="Tests whether any SQL login has a password identical to the login name."
       query=@"
SELECT 'SQL login [' + name COLLATE DATABASE_DEFAULT + '] has a password identical to the login name.' AS details,
    'Change the password. Attackers routinely test login-name-as-password.' AS actionStep
FROM sys.sql_logins WHERE PWDCOMPARE(name, password_hash) = 1
"@ }

    @{ id=1008; name="Common weak passwords"; category="Permissions & Roles"; severity="High"
       description="Tests SQL logins against a set of commonly used weak passwords (password, 123456, Password1, admin, sqlserver)."
       query=@"
SELECT 'SQL login [' + name COLLATE DATABASE_DEFAULT + '] uses a commonly guessed password.' AS details,
    'Change the password to a strong, unique value.' AS actionStep
FROM sys.sql_logins
WHERE PWDCOMPARE('password', password_hash) = 1 OR PWDCOMPARE('123456', password_hash) = 1
   OR PWDCOMPARE('Password1', password_hash) = 1 OR PWDCOMPARE('admin', password_hash) = 1
   OR PWDCOMPARE('sqlserver', password_hash) = 1
"@ }

    @{ id=1009; name="Password policy not enforced"; category="Permissions & Roles"; severity="Medium"
       description="Identifies enabled SQL logins with CHECK_POLICY = OFF, bypassing Windows password complexity requirements."
       query=@"
SELECT 'SQL login [' + name COLLATE DATABASE_DEFAULT + '] has CHECK_POLICY = OFF, bypassing password complexity requirements.' AS details,
    'Enable CHECK_POLICY unless there is a documented compatibility reason.' AS actionStep
FROM sys.sql_logins WHERE is_policy_checked = 0 AND name NOT LIKE '##%##' AND is_disabled = 0
"@ }

    @{ id=1010; name="Password expiration disabled"; category="Permissions & Roles"; severity="Medium"
       description="Identifies enabled SQL logins with CHECK_EXPIRATION = OFF (where policy is enabled), meaning passwords never rotate."
       query=@"
SELECT 'SQL login [' + name COLLATE DATABASE_DEFAULT + '] has CHECK_EXPIRATION = OFF. This password will never rotate.' AS details,
    'Enable CHECK_EXPIRATION or implement external rotation.' AS actionStep
FROM sys.sql_logins
WHERE is_expiration_checked = 0 AND is_policy_checked = 1 AND name NOT LIKE '##%##' AND is_disabled = 0 AND sid <> 0x01
"@ }

    @{ id=1011; name="Invalid Windows logins"; category="Permissions & Roles"; severity="Low"
       description="Uses sp_validatelogins to find Windows logins/groups that no longer map to valid Active Directory accounts."
       query=@"
CREATE TABLE #KovocoInvalid (LoginSID VARBINARY(85), LoginName VARCHAR(256));
INSERT INTO #KovocoInvalid EXEC sp_validatelogins;
SELECT '[' + LoginName + '] is an orphaned Windows login with no matching AD account.' AS details,
    'Verify the account no longer exists, then drop the login.' AS actionStep
FROM #KovocoInvalid;
DROP TABLE #KovocoInvalid;
"@ }

    @{ id=1013; name="VIEW ANY DATABASE granted to public"; category="Permissions & Roles"; severity="Medium"
       description="Checks whether the public server role has VIEW ANY DATABASE, allowing every login to enumerate all databases."
       query=@"
SELECT 'The [public] role has VIEW ANY DATABASE, allowing every login to see all database names.' AS details,
    'Revoke VIEW ANY DATABASE from public unless specifically required.' AS actionStep
FROM sys.server_permissions WHERE grantee_principal_id = 2 AND [type] = 'VD' AND [state] IN ('G','W')
"@ }

    @{ id=1014; name="Service account elevated privileges"; category="Permissions & Roles"; severity="High"
       description="Checks if the SQL Server service runs as LocalSystem or NT AUTHORITY\\SYSTEM, which grants excessive OS-level privileges."
       query=@"
SELECT 'SQL Server service runs as [' + service_account + '], a highly privileged built-in account.' AS details,
    'Use a dedicated low-privilege domain account or gMSA instead.' AS actionStep
FROM sys.dm_server_services
WHERE UPPER(service_account) IN ('LOCALSYSTEM', 'NT AUTHORITY\SYSTEM')
    AND servicename LIKE 'SQL Server (%'
"@ }


    # -- CONFIGURATION & SURFACE AREA --

    @{ id=2001; name="xp_cmdshell enabled"; category="Configuration & Surface Area"; severity="Medium"
       description="Checks whether xp_cmdshell is enabled, allowing sysadmins to execute OS commands from SQL Server."
       query=@"
SELECT 'xp_cmdshell is enabled, allowing sysadmins to execute OS commands from SQL Server.' AS details,
    'Disable via sp_configure if not actively required.' AS actionStep
FROM sys.configurations WHERE name = 'xp_cmdshell' AND value_in_use = 1
"@ }

    @{ id=2002; name="CLR enabled"; category="Configuration & Surface Area"; severity="Medium"
       description="Checks whether CLR integration is enabled, permitting .NET assemblies to execute in the SQL Server process (skips if SSISDB exists)."
       query=@"
SELECT 'CLR integration is enabled, permitting .NET assemblies to run in the SQL Server process.' AS details,
    CASE WHEN CAST(SERVERPROPERTY('ProductMajorVersion') AS INT) >= 14
        THEN 'For SQL 2017+, consider clr strict security instead.'
        ELSE 'A SAFE assembly may still access external resources. Disable if not required.' END AS actionStep
FROM sys.configurations WHERE name = 'clr enabled' AND value_in_use = 1
    AND NOT EXISTS (SELECT 1 FROM sys.databases WHERE name = 'SSISDB')
"@ }

    @{ id=2003; name="Cross-database ownership chaining"; category="Configuration & Surface Area"; severity="Medium"
       description="Checks whether server-level cross-database ownership chaining is enabled, allowing cross-database object access without permission checks."
       query=@"
SELECT 'Server-level cross-database ownership chaining is enabled.' AS details,
    'Disable at server level. Enable only at individual database level where required.' AS actionStep
FROM sys.configurations WHERE name = 'cross db ownership chaining' AND value_in_use = 1
"@ }

    @{ id=2004; name="Ad Hoc Distributed Queries"; category="Configuration & Surface Area"; severity="Medium"
       description="Checks whether Ad Hoc Distributed Queries are enabled, permitting OPENROWSET/OPENDATASOURCE to arbitrary external sources."
       query=@"
SELECT 'Ad Hoc Distributed Queries are enabled, permitting OPENROWSET/OPENDATASOURCE calls.' AS details,
    'Disable unless required. SQL injection + this setting = external file reads.' AS actionStep
FROM sys.configurations WHERE name = 'Ad Hoc Distributed Queries' AND value_in_use = 1
"@ }

    @{ id=2005; name="Ole Automation Procedures"; category="Configuration & Surface Area"; severity="Medium"
       description="Checks whether Ole Automation Procedures are enabled, allowing OLE object creation inside SQL Server."
       query=@"
SELECT 'Ole Automation Procedures are enabled.' AS details,
    'Disable unless actively required.' AS actionStep
FROM sys.configurations WHERE name = 'Ole Automation Procedures' AND value_in_use = 1
"@ }

    @{ id=2006; name="Remote Access enabled without linked servers"; category="Configuration & Surface Area"; severity="Low"
       description="Checks whether the Remote Access setting is enabled when no linked servers exist. Remote Access allows remote stored procedure calls between servers, but defaults to ON even in new installations. It is only needed for linked server or log shipping RPC scenarios."
       query=@"
IF (SELECT value_in_use FROM sys.configurations WHERE name = 'remote access') = 1
   AND NOT EXISTS (SELECT 1 FROM sys.servers WHERE is_linked = 1)
    SELECT 'Remote Access is enabled but no linked servers are configured. This setting allows remote stored procedure execution between servers and has been deprecated by Microsoft, though it still defaults to ON in new installations (including SQL Server 2025).' AS details,
        'Since no linked servers exist on this instance, disable Remote Access: EXEC sp_configure ''remote access'', 0; RECONFIGURE; — Note: this requires a SQL Server restart to take effect.' AS actionStep;
"@ }

    @{ id=2007; name="Database Mail XPs"; category="Configuration & Surface Area"; severity="Low"
       description="Checks whether Database Mail XPs are enabled, which could be abused for phishing or DoS if the instance is compromised."
       query=@"
SELECT 'Database Mail XPs are enabled.' AS details,
    'Verify mail is needed. Ensure profiles are restricted to appropriate principals.' AS actionStep
FROM sys.configurations WHERE name = 'Database Mail XPs' AND value_in_use = 1
"@ }

    @{ id=2008; name="TRUSTWORTHY + sysadmin owner"; category="Configuration & Surface Area"; severity="High"
       description="Finds databases with TRUSTWORTHY ON whose owner is a sysadmin, enabling privilege escalation from db_owner to sysadmin."
       query=@"
SELECT 'Database [' + d.name COLLATE DATABASE_DEFAULT + '] has TRUSTWORTHY ON and sysadmin owner [' + sp.name COLLATE DATABASE_DEFAULT + ']. db_owner can escalate to sysadmin.' AS details,
    'Set TRUSTWORTHY OFF or change owner to a non-sysadmin login.' AS actionStep, d.name COLLATE DATABASE_DEFAULT AS databaseName
FROM sys.databases d INNER JOIN sys.server_principals sp ON d.owner_sid = sp.sid
WHERE d.database_id > 4 AND d.is_trustworthy_on = 1 AND IS_SRVROLEMEMBER('sysadmin', sp.name) = 1
"@ }

    @{ id=2009; name="TRUSTWORTHY databases"; category="Configuration & Surface Area"; severity="Medium"
       description="Finds user databases with TRUSTWORTHY ON (excluding those already flagged with sysadmin owners)."
       query=@"
SELECT 'Database [' + name COLLATE DATABASE_DEFAULT + '] has TRUSTWORTHY enabled.' AS details,
    'Disable TRUSTWORTHY. Use certificate-based code signing instead.' AS actionStep, name COLLATE DATABASE_DEFAULT AS databaseName
FROM sys.databases WHERE database_id > 4 AND is_trustworthy_on = 1
    AND IS_SRVROLEMEMBER('sysadmin', SUSER_SNAME(owner_sid)) = 0
"@ }

    @{ id=2010; name="Failed login audit not enabled"; category="Configuration & Surface Area"; severity="High"
       description="Reads the registry to verify login auditing captures failed login attempts."
       query=@"
DECLARE @AL INT;
EXEC master..xp_instance_regread 'HKEY_LOCAL_MACHINE','SOFTWARE\Microsoft\MSSQLServer\MSSQLServer','AuditLevel',@AL OUTPUT;
IF ISNULL(@AL, 0) < 2
    SELECT 'Login auditing does not capture failed logins. Brute-force attacks will go undetected.' AS details,
        'Set Login Auditing to Failed logins only or Both in SQL Server properties.' AS actionStep;
"@ }

    @{ id=2011; name="Recent failed logins"; category="Configuration & Surface Area"; severity="Medium"
       description="Reads the current SQL error log for failed login entries, which may indicate brute-force attempts."
       query=@"
DECLARE @EL TABLE (LogDate DATETIME, ProcessInfo NVARCHAR(50), Txt NVARCHAR(MAX));
INSERT @EL EXEC sp_readerrorlog 0, 1, 'Login failed';
DECLARE @c INT = (SELECT COUNT(*) FROM @EL);
IF @c > 0
    SELECT CAST(@c AS VARCHAR(10)) + ' failed login entries in the current error log.' AS details,
        'Review the error log for patterns: repeated logins, unusual IPs, off-hours attempts.' AS actionStep;
"@ }

    @{ id=2012; name="Error log retention"; category="Configuration & Surface Area"; severity="Low"
       description="Checks the number of configured error log files and recommends retaining at least 6 months of history. The default is 6 files, which at the default cycle-on-restart cadence may only cover days or weeks. Many administrators use a weekly log cycle (e.g., Ola Hallengren's maintenance solution includes an sp_cycle_errorlog step). With weekly cycling, 26 files = 6 months of history."
       query=@"
DECLARE @N INT;
EXEC master.sys.xp_instance_regread N'HKEY_LOCAL_MACHINE',N'Software\Microsoft\MSSQLServer\MSSQLServer',N'NumErrorLogs',@N OUTPUT;
SET @N = ISNULL(@N, 6);
IF @N < 26
    SELECT 'This instance is configured for ' + CAST(@N AS VARCHAR(10)) + ' error log files (default is 6). '
        + CASE
            WHEN @N <= 6 THEN 'At the default cycle-on-restart cadence, this may only retain days or weeks of login failure history — not enough for forensic review after a breach.'
            WHEN @N <= 12 THEN 'This is better than the default, but may only cover 2-3 months if logs are cycled weekly.'
            ELSE 'This provides partial coverage but falls short of the recommended 6-month retention.'
          END AS details,
        'We recommend configuring at least 26 error log files to retain approximately 6 months of security event history. '
        + 'If you are not already cycling logs on a schedule, consider adding a weekly SQL Agent job that runs EXEC sp_cycle_errorlog (Ola Hallengren''s maintenance solution includes this as a step). '
        + 'To change the retention count: EXEC xp_instance_regwrite N''HKEY_LOCAL_MACHINE'', N''Software\Microsoft\MSSQLServer\MSSQLServer'', N''NumErrorLogs'', REG_DWORD, 26; '
        + 'Or set it in SSMS under Management > SQL Server Logs > right-click > Configure.' AS actionStep;
"@ }

    @{ id=2013; name="Linked server with sa"; category="Configuration & Surface Area"; severity="High"
       description="Finds linked servers configured to connect using the sa login, granting all local users full remote admin rights."
       query=@"
SELECT 'Linked server [' + s.name COLLATE DATABASE_DEFAULT + '] connects to [' + s.data_source COLLATE DATABASE_DEFAULT + '] as [sa].' AS details,
    'Change to a least-privilege login or caller security context.' AS actionStep
FROM sys.servers s INNER JOIN sys.linked_logins l ON s.server_id = l.server_id
WHERE s.is_linked = 1 AND l.local_principal_id = 0 AND l.uses_self_credential = 0 AND l.remote_name = 'sa'
"@ }

    @{ id=2014; name="Linked server with fixed login"; category="Configuration & Surface Area"; severity="Medium"
       description="Finds linked servers using a fixed (non-sa) remote login, which may have more permissions than intended."
       query=@"
SELECT 'Linked server [' + s.name COLLATE DATABASE_DEFAULT + '] connects to [' + s.data_source COLLATE DATABASE_DEFAULT + '] as [' + l.remote_name COLLATE DATABASE_DEFAULT + '].' AS details,
    'Verify the remote login has minimum required permissions.' AS actionStep
FROM sys.servers s INNER JOIN sys.linked_logins l ON s.server_id = l.server_id
WHERE s.is_linked = 1 AND l.local_principal_id = 0 AND l.uses_self_credential = 0
    AND l.remote_name IS NOT NULL AND l.remote_name <> 'sa'
"@ }

    @{ id=2015; name="Startup stored procedures"; category="Configuration & Surface Area"; severity="Medium"
       description="Finds stored procedures in master that are configured to execute automatically when SQL Server starts."
       query=@"
SELECT 'Procedure [master].[' + SPECIFIC_SCHEMA + '].[' + SPECIFIC_NAME + '] runs on every SQL Server startup.' AS details,
    'Verify what this procedure does. Malicious startup procs persist across restarts.' AS actionStep
FROM master.INFORMATION_SCHEMA.ROUTINES WHERE OBJECTPROPERTY(OBJECT_ID(ROUTINE_NAME), 'ExecIsStartup') = 1
"@ }

    @{ id=2016; name="Startup Agent jobs"; category="Configuration & Surface Area"; severity="Medium"
       description="Finds enabled SQL Agent jobs scheduled to run automatically when SQL Server Agent starts."
       query=@"
SELECT 'Agent job [' + j.name COLLATE DATABASE_DEFAULT + '] runs automatically on Agent startup.' AS details,
    'Verify what this job does. Startup jobs execute before administrators can intervene.' AS actionStep
FROM msdb.dbo.sysschedules s
INNER JOIN msdb.dbo.sysjobschedules js ON s.schedule_id = js.schedule_id
INNER JOIN msdb.dbo.sysjobs j ON js.job_id = j.job_id
WHERE s.freq_type = 64 AND s.enabled = 1 AND j.enabled = 1
"@ }

    @{ id=2017; name="Force Encryption disabled"; category="Configuration & Surface Area"; severity="Medium"
       description="Reads the registry to check if Force Encryption is enabled, ensuring all client connections use TLS."
       query=@"
DECLARE @FE INT;
EXEC xp_instance_regread 'HKEY_LOCAL_MACHINE','Software\Microsoft\Microsoft SQL Server\MSSQLServer\SuperSocketNetLib','ForceEncryption',@FE OUTPUT;
IF ISNULL(@FE, 0) = 0
    SELECT 'Force Encryption is DISABLED. Connections may transmit data in cleartext.' AS details,
        'Enable Force Encryption in SQL Server Configuration Manager.' AS actionStep;
"@ }

    @{ id=2018; name="Hide Instance disabled"; category="Configuration & Surface Area"; severity="Low"
       description="Checks whether Hide Instance is enabled, preventing the SQL Server Browser from advertising this instance."
       query=@"
DECLARE @HI INT;
EXEC xp_instance_regread 'HKEY_LOCAL_MACHINE','Software\Microsoft\Microsoft SQL Server\MSSQLServer\SuperSocketNetLib','HideInstance',@HI OUTPUT;
IF ISNULL(@HI, 0) = 0
    SELECT 'Hide Instance is DISABLED. SQL Browser will advertise this instance on the network.' AS details,
        'Enable in Configuration Manager. Clients must specify port explicitly.' AS actionStep;
"@ }

    @{ id=2019; name="C2 audit mode"; category="Configuration & Surface Area"; severity="Low"
       description="Checks whether C2 audit mode is enabled, which generates extensive audit logs that can fill the drive and crash SQL Server."
       query=@"
SELECT 'C2 audit mode is enabled. Log volume can fill the data drive and shut down SQL Server.' AS details,
    'Migrate to SQL Server Audit for granular control without drive-fill risk.' AS actionStep
FROM sys.configurations WHERE name = 'c2 audit mode' AND value_in_use = 1
"@ }

    @{ id=2020; name="Contained Database Authentication"; category="Configuration & Surface Area"; severity="Low"
       description="Checks if Contained Database Authentication is enabled, which permits contained databases with independent authentication."
       query=@"
SELECT 'Contained Database Authentication is enabled.' AS details,
    'Verify this is intentional. Contained database users with ALTER can elevate themselves.' AS actionStep
FROM sys.configurations WHERE name = 'contained database authentication' AND value_in_use = 1
"@ }

    @{ id=2021; name="Agent jobs owned by users"; category="Configuration & Surface Area"; severity="Low"
       description="Finds enabled Agent jobs owned by non-sa logins. If the owner account is disabled or removed, the job breaks."
       query=@"
SELECT 'Job [' + j.name COLLATE DATABASE_DEFAULT + '] is owned by [' + SUSER_SNAME(j.owner_sid) COLLATE DATABASE_DEFAULT + ']. If this login is removed, the job fails.' AS details,
    'Consider changing job ownership to sa.' AS actionStep
FROM msdb.dbo.sysjobs j
WHERE j.enabled = 1 AND SUSER_SNAME(j.owner_sid) <> SUSER_SNAME(0x01) AND SUSER_SNAME(j.owner_sid) NOT LIKE '##%'
"@ }

    @{ id=2022; name="Unsupported SQL Server version"; category="Configuration & Surface Area"; severity="High"
       description="Checks if the SQL Server major version is older than 2016, meaning no future security patches from Microsoft."
       query=@"
IF CAST(SERVERPROPERTY('ProductMajorVersion') AS INT) < 13 AND SERVERPROPERTY('EngineEdition') <> 8
    SELECT 'This SQL Server version is no longer supported by Microsoft. No future security updates.' AS details,
        'Upgrade to SQL Server 2016 or later.' AS actionStep;
"@ }


    # -- ENCRYPTION & DATA PROTECTION --

    @{ id=3001; name="Backup encryption not enabled"; category="Encryption & Data Protection"; severity="Medium"
       description="Checks recent full backups for user databases to determine if any were written without encryption. Unencrypted backups expose data at rest if backup media is lost or stolen."
       minVersion=12
       query=@"
;WITH LatestBackups AS (
    SELECT database_name, encryptor_type, key_algorithm,
        ROW_NUMBER() OVER (PARTITION BY database_name ORDER BY backup_finish_date DESC) AS rn
    FROM msdb.dbo.backupset
    WHERE type = 'D' AND database_name NOT IN ('master','model','msdb','tempdb')
)
SELECT 'The most recent full backup of [' + database_name COLLATE DATABASE_DEFAULT + '] is not encrypted.' AS details,
    'Enable backup encryption using a certificate or asymmetric key. Example: BACKUP DATABASE [' + database_name COLLATE DATABASE_DEFAULT + '] TO DISK = ''...'' WITH ENCRYPTION(ALGORITHM = AES_256, SERVER CERTIFICATE = [YourBackupCert]).' AS actionStep,
    database_name COLLATE DATABASE_DEFAULT AS databaseName
FROM LatestBackups
WHERE rn = 1 AND encryptor_type IS NULL
"@ }

    @{ id=3002; name="TDE certificate never backed up"; category="Encryption & Data Protection"; severity="High"
       description="Finds TDE encryption certificates that have never had their private key backed up. Without a backup, you cannot restore the encrypted database on another server."
       query=@"
SELECT 'The TDE certificate [' + c.name COLLATE DATABASE_DEFAULT + '] protecting database [' + DB_NAME(d.database_id) COLLATE DATABASE_DEFAULT + '] has never been backed up.' AS details,
    'Back up the certificate immediately: BACKUP CERTIFICATE [' + c.name COLLATE DATABASE_DEFAULT + '] TO FILE = ''C:\Secure\' + c.name COLLATE DATABASE_DEFAULT + '.cer'' WITH PRIVATE KEY (FILE = ''C:\Secure\' + c.name COLLATE DATABASE_DEFAULT + '.pvk'', ENCRYPTION BY PASSWORD = ''<StrongPassword>''); Store the files and password in a secure offsite location.' AS actionStep,
    DB_NAME(d.database_id) COLLATE DATABASE_DEFAULT AS databaseName
FROM sys.certificates c
INNER JOIN sys.dm_database_encryption_keys d ON c.thumbprint = d.encryptor_thumbprint
WHERE c.pvt_key_last_backup_date IS NULL
"@ }

    @{ id=3003; name="TDE certificate expiring soon"; category="Encryption & Data Protection"; severity="Medium"
       description="Finds TDE certificates that will expire within 90 days. While expired TDE certificates still function, rotating them is a security best practice."
       query=@"
SELECT 'The TDE certificate [' + c.name COLLATE DATABASE_DEFAULT + '] for database [' + DB_NAME(d.database_id) COLLATE DATABASE_DEFAULT + '] expires on ' + CONVERT(VARCHAR(20), c.expiry_date, 120) + '.' AS details,
    'Rotate the TDE certificate before expiration. Create a new certificate, alter the database encryption key to use it, then back up the new certificate.' AS actionStep,
    DB_NAME(d.database_id) COLLATE DATABASE_DEFAULT AS databaseName
FROM sys.certificates c
INNER JOIN sys.dm_database_encryption_keys d ON c.thumbprint = d.encryptor_thumbprint
WHERE c.expiry_date <= DATEADD(DAY, 90, GETDATE())
"@ }

    @{ id=3004; name="Force Encryption off with self-signed cert"; category="Encryption & Data Protection"; severity="Medium"
       description="When Force Encryption is disabled and the instance uses a self-signed certificate, client connections may fall back to unencrypted communication. Checks the registry for the Force Encryption flag and whether a custom certificate thumbprint has been configured."
       query=@"
DECLARE @FE INT, @CertHash NVARCHAR(256);
EXEC xp_instance_regread 'HKEY_LOCAL_MACHINE','Software\Microsoft\Microsoft SQL Server\MSSQLServer\SuperSocketNetLib','ForceEncryption',@FE OUTPUT;
EXEC xp_instance_regread 'HKEY_LOCAL_MACHINE','Software\Microsoft\Microsoft SQL Server\MSSQLServer\SuperSocketNetLib','Certificate',@CertHash OUTPUT;
IF ISNULL(@FE, 0) = 0 AND (ISNULL(@CertHash, '') = '' OR LEN(@CertHash) < 10)
    SELECT 'Force Encryption is OFF and no custom TLS certificate is configured. SQL Server is using a self-signed certificate, and clients can connect without encryption.' AS details,
        'Install a CA-issued TLS certificate on the server, configure it in SQL Server Configuration Manager, and enable Force Encryption. This ensures all connections are encrypted with a trusted certificate.' AS actionStep;
"@ }

    @{ id=3005; name="Backup certificate never backed up"; category="Encryption & Data Protection"; severity="High"
       description="Finds certificates used for backup encryption that have never had their private key backed up. Without a backup, encrypted backups cannot be restored on another server."
       minVersion=12
       query=@"
SELECT DISTINCT 'The backup encryption certificate [' + c.name COLLATE DATABASE_DEFAULT + '] used by database [' + b.database_name COLLATE DATABASE_DEFAULT + '] has never been backed up.' AS details,
    'Back up this certificate and its private key immediately to a secure offsite location.' AS actionStep,
    b.database_name COLLATE DATABASE_DEFAULT AS databaseName
FROM sys.certificates c
INNER JOIN msdb.dbo.backupset b ON c.thumbprint = b.encryptor_thumbprint
WHERE c.pvt_key_last_backup_date IS NULL AND b.encryptor_thumbprint IS NOT NULL
"@ }


    # -- NETWORK & CONNECTIVITY --

    @{ id=4001; name="SQL Browser service running"; category="Network & Connectivity"; severity="Low"
       description="Checks if the SQL Server Browser service is running. The Browser service responds to UDP 1434 queries and advertises all SQL Server instances, their names, and port numbers to anyone on the network."
       query=@"
SELECT 'The SQL Server Browser service is running, advertising instance names and ports on UDP 1434 to anyone on the network.' AS details,
    'If all applications connect using explicit server\instance or server,port syntax, consider stopping and disabling the SQL Browser service to reduce network exposure. If named instances require dynamic port discovery, restrict network access to UDP 1434 via firewall rules.' AS actionStep
FROM sys.dm_server_services
WHERE servicename LIKE 'SQL Server Browser%' AND status = 4
"@ }

    @{ id=4002; name="Default port 1433 in use"; category="Network & Connectivity"; severity="Low"
       description="Checks whether the instance is listening on the well-known default port 1433. Automated scanners and worms target this port specifically."
       query=@"
IF EXISTS (
    SELECT 1 FROM sys.dm_exec_connections
    WHERE local_tcp_port = 1433 AND session_id = @@SPID
)
    SELECT 'This instance is listening on the default port 1433, which is the first port targeted by automated SQL Server scanners and worms.' AS details,
        'Consider changing to a non-standard port in SQL Server Configuration Manager. Update connection strings and firewall rules accordingly. This is defense-in-depth — it won''t stop a determined attacker but eliminates drive-by scanning.' AS actionStep;
"@ }

    @{ id=4003; name="Multiple IP addresses listening"; category="Network & Connectivity"; severity="Low"
       description="Checks if SQL Server is configured to listen on all IP addresses (0.0.0.0). In multi-NIC environments, this may expose SQL Server on interfaces that should not have database access (e.g., a management or backup network)."
       query=@"
DECLARE @ListenAll INT;
EXEC xp_instance_regread 'HKEY_LOCAL_MACHINE','Software\Microsoft\Microsoft SQL Server\MSSQLServer\SuperSocketNetLib','ListenOnAllIPs',@ListenAll OUTPUT;
IF ISNULL(@ListenAll, 1) = 1
    SELECT 'SQL Server is configured to listen on ALL IP addresses. On servers with multiple network interfaces, this may expose the instance on networks where database access is not intended (e.g., backup, management, or public-facing NICs).' AS details,
        'In SQL Server Configuration Manager, under TCP/IP Properties, set Listen All to No, then enable only the specific IP addresses that should accept database connections.' AS actionStep;
"@ }


    # -- VULNERABILITY MANAGEMENT --

    @{ id=5001; name="Dynamic Data Masking not in use"; category="Vulnerability Management"; severity="Low"
       description="Checks whether any user databases have Dynamic Data Masking rules configured. DDM is a built-in feature (SQL 2016+) that masks sensitive data from non-privileged users without changing stored data. This check reports if the feature is completely unused across all user databases."
       minVersion=13
       query=@"
IF NOT EXISTS (
    SELECT 1 FROM sys.databases d
    CROSS APPLY (
        SELECT TOP 1 1 AS x FROM sys.masked_columns WHERE is_masked = 1
    ) mc
    WHERE d.database_id = DB_ID() AND d.database_id > 4
)
AND (SELECT COUNT(*) FROM sys.databases WHERE database_id > 4 AND state = 0) > 0
    SELECT 'No Dynamic Data Masking rules are configured in the current database. DDM can protect sensitive columns (SSN, email, credit card) from non-privileged users without application changes.' AS details,
        'Review tables for columns containing PII or sensitive data and apply masking rules. Example: ALTER TABLE dbo.Customers ALTER COLUMN SSN ADD MASKED WITH (FUNCTION = ''partial(0,"XXX-XX-",4)''); Non-privileged users will see masked values, while UNMASK permission holders see actual data.' AS actionStep;
"@ }

    @{ id=5002; name="Row-Level Security not in use"; category="Vulnerability Management"; severity="Low"
       description="Checks whether any security policies (Row-Level Security) exist in user databases. RLS is valuable for multi-tenant databases where row-level isolation should not depend solely on application logic."
       minVersion=13
       query=@"
IF NOT EXISTS (SELECT 1 FROM sys.security_policies)
AND (SELECT COUNT(*) FROM sys.databases WHERE database_id > 4 AND state = 0) > 0
    SELECT 'No Row-Level Security policies are configured in the current database. If this instance hosts multi-tenant data or role-based data access, RLS enforces row filtering at the database engine level rather than relying solely on application logic.' AS details,
        'Evaluate whether any tables contain data that should be filtered by user or tenant. RLS creates a security policy with a filter predicate function that automatically restricts which rows each user can access. This provides defense-in-depth even if the application layer has bugs.' AS actionStep;
"@ }

    @{ id=5003; name="SQL Vulnerability Assessment not configured"; category="Vulnerability Management"; severity="Low"
       description="Checks for the presence of SQL Vulnerability Assessment scan results. VA is built into SSMS 17.4+ and Azure SQL, providing automated security scanning against a knowledge base of known vulnerabilities."
       query=@"
IF NOT EXISTS (SELECT 1 FROM sys.dm_server_audit_status WHERE name LIKE '%VA%' OR name LIKE '%vulnerability%')
AND NOT EXISTS (SELECT 1 FROM msdb.dbo.sysjobs WHERE name LIKE '%vulnerability%' OR name LIKE '%VA scan%')
    SELECT 'No SQL Vulnerability Assessment scans appear to be configured. VA is a built-in scanning service available in SSMS 17.4+ and Azure SQL Database that checks for security misconfigurations, excessive permissions, and unprotected sensitive data.' AS details,
        'Open SSMS, right-click a database > Tasks > Vulnerability Assessment > Scan for Vulnerabilities. Configure a baseline and schedule recurring scans. For on-premises instances, scan results are stored locally. For Azure SQL, results integrate with Microsoft Defender for Cloud.' AS actionStep;
"@ }


    # -- OPERATIONAL SECURITY --

    @{ id=6001; name="EXECUTE AS LOGIN in stored procedures"; category="Operational Security"; severity="Medium"
       description="Finds stored procedures in user databases that use EXECUTE AS with a login context, which allows the procedure to run with elevated server-level permissions regardless of who calls it."
       query=@"
SELECT 'Procedure [' + DB_NAME() + '].[' + s.name COLLATE DATABASE_DEFAULT + '].[' + p.name COLLATE DATABASE_DEFAULT + '] uses EXECUTE AS LOGIN, running with server-level permissions of the specified login regardless of the caller.' AS details,
    'Review whether EXECUTE AS LOGIN is necessary. If only database-level elevation is needed, use EXECUTE AS USER instead. If server-level access is required, consider using certificate-signed modules with specific server permissions.' AS actionStep
FROM sys.sql_modules m
INNER JOIN sys.procedures p ON m.object_id = p.object_id
INNER JOIN sys.schemas s ON p.schema_id = s.schema_id
WHERE m.execute_as_principal_id IS NOT NULL
    AND m.execute_as_principal_id <> -2
    AND EXISTS (SELECT 1 FROM sys.server_principals sp WHERE sp.principal_id = m.execute_as_principal_id)
"@ }

    @{ id=6002; name="Agent proxy accounts with sysadmin credentials"; category="Operational Security"; severity="High"
       description="Finds SQL Agent proxy accounts whose underlying credential maps to a login that is a member of the sysadmin role. Job steps using these proxies run with full sysadmin-level OS access."
       query=@"
SELECT 'Agent proxy [' + p.name COLLATE DATABASE_DEFAULT + '] uses credential [' + c.name COLLATE DATABASE_DEFAULT + '] mapped to [' + c.credential_identity COLLATE DATABASE_DEFAULT + '], which is a sysadmin. Job steps using this proxy execute with full admin-level OS access.' AS details,
    'Review whether this proxy needs sysadmin-level access. Create a dedicated low-privilege credential for the proxy, or restrict which job steps can use it via msdb.dbo.sp_grant_proxy_to_subsystem.' AS actionStep
FROM msdb.dbo.sysproxies p
INNER JOIN sys.credentials c ON p.credential_id = c.credential_id
WHERE IS_SRVROLEMEMBER('sysadmin', c.credential_identity) = 1
    AND p.enabled = 1
"@ }

    @{ id=6003; name="Database Mail public profile access"; category="Operational Security"; severity="Medium"
       description="Finds Database Mail profiles configured as public (accessible to any database user). A compromised low-privilege user could abuse public mail profiles for phishing, spam, or data exfiltration via email attachments."
       query=@"
SELECT 'Database Mail profile [' + p.name COLLATE DATABASE_DEFAULT + '] is configured as a public profile, accessible to any database user in msdb.' AS details,
    'Make the profile private and grant access only to specific database principals or roles that need to send mail: EXECUTE msdb.dbo.sysmail_update_principalprofile_sp @principal_name = ''public'', @profile_name = ''' + p.name COLLATE DATABASE_DEFAULT + ''', @is_default = 0; Then grant to specific users.' AS actionStep
FROM msdb.dbo.sysmail_principalprofile pp
INNER JOIN msdb.dbo.sysmail_profile p ON pp.profile_id = p.profile_id
WHERE pp.principal_sid = 0x00 AND pp.is_default = 1
"@ }

    @{ id=6004; name="Guest user enabled in user databases"; category="Operational Security"; severity="Medium"
       description="Checks for user databases where the guest user has CONNECT permission. This allows any server login to access the database without an explicit database user mapping."
       query=@"
SELECT 'The guest user has CONNECT permission in database [' + d.name COLLATE DATABASE_DEFAULT + '], allowing any authenticated login to access this database without an explicit user mapping.' AS details,
    'Revoke guest access unless specifically required: USE [' + d.name COLLATE DATABASE_DEFAULT + ']; REVOKE CONNECT FROM guest;' AS actionStep,
    d.name COLLATE DATABASE_DEFAULT AS databaseName
FROM sys.databases d
WHERE d.database_id > 4 AND d.state = 0
AND EXISTS (
    SELECT 1 FROM sys.database_permissions dp
    INNER JOIN sys.database_principals pr ON dp.grantee_principal_id = pr.principal_id
    WHERE pr.name = 'guest' AND dp.permission_name = 'CONNECT' AND dp.state = 'G'
    AND DB_ID() = d.database_id
)
"@ }

    @{ id=6005; name="Agent jobs with CmdExec or PowerShell steps"; category="Operational Security"; severity="Medium"
       description="Finds enabled SQL Agent jobs that contain CmdExec or PowerShell job steps. These steps execute operating system commands and can be used for privilege escalation or lateral movement if the Agent service account is over-privileged."
       query=@"
SELECT 'Job [' + j.name COLLATE DATABASE_DEFAULT + '] has a ' +
    CASE js.subsystem
        WHEN 'CmdExec' THEN 'CmdExec (OS command)'
        WHEN 'PowerShell' THEN 'PowerShell'
    END + ' step [' + js.step_name COLLATE DATABASE_DEFAULT + '] that executes under the Agent service account or a proxy.' AS details,
    'Review the command in this step. If the step uses the Agent service account (no proxy), it runs with the full OS permissions of that account. Consider assigning a least-privilege proxy or replacing with a T-SQL alternative.' AS actionStep
FROM msdb.dbo.sysjobs j
INNER JOIN msdb.dbo.sysjobsteps js ON j.job_id = js.job_id
WHERE j.enabled = 1 AND js.subsystem IN ('CmdExec', 'PowerShell')
"@ }


    # -- INSTANCE INFORMATION --

    @{ id=9001; name="Server name"; category="Instance Information"; severity="Information"
       description="Reports the physical NetBIOS name of the server hosting this SQL Server instance."
       query="SELECT CAST(SERVERPROPERTY('ComputerNamePhysicalNetBIOS') AS NVARCHAR(128)) AS details, NULL AS actionStep" }

    @{ id=9002; name="Instance name"; category="Instance Information"; severity="Information"
       description="Reports the SQL Server instance name, or (default instance) if unnamed."
       query="SELECT COALESCE(CAST(SERVERPROPERTY('InstanceName') AS NVARCHAR(128)), '(default instance)') AS details, NULL AS actionStep" }

    @{ id=9003; name="SQL Server version"; category="Instance Information"; severity="Information"
       description="Reports the full product version and edition of this SQL Server instance."
       query="SELECT CAST(SERVERPROPERTY('ProductVersion') AS NVARCHAR(128)) + ' - ' + CAST(SERVERPROPERTY('Edition') AS NVARCHAR(128)) AS details, NULL AS actionStep" }

    @{ id=9004; name="SQL Server service account"; category="Instance Information"; severity="Information"
       description="Reports the Windows account running the SQL Server database engine service."
       query="SELECT service_account AS details, NULL AS actionStep FROM sys.dm_server_services WHERE servicename LIKE 'SQL Server (%'" }

    @{ id=9005; name="SQL Agent service account"; category="Instance Information"; severity="Information"
       description="Reports the Windows account running the SQL Server Agent service."
       query="SELECT service_account AS details, NULL AS actionStep FROM sys.dm_server_services WHERE servicename LIKE 'SQL Server Agent%'" }

    @{ id=9006; name="IP address"; category="Instance Information"; severity="Information"
       description="Reports the local IP address of the current connection to this SQL Server instance."
       query="SELECT COALESCE(CONVERT(VARCHAR(50), CONNECTIONPROPERTY('local_net_address')), 'UNKNOWN') AS details, 'Verify this is not externally-facing.' AS actionStep" }

    @{ id=9007; name="Encrypted databases"; category="Instance Information"; severity="Information"
       description="Counts user databases with TDE encryption enabled and reports the algorithm/key length in use."
       query=@"
SELECT CAST(COUNT(database_id) AS VARCHAR(10)) + ' database(s) encrypted with ' + key_algorithm + ' ' + CAST(key_length AS VARCHAR(5)) AS details,
    'Ensure encryption keys are backed up offsite.' AS actionStep
FROM sys.dm_database_encryption_keys WHERE database_id > 4 GROUP BY key_algorithm, key_length
"@ }

    @{ id=9008; name="Unencrypted user databases"; category="Instance Information"; severity="Information"
       description="Counts user databases that are NOT using TDE encryption."
       query=@"
SELECT CAST(COUNT(database_id) AS VARCHAR(10)) + ' user database(s) are not encrypted with TDE.' AS details,
    'Evaluate whether TDE is appropriate for databases with sensitive data.' AS actionStep
FROM sys.databases d WHERE database_id > 4
    AND NOT EXISTS (SELECT 1 FROM sys.dm_database_encryption_keys dek WHERE d.database_id = dek.database_id)
HAVING COUNT(database_id) > 0
"@ }
)


# ============================================================================
# HTML DASHBOARD
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
:root{--bg:#06090f;--card:rgba(14,20,33,0.85);--card2:rgba(20,28,45,0.95);--bdr:rgba(56,78,119,0.25);--bdr2:rgba(99,149,255,0.4);--t1:#d8e2f0;--t2:#7a8ba8;--t3:#4a5873;--acc:#5b8af5;--accg:rgba(91,138,245,0.15);--hi:#f04848;--md:#e8a020;--lo:#4499dd;--inf:#607088;--ok:#38b060;--f1:'DM Sans',-apple-system,sans-serif;--f2:'JetBrains Mono',monospace;}
*{margin:0;padding:0;box-sizing:border-box;}
body{font-family:var(--f1);background:var(--bg);color:var(--t1);min-height:100vh;}
body::before{content:'';position:fixed;inset:0;background-image:linear-gradient(rgba(56,78,119,0.04) 1px,transparent 1px),linear-gradient(90deg,rgba(56,78,119,0.04) 1px,transparent 1px);background-size:48px 48px;pointer-events:none;z-index:0;}
.hdr{position:sticky;top:0;z-index:100;background:rgba(6,9,15,0.92);backdrop-filter:blur(16px);border-bottom:1px solid var(--bdr);padding:0 28px;height:56px;display:flex;align-items:center;justify-content:space-between;}
.lg{display:flex;align-items:center;gap:12px;}
.lm{width:32px;height:32px;background:linear-gradient(135deg,#5b8af5,#3a5fc0);border-radius:7px;display:flex;align-items:center;justify-content:center;font-weight:800;font-size:15px;color:#fff;box-shadow:0 2px 12px rgba(91,138,245,0.25);}
.lt{font-weight:700;font-size:15px;letter-spacing:.08em;color:#fff;}
.ls{font-size:9.5px;color:var(--acc);letter-spacing:.18em;text-transform:uppercase;margin-top:-1px;}
.hs{font-family:var(--f2);font-size:11px;padding:3px 10px;border-radius:4px;}
.hsd{background:rgba(240,72,72,0.1);color:var(--hi);border:1px solid rgba(240,72,72,0.2);}
.hsc{background:rgba(56,176,96,0.1);color:var(--ok);border:1px solid rgba(56,176,96,0.2);}
.cnt{position:relative;z-index:1;max-width:1160px;margin:0 auto;padding:24px;}
.cs{display:flex;align-items:center;justify-content:center;min-height:calc(100vh - 56px);padding-bottom:80px;}
.cb{background:var(--card);border:1px solid var(--bdr);border-radius:12px;padding:36px 40px;width:100%;max-width:460px;box-shadow:0 8px 40px rgba(0,0,0,0.3);}
.cb h2{font-size:18px;font-weight:700;color:#fff;margin-bottom:4px;}
.cb .st{font-size:13px;color:var(--t2);margin-bottom:24px;}
.fg{margin-bottom:16px;}.fg label{display:block;font-size:11px;font-weight:600;color:var(--t2);text-transform:uppercase;letter-spacing:.08em;margin-bottom:6px;}
.fg input,.fg select{width:100%;padding:9px 12px;background:rgba(6,9,15,0.6);border:1px solid var(--bdr);border-radius:6px;color:var(--t1);font-family:var(--f2);font-size:13px;outline:none;transition:border-color .2s;}
.fg input:focus,.fg select:focus{border-color:var(--acc);box-shadow:0 0 0 3px var(--accg);}
.fg input::placeholder{color:var(--t3);}.fg select option{background:#0a0e1a;color:var(--t1);}
.fr{display:grid;grid-template-columns:1fr 1fr;gap:12px;}
.cr{display:flex;align-items:center;gap:8px;margin-bottom:14px;cursor:pointer;}
.cr input[type="checkbox"]{width:16px;height:16px;accent-color:var(--acc);cursor:pointer;}
.cr span{font-size:13px;color:var(--t2);}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;padding:10px 20px;border-radius:7px;font-size:13px;font-weight:600;border:none;cursor:pointer;transition:all .2s;font-family:var(--f1);}
.bp{background:linear-gradient(135deg,#5b8af5,#3a6ae0);color:#fff;width:100%;box-shadow:0 2px 12px rgba(91,138,245,0.25);}
.bp:hover{box-shadow:0 4px 20px rgba(91,138,245,0.4);transform:translateY(-1px);}
.bp:disabled{opacity:.5;cursor:not-allowed;transform:none;box-shadow:none;}
.bo{background:transparent;border:1px solid var(--bdr);color:var(--t2);}.bo:hover{border-color:var(--acc);color:var(--acc);}
.em{background:rgba(240,72,72,0.08);border:1px solid rgba(240,72,72,0.2);border-radius:6px;padding:10px 14px;font-size:12px;color:var(--hi);margin-bottom:16px;display:none;}
.in{font-size:11px;color:var(--t3);margin-top:12px;text-align:center;line-height:1.5;}
.tb{display:flex;gap:0;border-bottom:1px solid var(--bdr);margin-bottom:24px;}
.tt{padding:10px 20px;font-size:12.5px;font-weight:500;color:var(--t3);background:none;border:none;border-bottom:2px solid transparent;cursor:pointer;transition:all .15s;font-family:var(--f1);}
.tt:hover{color:var(--t2);}.tt.ac{color:var(--acc);border-bottom-color:var(--acc);font-weight:700;}
.sg{display:grid;grid-template-columns:200px 1fr;gap:16px;margin-bottom:24px;}
.sc{background:var(--card);border:1px solid var(--bdr);border-radius:10px;padding:24px;display:flex;flex-direction:column;align-items:center;justify-content:center;}
.sl{font-size:10px;color:var(--t3);text-transform:uppercase;letter-spacing:.12em;margin-bottom:10px;}
.sr{position:relative;width:110px;height:110px;}.sr svg{transform:rotate(-90deg);}
.sv{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;flex-direction:column;}
.sv .n{font-size:30px;font-weight:800;}.sv .d{font-size:9px;color:var(--t3);}
.svr{font-size:10px;color:var(--t2);margin-top:6px;}
.scs{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;}
.scd{background:var(--card);border:1px solid var(--bdr);border-radius:10px;padding:16px 18px;cursor:pointer;transition:all .15s;position:relative;overflow:hidden;}
.scd:hover{border-color:var(--bdr2);background:var(--card2);}
.scd .br{position:absolute;top:0;left:0;right:0;height:2px;}
.scd .lb{font-size:10px;color:var(--t3);text-transform:uppercase;letter-spacing:.08em;margin-bottom:6px;}
.scd .ct{font-size:32px;font-weight:800;line-height:1;}.scd .un{font-size:10px;color:var(--t3);margin-top:3px;}
.mc{background:var(--card);border:1px solid var(--bdr);border-radius:10px;padding:18px 20px;margin-bottom:20px;}
.mc .mt{font-size:11px;font-weight:700;color:var(--acc);text-transform:uppercase;letter-spacing:.1em;margin-bottom:10px;}
.mg{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:6px;font-size:12.5px;}
.mg .mk{color:var(--t3);min-width:85px;display:inline-block;}.mg .mv{color:var(--t2);font-family:var(--f2);font-size:11.5px;}
.fb{display:flex;gap:6px;margin-bottom:14px;flex-wrap:wrap;align-items:center;}
.fl{padding:5px 12px;border-radius:5px;font-size:11.5px;font-weight:600;border:1px solid var(--bdr);background:transparent;color:var(--t3);cursor:pointer;transition:all .12s;font-family:var(--f1);}
.fl:hover{border-color:var(--bdr2);color:var(--t2);}.fl.ac{border-color:var(--acc);background:var(--accg);color:var(--acc);}
.si{margin-left:auto;padding:5px 12px;border-radius:5px;border:1px solid var(--bdr);background:rgba(6,9,15,0.5);color:var(--t1);font-size:12px;width:200px;outline:none;font-family:var(--f2);}
.si:focus{border-color:var(--acc);box-shadow:0 0 0 3px var(--accg);}
.frow{background:var(--card);border:1px solid var(--bdr);border-radius:8px;margin-bottom:4px;cursor:pointer;transition:all .12s;overflow:hidden;}
.frow:hover{border-color:var(--bdr2);background:var(--card2);}
.fh{padding:10px 14px;display:flex;align-items:center;gap:10px;}
.dot{width:6px;height:6px;border-radius:50%;flex-shrink:0;}
.fsv{font-size:9.5px;font-weight:700;text-transform:uppercase;min-width:72px;}
.fn{font-weight:600;font-size:12.5px;color:#eef2f8;flex:1;}
.fc{font-size:10px;color:var(--t3);background:rgba(56,78,119,0.12);padding:1px 7px;border-radius:3px;}
.fdb{font-size:10.5px;color:var(--acc);background:var(--accg);padding:1px 7px;border-radius:3px;font-family:var(--f2);}
.fid{font-size:10px;color:var(--t3);font-family:var(--f2);}
.far{color:var(--t3);font-size:12px;transition:transform .2s;}
.frow.exp .far{transform:rotate(180deg);}
.fd{display:none;padding:0 14px 14px 28px;border-top:1px solid rgba(56,78,119,0.12);}
.frow.exp .fd{display:block;}
.ds{margin-top:10px;font-size:12.5px;line-height:1.6;}.ds .dl{color:var(--t3);}.ds .dv{color:var(--t2);}
.ab{background:rgba(56,176,96,0.06);border:1px solid rgba(56,176,96,0.15);border-radius:6px;padding:9px 12px;margin-top:10px;}
.ab .al{font-size:10px;font-weight:700;color:var(--ok);text-transform:uppercase;letter-spacing:.06em;}
.ab .av{font-size:12px;color:#6cd992;margin-top:2px;}
.es{text-align:center;padding:48px;color:var(--t3);font-size:13px;}
.ha{background:var(--card);border:1px solid rgba(240,72,72,0.2);border-radius:10px;padding:18px 20px;margin-bottom:20px;}
.ha .hat{font-size:11px;font-weight:700;color:var(--hi);text-transform:uppercase;letter-spacing:.1em;margin-bottom:10px;}
.hai{padding:8px 0;border-bottom:1px solid rgba(240,72,72,0.06);display:flex;gap:10px;align-items:flex-start;}
.hai:last-child{border-bottom:none;}
.had{color:var(--hi);font-size:8px;margin-top:5px;}
.han{font-weight:600;color:#eef2f8;font-size:12.5px;}
.hadl{color:var(--t2);font-size:11.5px;margin-top:1px;}
.ft{text-align:center;padding:24px;font-size:10.5px;color:var(--t3);border-top:1px solid var(--bdr);margin-top:32px;}
/* inventory-specific */
.inv-stats{display:flex;gap:12px;margin-bottom:16px;flex-wrap:wrap;}
.inv-stat{background:var(--card);border:1px solid var(--bdr);border-radius:8px;padding:10px 16px;display:flex;align-items:center;gap:8px;font-size:12.5px;}
.inv-stat .isc{font-weight:800;font-size:18px;}
.inv-stat .isl{color:var(--t3);}
.inv-row{background:var(--card);border:1px solid var(--bdr);border-radius:8px;margin-bottom:3px;overflow:hidden;cursor:pointer;transition:all .12s;}
.inv-row:hover{border-color:var(--bdr2);background:var(--card2);}
.inv-h{padding:9px 14px;display:flex;align-items:center;gap:10px;}
.inv-badge{font-size:9px;font-weight:700;text-transform:uppercase;padding:2px 8px;border-radius:3px;min-width:52px;text-align:center;}
.inv-badge-pass{background:rgba(56,176,96,0.12);color:var(--ok);}
.inv-badge-find{background:rgba(240,72,72,0.12);color:var(--hi);}
.inv-badge-err{background:rgba(232,160,32,0.12);color:var(--md);}
.inv-badge-skip{background:rgba(96,112,136,0.12);color:var(--inf);}
.inv-badge-info{background:rgba(91,138,245,0.1);color:var(--acc);}
.inv-name{font-weight:600;font-size:12.5px;color:#eef2f8;flex:1;}
.inv-cat{font-size:10px;color:var(--t3);background:rgba(56,78,119,0.12);padding:1px 7px;border-radius:3px;}
.inv-sev{font-size:9px;font-weight:700;text-transform:uppercase;}
.inv-id{font-size:10px;color:var(--t3);font-family:var(--f2);}
.inv-d{display:none;padding:0 14px 12px 14px;border-top:1px solid rgba(56,78,119,0.08);font-size:12.5px;line-height:1.6;color:var(--t2);}
.inv-row.exp .inv-d{display:block;}
.inv-d .idesc{margin-top:8px;}.inv-d .ifind{margin-top:6px;color:var(--t2);font-size:12px;}
.inv-d .ifind-item{padding:3px 0;border-bottom:1px solid rgba(56,78,119,0.06);}
.inv-d .ifind-item:last-child{border-bottom:none;}
.inv-d .ierr{margin-top:6px;color:var(--md);font-family:var(--f2);font-size:11px;}
.sp{width:18px;height:18px;border:2px solid rgba(255,255,255,0.2);border-top-color:#fff;border-radius:50%;animation:sp .6s linear infinite;display:inline-block;}
@keyframes sp{to{transform:rotate(360deg);}}
@keyframes fi{from{opacity:0;transform:translateY(8px);}to{opacity:1;transform:translateY(0);}}
.fi{animation:fi .3s ease;}
@media(max-width:768px){.sg{grid-template-columns:1fr;}.scs{grid-template-columns:repeat(2,1fr);}.fr{grid-template-columns:1fr;}}
</style>
</head>
<body>
<div class="hdr"><div class="lg"><div class="lm">K</div><div><div class="lt">KOVOCO</div><div class="ls">Security Assessment</div></div></div><div id="hs" class="hs hsd">DISCONNECTED</div></div>

<div id="CS" class="cs"><div class="cb fi">
<h2>Connect to SQL Server</h2><div class="st">No installation needed on the target. Checks run as read-only queries.</div>
<div id="CE" class="em"></div>
<div class="fg"><label>Server Instance</label><input type="text" id="SI" placeholder="SERVER1\INSTANCE or server1,1433" autofocus></div>
<div class="fg"><label>Authentication</label><select id="AT" onchange="document.getElementById('SA').style.display=this.value==='sql'?'block':'none'"><option value="windows">Windows Authentication</option><option value="sql">SQL Server Authentication</option></select></div>
<div id="SA" style="display:none"><div class="fr"><div class="fg"><label>Username</label><input type="text" id="SU" placeholder="sa"></div><div class="fg"><label>Password</label><input type="password" id="SP" placeholder="password"></div></div></div>
<div class="cr" onclick="this.querySelector('input').click()"><input type="checkbox" id="TC" onclick="event.stopPropagation()" checked><span>Trust server certificate (required for self-signed certs)</span></div>
<button class="btn bp" id="CB" onclick="run()">Run Security Assessment</button>
<div class="in">Requires sysadmin &middot; Nothing installed on target<br>Kovoco Security Engine v3.1</div>
</div></div>

<div id="DS" style="display:none"><div class="cnt fi">
<div class="tb">
  <button class="tt ac" onclick="tab('dash',this)">Dashboard</button>
  <button class="tt" onclick="tab('find',this)" id="TF">Findings</button>
  <button class="tt" onclick="tab('inv',this)" id="TI">Check Inventory</button>
  <button class="btn bo" style="margin-left:auto;font-size:11px;padding:5px 14px;" onclick="document.getElementById('CS').style.display='flex';document.getElementById('DS').style.display='none';document.getElementById('hs').className='hs hsd';document.getElementById('hs').textContent='DISCONNECTED';">New Assessment</button>
</div>

<div id="tab-dash">
  <div class="sg"><div class="sc"><div class="sl">Security Score</div><div class="sr"><svg viewBox="0 0 110 110" width="110" height="110"><circle cx="55" cy="55" r="48" fill="none" stroke="rgba(56,78,119,0.12)" stroke-width="7"/><circle id="SA2" cx="55" cy="55" r="48" fill="none" stroke="var(--acc)" stroke-width="7" stroke-dasharray="0 302" stroke-linecap="round" style="transition:stroke-dasharray .8s ease,stroke .8s ease;"/></svg><div class="sv"><span class="n" id="SN">-</span><span class="d">/ 100</span></div></div><div class="svr" id="SV"></div></div>
  <div class="scs">
    <div class="scd" onclick="cf='High';document.getElementById('TF').click();rF();"><div class="br" style="background:var(--hi)"></div><div class="lb">High</div><div class="ct" id="cH" style="color:var(--hi)">0</div><div class="un">findings</div></div>
    <div class="scd" onclick="cf='Medium';document.getElementById('TF').click();rF();"><div class="br" style="background:var(--md)"></div><div class="lb">Medium</div><div class="ct" id="cM" style="color:var(--md)">0</div><div class="un">findings</div></div>
    <div class="scd" onclick="cf='Low';document.getElementById('TF').click();rF();"><div class="br" style="background:var(--lo)"></div><div class="lb">Low</div><div class="ct" id="cL" style="color:var(--lo)">0</div><div class="un">findings</div></div>
    <div class="scd" onclick="cf='Information';document.getElementById('TF').click();rF();"><div class="br" style="background:var(--inf)"></div><div class="lb">Info</div><div class="ct" id="cI" style="color:var(--inf)">0</div><div class="un">findings</div></div>
  </div></div>
  <div class="mc"><div class="mt">Assessment Details</div><div class="mg" id="MG"></div></div>
  <div id="HA"></div>
</div>

<div id="tab-find" style="display:none"><div class="fb" id="FB"></div><div id="FL"></div></div>
<div id="tab-inv" style="display:none"><div id="IS"></div><div class="fb" id="IB"></div><div id="IL"></div></div>

<div class="ft">Kovoco SQL Server Security Assessment Engine v3.1</div>
</div></div>

<script>
var R=null,cf='All',st='',ex=null,ix=null,ivf='All';
var SV={High:{c:'var(--hi)',w:4},Medium:{c:'var(--md)',w:3},Low:{c:'var(--lo)',w:2},Information:{c:'var(--inf)',w:1}};
function E(s){if(!s)return'';return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
function tab(id,b){document.querySelectorAll('[id^="tab-"]').forEach(function(t){t.style.display='none';});document.getElementById('tab-'+id).style.display='block';document.querySelectorAll('.tt').forEach(function(x){x.classList.remove('ac');});b.classList.add('ac');}

function run(){
  var btn=document.getElementById('CB'),err=document.getElementById('CE');err.style.display='none';
  var p={serverInstance:document.getElementById('SI').value.trim(),authType:document.getElementById('AT').value,sqlUser:document.getElementById('SU').value.trim(),sqlPass:document.getElementById('SP').value,trustCert:document.getElementById('TC').checked};
  if(!p.serverInstance){err.textContent='Please enter a server instance.';err.style.display='block';return;}
  if(p.authType==='sql'&&!p.sqlUser){err.textContent='Enter a username for SQL auth.';err.style.display='block';return;}
  btn.disabled=true;btn.innerHTML='<span class="sp"></span> Running security checks...';
  fetch('/api/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(p)})
  .then(function(r){return r.json();}).then(function(d){if(!d.success)throw new Error(d.error||'Failed');R=d;show();})
  .catch(function(e){err.textContent=e.message;err.style.display='block';})
  .finally(function(){btn.disabled=false;btn.innerHTML='Run Security Assessment';});
}

function show(){
  document.getElementById('CS').style.display='none';document.getElementById('DS').style.display='block';
  var h=document.getElementById('hs');h.className='hs hsc';h.textContent=R.metadata.serverInstance||'CONNECTED';
  cf='All';st='';ex=null;ix=null;ivf='All';rS();rM();rH();rF();rI();
  document.querySelectorAll('[id^="tab-"]').forEach(function(t){t.style.display='none';});
  document.getElementById('tab-dash').style.display='block';
  document.querySelectorAll('.tt').forEach(function(b){b.classList.remove('ac');});document.querySelector('.tt').classList.add('ac');
}

function rS(){
  var s=R.summary;
  document.getElementById('cH').textContent=s.High||0;document.getElementById('cM').textContent=s.Medium||0;
  document.getElementById('cL').textContent=s.Low||0;document.getElementById('cI').textContent=s.Information||0;
  var dd=(s.High||0)*15+(s.Medium||0)*5+(s.Low||0)*1,sc=Math.max(0,Math.min(100,100-dd)),ci=2*Math.PI*48;
  var clr=sc>=80?'var(--ok)':sc>=50?'var(--md)':'var(--hi)';
  var a=document.getElementById('SA2');a.setAttribute('stroke',clr);a.setAttribute('stroke-dasharray',(sc/100)*ci+' '+ci);
  document.getElementById('SN').textContent=sc;document.getElementById('SN').style.color=clr;
  document.getElementById('SV').textContent=sc>=80?'Good posture':sc>=50?'Needs attention':'Critical issues found';
  document.getElementById('TF').textContent='Findings ('+R.findings.length+')';
  var inv=R.checkResults||[];
  document.getElementById('TI').textContent='Check Inventory ('+inv.length+')';
}

function rM(){
  var m=R.metadata;
  document.getElementById('MG').innerHTML=[['Generated',m.generatedAt],['Instance',m.serverInstance],['Version',m.sqlVersion],['Checks',m.checksRun],['Executed By',m.executedBy],['Duration',m.duration]].map(function(kv){return '<div><span class="mk">'+kv[0]+':</span> <span class="mv">'+E(kv[1]||'-')+'</span></div>';}).join('');
}

function rH(){
  var h=R.findings.filter(function(f){return f.severity==='High';});
  if(!h.length){document.getElementById('HA').innerHTML='';return;}
  document.getElementById('HA').innerHTML='<div class="ha"><div class="hat">High Severity - Immediate Action Required</div>'+h.slice(0,8).map(function(f){return '<div class="hai"><span class="had">&#9679;</span><div><div class="han">'+E(f.name)+'</div><div class="hadl">'+E(f.details)+'</div></div></div>';}).join('')+'</div>';
}

function rF(){
  var ff=R.findings,counts={All:ff.length,High:0,Medium:0,Low:0,Information:0};
  ff.forEach(function(f){counts[f.severity]=(counts[f.severity]||0)+1;});
  document.getElementById('FB').innerHTML=['All','High','Medium','Low','Information'].map(function(s){return '<button class="fl '+(cf===s?'ac':'')+'" onclick="cf=\''+s+'\';rF();">'+s+' ('+counts[s]+')</button>';}).join('')+'<input class="si" placeholder="Search..." value="'+E(st)+'" oninput="st=this.value;rF();">';
  var fil=ff.filter(function(f){if(cf!=='All'&&f.severity!==cf)return false;if(st){var t=st.toLowerCase();return[f.name,f.details,f.databaseName,f.actionStep,f.category].filter(Boolean).some(function(v){return v.toLowerCase().indexOf(t)>=0;});}return true;});
  fil.sort(function(a,b){return(SV[b.severity]?SV[b.severity].w:0)-(SV[a.severity]?SV[a.severity].w:0);});
  if(!fil.length){document.getElementById('FL').innerHTML='<div class="es">No findings match your filters.</div>';return;}
  document.getElementById('FL').innerHTML=fil.map(function(f,i){var c=SV[f.severity]||SV.Information;var id='f'+i+f.checkId;var x=ex===id;
    return '<div class="frow '+(x?'exp':'')+'" onclick="ex=ex===\''+id+'\'?null:\''+id+'\';rF();"><div class="fh"><div class="dot" style="background:'+c.c+'"></div><span class="fsv" style="color:'+c.c+'">'+f.severity+'</span><span class="fn">'+E(f.name)+'</span><span class="fc">'+E(f.category)+'</span>'+(f.databaseName?'<span class="fdb">'+E(f.databaseName)+'</span>':'')+'<span class="fid">#'+f.checkId+'</span><span class="far">&#9660;</span></div><div class="fd"><div class="ds"><span class="dv">'+E(f.details)+'</span></div>'+(f.actionStep?'<div class="ab"><div class="al">Recommended Action</div><div class="av">'+E(f.actionStep)+'</div></div>':'')+'</div></div>';
  }).join('');
}

function rI(){
  var inv=R.checkResults||[];
  var counts={All:inv.length,Passed:0,Finding:0,Error:0,Skipped:0,Info:0};
  inv.forEach(function(c){counts[c.outcome]=(counts[c.outcome]||0)+1;});
  // stats bar
  document.getElementById('IS').innerHTML='<div class="inv-stats">'+
    '<div class="inv-stat"><span class="isc" style="color:var(--ok)">'+counts.Passed+'</span><span class="isl">Passed</span></div>'+
    '<div class="inv-stat"><span class="isc" style="color:var(--hi)">'+(counts.Finding||0)+'</span><span class="isl">Findings</span></div>'+
    '<div class="inv-stat"><span class="isc" style="color:var(--md)">'+(counts.Error||0)+'</span><span class="isl">Errors</span></div>'+
    '<div class="inv-stat"><span class="isc" style="color:var(--inf)">'+(counts.Skipped||0)+'</span><span class="isl">Skipped</span></div>'+
    '<div class="inv-stat"><span class="isc" style="color:var(--acc)">'+(counts.Info||0)+'</span><span class="isl">Info</span></div>'+
    '</div>';
  // filter bar
  document.getElementById('IB').innerHTML=['All','Passed','Finding','Error','Skipped','Info'].map(function(s){return '<button class="fl '+(ivf===s?'ac':'')+'" onclick="ivf=\''+s+'\';rI();">'+s+' ('+(counts[s]||0)+')</button>';}).join('');
  // list
  var fil=inv.filter(function(c){return ivf==='All'||c.outcome===ivf;});
  if(!fil.length){document.getElementById('IL').innerHTML='<div class="es">No checks match this filter.</div>';return;}
  var bcls={Passed:'inv-badge-pass',Finding:'inv-badge-find',Error:'inv-badge-err',Skipped:'inv-badge-skip',Info:'inv-badge-info'};
  var scls={High:'var(--hi)',Medium:'var(--md)',Low:'var(--lo)',Information:'var(--inf)'};
  document.getElementById('IL').innerHTML=fil.map(function(c,i){
    var id='iv'+i+c.checkId;var x=ix===id;
    return '<div class="inv-row '+(x?'exp':'')+'" onclick="ix=ix===\''+id+'\'?null:\''+id+'\';rI();">'+
      '<div class="inv-h">'+
        '<span class="inv-badge '+(bcls[c.outcome]||'inv-badge-skip')+'">'+c.outcome+'</span>'+
        '<span class="inv-name">'+E(c.name)+'</span>'+
        '<span class="inv-cat">'+E(c.category)+'</span>'+
        '<span class="inv-sev" style="color:'+(scls[c.severity]||'var(--inf)')+'">'+E(c.severity)+'</span>'+
        '<span class="inv-id">#'+c.checkId+'</span>'+
        '<span class="far">&#9660;</span>'+
      '</div>'+
      '<div class="inv-d">'+
        '<div class="idesc"><strong style="color:var(--t3)">What this checks:</strong> '+E(c.description)+'</div>'+
        (c.findingCount>0?'<div class="ifind"><strong style="color:var(--hi)">'+c.findingCount+' finding(s):</strong>'+c.findingDetails.map(function(d){return '<div class="ifind-item">'+E(d)+'</div>';}).join('')+'</div>':'')+
        (c.outcome==='Passed'?'<div style="margin-top:6px;color:var(--ok);font-size:12px;">&#10003; No issues detected for this check.</div>':'')+
        (c.outcome==='Error'?'<div class="ierr">Error: '+E(c.errorMessage)+'</div>':'')+
        (c.outcome==='Skipped'?'<div style="margin-top:6px;color:var(--inf);font-size:12px;">Skipped: SQL Server version too old for this check.</div>':'')+
      '</div></div>';
  }).join('');
}
</script>
</body>
</html>
'@


# ============================================================================
# SERVER + ENGINE
# ============================================================================
$url = "http://localhost:$Port/"
$listener = New-Object System.Net.HttpListener
$listener.Prefixes.Add($url)
try { $listener.Start() } catch { Write-Host "  [X] Port $Port failed: $($_.Exception.Message)" -ForegroundColor Red; exit 1 }
Write-Host "  [+] Running at " -NoNewline -ForegroundColor Green; Write-Host $url -ForegroundColor Cyan
Write-Host "  [*] Ctrl+C to stop.`n" -ForegroundColor DarkGray
if (-not $NoBrowser) { Start-Process $url }

function Invoke-KovocoAssessment {
    param($Body)
    $sw = Get-Date
    $p = $Body | ConvertFrom-Json

    $cp = @{ ServerInstance=$p.serverInstance; Database="master"; QueryTimeout=300 }
    if ($p.trustCert) { $cp["TrustServerCertificate"] = $true }
    if ($p.authType -eq "sql") {
        $cp["Credential"] = New-Object PSCredential($p.sqlUser, (ConvertTo-SecureString $p.sqlPass -AsPlainText -Force))
    }

    $ii = Invoke-Sqlcmd @cp -Query "SELECT @@SERVERNAME AS SN, SYSTEM_USER AS EU, CAST(SERVERPROPERTY('ProductVersion') AS NVARCHAR(128)) AS Ver, CAST(SERVERPROPERTY('Edition') AS NVARCHAR(128)) AS Ed, CAST(SERVERPROPERTY('ProductMajorVersion') AS INT) AS MV"
    Write-Host "  [+] Connected: $($ii.SN) ($($ii.Ver))" -ForegroundColor Green

    $sa = Invoke-Sqlcmd @cp -Query "SELECT IS_SRVROLEMEMBER('sysadmin') AS V"
    if ($sa.V -ne 1) { throw "Not a sysadmin. Kovoco requires sysadmin for a complete assessment." }

    $findings = @()
    $checkResults = @()
    $summary = @{ High=0; Medium=0; Low=0; Information=0 }
    $cRun=0; $cSkip=0; $cErr=0; $cPass=0; $cFind=0

    foreach ($chk in $script:SecurityChecks) {
        $minV = if ($chk.minVersion) { $chk.minVersion } else { 13 }

        # Version skip
        if ($ii.MV -lt $minV) {
            $cSkip++
            $checkResults += @{
                checkId=$chk.id; name=$chk.name; category=$chk.category; severity=$chk.severity
                description=$chk.description; outcome="Skipped"; findingCount=0; findingDetails=@(); errorMessage=$null
            }
            continue
        }

        $cRun++
        try {
            $rows = @(Invoke-Sqlcmd @cp -Query $chk.query -ErrorAction Stop)
            $validRows = @($rows | Where-Object { $_.details -and -not [string]::IsNullOrWhiteSpace($_.details) })
            $fDetails = @()

            if ($validRows.Count -gt 0 -and $chk.severity -ne "Information") {
                $cFind++
                foreach ($r in $validRows) {
                    $sev = $chk.severity
                    if ($summary.ContainsKey($sev)) { $summary[$sev]++ }
                    $fDetails += [string]$r.details
                    $findings += @{
                        checkId=$chk.id; name=$chk.name; category=$chk.category; severity=$sev
                        details=[string]$r.details
                        actionStep=if($r.actionStep){[string]$r.actionStep}else{$null}
                        databaseName=if($r.PSObject.Properties['databaseName']-and$r.databaseName){[string]$r.databaseName}else{$null}
                    }
                }
                $checkResults += @{
                    checkId=$chk.id; name=$chk.name; category=$chk.category; severity=$chk.severity
                    description=$chk.description; outcome="Finding"; findingCount=$validRows.Count; findingDetails=$fDetails; errorMessage=$null
                }
            }
            elseif ($chk.severity -eq "Information") {
                # Info checks always report
                foreach ($r in $validRows) {
                    $summary["Information"]++
                    $fDetails += [string]$r.details
                    $findings += @{
                        checkId=$chk.id; name=$chk.name; category=$chk.category; severity="Information"
                        details=[string]$r.details
                        actionStep=if($r.actionStep){[string]$r.actionStep}else{$null}
                        databaseName=$null
                    }
                }
                $checkResults += @{
                    checkId=$chk.id; name=$chk.name; category=$chk.category; severity="Information"
                    description=$chk.description; outcome="Info"; findingCount=$fDetails.Count; findingDetails=$fDetails; errorMessage=$null
                }
            }
            else {
                $cPass++
                $checkResults += @{
                    checkId=$chk.id; name=$chk.name; category=$chk.category; severity=$chk.severity
                    description=$chk.description; outcome="Passed"; findingCount=0; findingDetails=@(); errorMessage=$null
                }
            }
        }
        catch {
            $cErr++
            Write-Host "  [!] #$($chk.id) $($chk.name): $($_.Exception.Message)" -ForegroundColor Yellow
            $checkResults += @{
                checkId=$chk.id; name=$chk.name; category=$chk.category; severity=$chk.severity
                description=$chk.description; outcome="Error"; findingCount=0; findingDetails=@(); errorMessage=$_.Exception.Message
            }
        }
    }

    $el = (Get-Date) - $sw
    $statsText = "$cRun executed, $cPass passed, $cFind with findings, $cErr errors, $cSkip skipped"

    return @{
        success=$true
        metadata=@{
            toolName="Kovoco SQL Server Security Assessment"; toolVersion=$KovocoVersion
            generatedAt=(Get-Date).ToString("yyyy-MM-ddTHH:mm:ss"); serverInstance=$p.serverInstance
            sqlVersion="$($ii.Ver) ($($ii.Ed))"; executedBy=[string]$ii.EU
            checksRun=$statsText; duration="$([math]::Round($el.TotalSeconds,1))s"
        }
        summary=$summary; findings=$findings; checkResults=$checkResults
    }
}

# Register Ctrl+C handler to cleanly shut down the listener
[Console]::TreatControlCAsInput = $false
$script:keepRunning = $true
$null = Register-EngineEvent -SourceIdentifier PowerShell.Exiting -Action { $script:keepRunning = $false } -ErrorAction SilentlyContinue

try {
    while ($script:keepRunning -and $listener.IsListening) {
        # Use async BeginGetContext so we can poll for Ctrl+C
        $asyncResult = $listener.BeginGetContext($null, $null)

        # Poll every 500ms — allows Ctrl+C to break the loop
        while (-not $asyncResult.AsyncWaitHandle.WaitOne(500)) {
            if (-not $script:keepRunning) { break }
            # Check if [Console]::KeyAvailable works (won't in ISE, but fine)
            try {
                if ([Console]::KeyAvailable) {
                    $key = [Console]::ReadKey($true)
                    if ($key.Key -eq 'C' -and $key.Modifiers -eq 'Control') {
                        $script:keepRunning = $false
                        break
                    }
                }
            } catch {}
        }

        if (-not $script:keepRunning) { break }

        $ctx = $listener.EndGetContext($asyncResult)
        $req = $ctx.Request; $rsp = $ctx.Response

        try {
            if ($req.Url.AbsolutePath -eq "/" -and $req.HttpMethod -eq "GET") {
                $buf = [Text.Encoding]::UTF8.GetBytes($HTML_DASHBOARD)
                $rsp.ContentType = "text/html; charset=utf-8"
                $rsp.ContentLength64 = $buf.Length
                $rsp.OutputStream.Write($buf, 0, $buf.Length)
                Write-Host "  [>] Dashboard served" -ForegroundColor DarkGray
            }
            elseif ($req.Url.AbsolutePath -eq "/api/run" -and $req.HttpMethod -eq "POST") {
                $rd = New-Object IO.StreamReader($req.InputStream); $body = $rd.ReadToEnd(); $rd.Close()
                Write-Host "  [>] Assessment starting..." -ForegroundColor Cyan
                try {
                    $res = Invoke-KovocoAssessment -Body $body
                    $j = $res | ConvertTo-Json -Depth 10 -Compress
                    Write-Host "  [+] Done: $($res.metadata.checksRun)" -ForegroundColor Green
                }
                catch {
                    $j = (@{ success = $false; error = $_.Exception.Message } | ConvertTo-Json -Compress)
                    Write-Host "  [X] $($_.Exception.Message)" -ForegroundColor Red
                }
                $buf = [Text.Encoding]::UTF8.GetBytes($j)
                $rsp.ContentType = "application/json; charset=utf-8"
                $rsp.ContentLength64 = $buf.Length
                $rsp.OutputStream.Write($buf, 0, $buf.Length)
            }
            else {
                $rsp.StatusCode = 404
                $buf = [Text.Encoding]::UTF8.GetBytes("Not Found")
                $rsp.ContentLength64 = $buf.Length
                $rsp.OutputStream.Write($buf, 0, $buf.Length)
            }
        }
        catch {
            Write-Host "  [X] $($_.Exception.Message)" -ForegroundColor Red
            try {
                $rsp.StatusCode = 500
                $buf = [Text.Encoding]::UTF8.GetBytes((@{ error = $_.Exception.Message } | ConvertTo-Json -Compress))
                $rsp.ContentType = "application/json"
                $rsp.ContentLength64 = $buf.Length
                $rsp.OutputStream.Write($buf, 0, $buf.Length)
            } catch {}
        }
        finally {
            $rsp.OutputStream.Close()
        }
    }
}
finally {
    Write-Host "`n  [*] Shutting down web server..." -ForegroundColor Yellow
    try { $listener.Stop() } catch {}
    try { $listener.Close() } catch {}
    Write-Host "  [+] Server stopped. Back to prompt." -ForegroundColor Green
}
