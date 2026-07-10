# 01 · Recon & Enumeration

The goal is a complete, trustworthy map of the reachable attack surface. Enumeration is finished
only when each relevant service has an evidence-backed next step or a documented reason to defer
it. Start from the [standalone foothold loop](00-standalone-foothold-loop.md), and return here after
every new hostname, credential, authentication state, or network position.

> 💡 A fast scan is a lead generator, not ground truth. Verify surprising results with a second
> method and distinguish “no finding” from timeout, protocol mismatch, authentication failure, or
> tool error.

---

## 1.1 First steps and naming

- Record the target, scope, VPN interface, start time, and expected objective.
- Keep scan output, raw HTTP requests, downloaded files, and screenshots per target.
- Add every hostname learned from redirects, certificates, banners, email addresses, DNS, page
  content, or configuration files. Name-based routing and Kerberos depend on correct resolution.

```bash
mkdir -p scans web files
echo '<ip>  target.local app.target.local' | sudo tee -a /etc/hosts
getent hosts target.local app.target.local
```

Do not collapse hostnames that share an IP. Each hostname may expose a different web application.

## 1.2 Host discovery (only when scope contains a range)

```bash
nmap -sn <range>/24 -oA scans/sweep
sudo nmap -PR -sn <range>/24 -oA scans/arp-sweep   # same L2 segment only
```

> 💡 If scope says a host exists, scan it directly with `-Pn`. Firewalls commonly drop discovery
> probes, so “host seems down” is not proof that the target is absent.

## 1.3 TCP and UDP scanning

Run discovery lanes in parallel and begin interacting with early results.

```bash
# Fast orientation
sudo nmap -n -Pn -sS --top-ports 1000 -T4 --max-retries 2 \
  -oA scans/tcp-quick <ip>

# Full TCP range
sudo nmap -n -Pn -sS -p- -T4 --min-rate 1000 --max-retries 2 \
  -oA scans/tcp-full <ip>

# Focused version and default-script pass on ports actually found
sudo nmap -n -Pn -sC -sV -p <tcp-ports> --reason \
  -oA scans/tcp-services <ip>

# UDP first pass; version detection can resolve some open|filtered results
sudo nmap -n -Pn -sU --top-ports 100 -sV --version-light -T3 --reason \
  -oA scans/udp-top100 <ip>
```

If the full scan returns unexpectedly few ports, a service times out, or scan runs disagree, remove
the aggressive minimum rate and verify more conservatively:

```bash
sudo nmap -n -Pn -sS -p- -T3 --max-retries 3 --reason \
  -oA scans/tcp-verify <ip>
sudo nmap -n -Pn -p <unknown-ports> -sV --version-all --reason \
  --script=banner,ssl-cert -oA scans/unknown-deep <ip>
```

Expand UDP when TCP and the first UDP pass do not explain the machine:

```bash
sudo nmap -n -Pn -sU --top-ports 1000 -T3 --reason \
  -oA scans/udp-top1000 <ip>
sudo nmap -n -Pn -sU -sV -sC -p <udp-ports> --reason \
  -oA scans/udp-services <ip>
```

⛔ Do not run NSE `dos`, `exploit`, `brute`, or other intrusive categories merely because they
exist. Select scripts whose behavior you understand and that remain inside the authorized scope.

## 1.4 Validate every open service

Do not trust the registered port name. A web server can listen on 22 and SSH can listen on 8080.

```bash
nc -nv <ip> <port>                         # plaintext banner / manual protocol
openssl s_client -connect <ip>:<port> -servername <hostname> </dev/null
curl -skiv --max-time 10 http://<ip>:<port>/
curl -skiv --max-time 10 https://<hostname>:<port>/
```

For each service, record:

- actual protocol, product, version/build, OS clues, hostname/domain, and authentication method;
- anonymous/guest/no-auth and known-credential results;
- list/read/write/query/execute capabilities;
- exact error or denial, including whether the failure came from transport, TLS, protocol, auth,
  or permissions;
- one next decisive test and the prerequisite it checks.

Rank a proven anonymous read, writable share, upload, hidden vhost, or exact vulnerable component
above a generic banner and speculative exploit.

## 1.5 HTTP / HTTPS

Treat every `(scheme, hostname, port)` and every authentication state as a separate origin.

### Baseline each origin

```bash
whatweb -a 3 <url>
curl -sk -D web/root.headers -o web/root.body <url>/
curl -sk -o /dev/null \
  -w 'code=%{http_code} bytes=%{size_download} redirect=%{redirect_url} time=%{time_total}\n' \
  <url>/
curl -skI <url>/
curl -sk -X OPTIONS -i <url>/
nikto -h <url>/ -output web/nikto.txt
```

For TLS, collect certificate names and retest them as hostnames:

```bash
openssl s_client -connect <ip>:<port> -servername <hostname> </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -issuer -ext subjectAltName

# Force both destination IP and correct Host/SNI without changing DNS
curl -sk --resolve <hostname>:<port>:<ip> https://<hostname>:<port>/
```

Browse normally through Burp Community before fuzzing. Exercise login, registration, password
reset, search, upload, import/export, preview, profile, admin, and API workflows. Save raw requests
and record method, content type, cookies, CSRF tokens, hidden fields, JSON/XML keys, filenames,
custom headers, IDs, and redirects.

### Read the application before brute discovery

```bash
curl -sk <url>/robots.txt
curl -sk <url>/sitemap.xml
curl -sk <url>/.well-known/security.txt
curl -sk <url>/.git/HEAD
curl -sk <url>/.env
```

- Inspect HTML comments, linked JavaScript, source maps (`.js.map`), manifests, API base URLs,
  debug output, stack traces, cookie names, and generator metadata.
- Search downloaded JS for routes, parameter names, hostnames, credentials, feature flags, and
  source-map references. Verify findings manually; minified strings include false positives.
- Recurse from every interesting directory. `/admin/`, `/api/`, and `/app/` are new discovery
  roots, not completed findings.
- Record `401`, `403`, `405`, and `500` paths. They prove routing and often reveal an auth boundary,
  alternate method, or parser.

### Content discovery with a calibrated baseline

First request several random nonexistent paths and note status, size, redirect target, and dynamic
variation. Many apps return a soft `200` for everything.

```bash
curl -sk -o /dev/null \
  -w 'code=%{http_code} bytes=%{size_download} redirect=%{redirect_url}\n' \
  <url>/definitely-not-a-real-path-7f3a

ffuf -u <url>/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  -ac -mc all -e .php,.asp,.aspx,.jsp,.txt,.bak,.old,.zip,.tar.gz,.conf,.config \
  -o web/ffuf-root.json -of json

feroxbuster -u <url>/ \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  -x php,asp,aspx,jsp,txt,bak,old,zip -d 2 -o web/ferox-root.txt
```

If calibration hides a real result, replace `-ac` with explicit filters based on several invalid
controls (`-fs`, `-fw`, `-fl`, `-fc`). Do not restrict matches to only `200/301/302/403`; useful
responses also include `204`, `307/308`, `401`, `405`, and `500`.

Choose extensions from the observed stack. Test backup transformations of known files, such as
`index.php.bak`, `web.config.old`, `appsettings.json~`, and archived source, instead of only adding
extensions to random words.

### Virtual hosts and hostname routing

```bash
# Learn the default invalid-host response first
baseline=$(curl -sk -H 'Host: invalid.target.local' -o /dev/null \
  -w '%{size_download}' http://<ip>:<port>/)

ffuf -u http://<ip>:<port>/ \
  -H 'Host: FUZZ.target.local' \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt \
  -mc all -fs "$baseline" -o web/ffuf-vhosts.json -of json
```

Add each hit to `/etc/hosts`, browse it, and repeat content discovery. For HTTPS, retest with the
correct SNI using `--resolve`; a Host header sent through the default TLS vhost can miss an
SNI-gated application.

### Parameters, raw requests, and authenticated discovery

```bash
# GET parameter names
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt:PARAM \
  -u '<url>/endpoint?PARAM=probe' -ac -mc all

# Form parameter names
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt:PARAM \
  -u <url>/endpoint -X POST -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'PARAM=probe' -ac -mc all

# Preserve method, cookies, headers, JSON, and CSRF from Burp: put FUZZ in a saved request
ffuf -request web/request.txt -request-proto https -w <wordlist> -ac -mc all
```

Form, JSON, XML, and multipart bodies are different parser surfaces. Replay the exact working
request before changing a parameter; do not assume every POST is form-urlencoded.

### API, GraphQL, and CMS discovery

Check application-referenced paths first, then common documentation endpoints:

```bash
for p in openapi.json swagger.json api-docs swagger-ui graphql; do
  curl -sk -o /dev/null -w "$p  %{http_code}  %{size_download}\n" <url>/$p
done

# Harmless GraphQL parser check
curl -sk <url>/graphql -H 'Content-Type: application/json' \
  --data '{"query":"{__typename}"}'
```

- Map API versions, methods, content types, nested JSON objects, IDs, authorization headers, and
  role-sensitive operations. Retest as guest and authenticated users.
- Identify CMS core, theme, plugin/module, and exact version independently. Inspect public readme,
  changelog, assets, API output, and page source; then verify a candidate PoC's prerequisites.
- Enumeration modes of `wpscan`, `droopescan`, or similar tools can accelerate a known product,
  but understand the selected options and re-check current exam tool rules.

Move mapped inputs to [§02 Web Attacks](02-web-attacks.md).

## 1.6 SMB and MSRPC (139/445)

Try null and guest explicitly, then repeat the relevant checks with each safely testable
credential.

```bash
enum4linux-ng -A <ip>
smbclient -N -L //<ip>
smbmap -H <ip>
netexec smb <ip> -u '' -p '' --shares
netexec smb <ip> -u guest -p '' --shares

rpcclient -U '' -N <ip>
# rpcclient> enumdomusers
# rpcclient> querydispinfo
# rpcclient> enumdomgroups
# rpcclient> getdompwinfo
```

With credentials, do not keep the anonymous `-N` flag:

```bash
smbclient -L //<ip> -U '<domain>/<user>'
smbclient //<ip>/<share> -U '<domain>/<user>' \
  -c 'recurse ON; prompt OFF; mget *'
netexec smb <ip> -u <user> -p '<pass>' --shares
netexec smb <ip> -u <user> -p '<pass>' --rid-brute
```

Search downloaded shares for deployment scripts, backups, configs, connection strings, keys,
password databases, unattended files, and alternate hostnames. If a share appears writable, use a
uniquely named inert marker, verify the consumer/path relationship, and remove only your own file.

Before any spraying, determine lockout threshold, observation window, and reset behavior. A spray
can still lock accounts.

## 1.7 LDAP and Kerberos (389/636/3268/3269, 88)

Discover the directory base from RootDSE instead of guessing it:

```bash
ldapsearch -x -H ldap://<ip> -s base -b '' \
  namingContexts defaultNamingContext dnsHostName supportedSASLMechanisms

ldapsearch -x -H ldap://<ip> -b '<base-dn>' \
  '(objectClass=*)' '*' '+'

# Credentialed bind; -W prompts instead of placing the password in shell history
ldapsearch -x -H ldap://<ip> -D '<domain>\<user>' -W -b '<base-dn>' \
  '(objectClass=*)' sAMAccountName memberOf description servicePrincipalName
```

Repeat with `ldaps://` when 636 is open. Distinguish an invalid base, failed bind, TLS problem, and
a genuinely empty search.

Port 88 identifies a Kerberos KDC; in a Windows domain it is a strong domain-controller clue, not
proof by itself. Once the domain and user set are known, pivot to
[§08 Active Directory](08-active-directory.md).

## 1.8 FTP and TFTP (21, 69/udp)

```bash
nmap -n -Pn -p21 --script ftp-anon,ftp-syst <ip>
ftp <ip>                         # anonymous / blank or email-style password
curl -v --user 'anonymous:anonymous@' ftp://<ip>/
```

Inside FTP, check `SYST`, `STAT`, `PWD`, passive mode, binary mode, directory permissions, and
recursive content. Test upload only with an inert marker and delete that marker if permitted.
Map a writable directory to HTTP, a scheduled consumer, configuration loader, or another service;
write access alone is not code execution.

TFTP has no directory listing or authentication, so retrieve only plausible, evidence-backed
filenames:

```bash
tftp <ip> -c get <known-filename>
```

## 1.9 SSH (22 and non-standard ports)

```bash
nmap -n -Pn -p<port> -sV --script ssh-hostkey,ssh-auth-methods \
  --script-args 'ssh.user=<candidate-user>' <ip>
ssh -vv -p <port> <user>@<ip>
```

SSH is usually a destination for a recovered password or private key. Record supported auth,
host keys, banner/OS clues, and username-dependent behavior; do not default to broad brute force.
Nmap classifies `ssh-auth-methods` as intrusive because it begins an authentication attempt, so use
one evidence-backed username and expect the connection to be logged.

## 1.10 SMTP, POP3, and IMAP (25/465/587, 110/995, 143/993)

Plain SMTP and STARTTLS:

```bash
nc -nv <ip> 25
# EHLO target.local
# HELP
# VRFY <user>
# EXPN <list>

openssl s_client -starttls smtp -connect <ip>:587 -crlf
openssl s_client -connect <ip>:465 -crlf
```

Where permitted, `smtp-user-enum` can validate a small evidence-backed username list. Do not turn
enumeration into relay abuse, mass mail, or phishing.

With recovered credentials, enumerate mailbox capability and content:

```bash
openssl s_client -connect <ip>:993 -crlf       # IMAPS
# a1 CAPABILITY
# a2 LOGIN <user> <pass>
# a3 LIST "" "*"

openssl s_client -connect <ip>:995 -crlf       # POP3S
# USER <user>
# PASS <pass>
# LIST
```

Mail often supplies password-reset links, usernames, hostnames, and service credentials.

## 1.11 DNS (53 TCP/UDP)

```bash
dig @<ip> <domain> SOA
dig @<ip> <domain> NS
dig @<ip> <domain> A
dig @<ip> <domain> AAAA
dig @<ip> <domain> MX
dig @<ip> <domain> TXT
dig @<ip> <domain> ANY             # optional hint; not a complete enumeration method
dig @<ip> -x <target-ip>
dig @<ip> <domain> AXFR            # repeat against every authoritative nameserver
```

Extract hostnames and add them to the surface map. A refused AXFR is a completed test; a timeout or
wrong server/domain is not.

## 1.12 SNMP (161/udp)

```bash
onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp.txt <ip>
snmpwalk -v2c -c <community> <ip> 1.3.6.1.2.1.1                 # system
snmpwalk -v2c -c <community> <ip> 1.3.6.1.2.1.25.4.2.1.2      # process names
snmpwalk -v2c -c <community> <ip> 1.3.6.1.2.1.25.4.2.1.5      # process args
snmpwalk -v2c -c <community> <ip> 1.3.6.1.2.1.25.6.3.1.2      # installed software
snmp-check -c <community> <ip>
```

Try v1 if v2c fails. Use numeric OIDs (`-On`) when MIB names are unavailable. Enumerate system
description, interfaces, routes, listeners, users, processes/arguments, software, and storage.
`NET-SNMP-EXTEND-MIB` is valuable only when administrators configured extend entries; it is not a
general process listing.

## 1.13 RPC, NFS, and rsync (111/2049, 873)

```bash
rpcinfo -p <ip>
showmount -e <ip>
sudo mkdir -p /mnt/nfs-probe
sudo mount -t nfs -o ro,nolock <ip>:/<export> /mnt/nfs-probe
findmnt /mnt/nfs-probe
```

Review ownership, numeric UIDs/GIDs, keys, configs, backups, and export layout. Confirm export
options before treating `no_root_squash` or writable content as an escalation path.

```bash
rsync --list-only rsync://<ip>/
rsync --list-only rsync://<ip>/<module>/
rsync -av rsync://<ip>/<module>/ files/rsync/
```

Anonymous rsync modules can expose source, backups, credentials, or deployment paths. Test writes
only with a harmless marker and a proven reason.

## 1.14 Databases and data services

Start read-only: identify version, current identity/role, databases/schemas, privileges, and data
that can create another access path. File write or command execution always has privilege and
configuration prerequisites.

```bash
# MySQL / MariaDB
mysql -h <ip> -u <user> -p
# SELECT VERSION(), USER(), CURRENT_USER(), DATABASE();
# SHOW DATABASES; SHOW GRANTS;

# PostgreSQL
psql -h <ip> -U <user> -d postgres
# SELECT version(), current_user, current_database();
# \l   \du+   \dn   \dt *.*

# MSSQL: SQL authentication vs Windows authentication
impacket-mssqlclient '<user>:<pass>@<ip>'
impacket-mssqlclient '<domain>/<user>:<pass>@<ip>' -windows-auth
# SELECT @@version; SELECT SYSTEM_USER; SELECT IS_SRVROLEMEMBER('sysadmin');

# Redis: no-auth/known credential, then read-only triage
redis-cli -h <ip> PING
redis-cli -h <ip> INFO server
redis-cli -h <ip> INFO keyspace
redis-cli -h <ip> ACL WHOAMI
redis-cli -h <ip> --scan

# MongoDB
mongosh 'mongodb://<ip>:27017/'
```

Search application configs for the exact database credential before brute force. See
[§02.5 SQL injection](02-web-attacks.md#25-sql-injection) for database-to-foothold preconditions.

## 1.15 Other high-signal services

### WebDAV and alternate HTTP methods

```bash
curl -sk -X OPTIONS -i <url>/
curl -sk -X PROPFIND -H 'Depth: 1' <url>/
```

If DAV methods are enabled, determine authentication, visible collections, write permission, and
whether uploaded extensions execute. Never equate a successful PUT with a shell.

### WinRM, RDP, and VNC

```bash
curl -i http://<ip>:5985/wsman
nmap -n -Pn -p3389 --script rdp-enum-encryption <ip>
nmap -n -Pn -p5900 --script vnc-info,vnc-title <ip>
```

WinRM/RDP usually become useful after credentials are recovered. Validate login rights, not just a
correct password. For VNC, identify security type before considering a targeted credential test.

### Docker API and Elasticsearch

```bash
curl -s http://<ip>:2375/version
curl -s http://<ip>:2375/info
curl -s http://<ip>:9200/
curl -s 'http://<ip>:9200/_cat/indices?v'
```

Unauthenticated management APIs are high priority. Begin with read-only version, container/index,
and configuration discovery; do not launch or modify resources until the exact foothold path and
scope are understood.

### Git, Subversion, and exposed source

```bash
git ls-remote git://<ip>/<repository>
svn ls svn://<ip>/<repository>
curl -sk <url>/.git/HEAD
```

Recover source into the target workspace, inspect history as well as the current tree, and search
for routes, dependencies, hard-coded credentials, deployment paths, and fixed-but-still-deployed
bugs. Do not publish recovered private source.

## 1.16 Public exploit triage

```bash
searchsploit '<product> <exact-version>'
searchsploit --nmap scans/tcp-services.xml
searchsploit -x <EDB-ID>              # read before copying/running
searchsploit -m <EDB-ID>              # mirror into workspace
```

Before running a PoC, verify:

- exact product/component and affected version range;
- OS, architecture, protocol, authentication, feature, path, and configuration prerequisites;
- whether the exploit is detection-only, destructive, a denial of service, or starts a bind shell;
- callback IP/port, target URL/path, bad characters, payload size, and hard-coded offsets;
- what success and failure look like, and how to reproduce the change for the report.

⛔ A public exploit title is not evidence. If prerequisites do not match, return to enumeration
instead of repeatedly changing payloads at random.

## 1.17 Before you move on

- [ ] Quick and full TCP scans completed; suspicious results verified more conservatively.
- [ ] UDP received a first pass and an evidence-based deeper pass where needed.
- [ ] Every open port has a manually validated protocol and focused version/script result.
- [ ] Every hostname/certificate name was resolved and tested across relevant web ports.
- [ ] Every web origin was browsed, baselined, content/vhost/parameter-discovered, and mapped in
  each relevant authentication state.
- [ ] SMB/RPC, FTP/TFTP, LDAP, DNS, SNMP, NFS/rsync, mail, and databases were tested where present;
  tool errors and access denials were not recorded as empty results.
- [ ] Anonymous/guest/no-auth and all safely testable recovered credentials were tried subject to
  lockout policy and scope.
- [ ] Downloaded source/shares/configs were searched for credentials, hostnames, routes, and
  deployment relationships.
- [ ] Each live hypothesis has one missing prerequisite and one decisive next test.
- [ ] Deferred checks are marked `N/A` or deferred with a reason and a trigger for revisiting them.
