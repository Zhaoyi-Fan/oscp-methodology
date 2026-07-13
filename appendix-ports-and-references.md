# Appendix · Ports, Credentials, Paths & References

Use port numbers as routing hints, never as protocol proof. Validate the service manually and with
version detection; non-standard ports are common.

---

## Common ports → first decisive move

| Port | Likely service | First decisive move |
|---|---|---|
| 20/21 | FTP | `ftp-anon`, `SYST`; list/read; inert write test only if justified |
| 22 | SSH | banner/auth methods; destination for recovered password/key |
| 23 | Telnet | banner; no-auth/default/known credentials; capture OS clues |
| 25/465/587 | SMTP(S) | `EHLO`, methods, STARTTLS/implicit TLS; small user-validation set |
| 53 TCP/UDP | DNS | SOA/NS/TXT/PTR; AXFR against each authoritative NS |
| 69/udp | TFTP | retrieve only evidence-backed filenames; no listing/auth |
| 80/443 | HTTP(S) | full origin map: Host/SNI, redirects, content, parameters, auth state |
| 88 | Kerberos KDC | identify realm/domain; Windows domain-controller clue → §08 |
| 110/995 | POP3(S) | capabilities; with creds, list/read mail for reset links and secrets |
| 111 | rpcbind | `rpcinfo -p`; correlate NFS and other RPC programs |
| 135/139/445 | MSRPC/NetBIOS/SMB | null + guest + known creds; shares/users/policy; recurse files |
| 137/138 UDP | NetBIOS | names/domain clues; do not use poisoning/spoofing on the exam |
| 143/993 | IMAP(S) | capabilities; with creds, list mailboxes/messages |
| 161/udp | SNMP | v1/v2c communities; system/interfaces/process args/software |
| 389/636 | LDAP(S) | RootDSE → naming context → anonymous/credentialed search |
| 443/8443 | HTTPS | certificate SANs, SNI, Host routing, headers/source/dirs |
| 500/4500 UDP | IKE/IPsec | identify version/transforms/IDs within scope; no spoofing/DoS |
| 512–514 | r-services | trust files, host/user auth, cleartext login risk |
| 873 | rsync | list modules and files; source/backups/keys; map any write consumer |
| 1099 | Java RMI | exact product/class exposure; validate PoC/version prerequisites |
| 1433 | MSSQL | SQL vs Windows auth; version/current role; `xp_cmdshell` state |
| 1521 | Oracle | listener/SID/service names; known credentials and version |
| 2049 | NFS | `showmount -e`; read-only mount; ownership/export options |
| 2375/2376 | Docker API | `/version`, `/info`, containers; no-auth API is high priority |
| 3000/5000/8000/8080/8443 | Alternate web | treat as separate origin; framework/API/admin surface |
| 3128 | HTTP proxy/Squid | proxy behavior; test only in-scope local/target destinations |
| 3306 | MySQL/MariaDB | version/current identity/grants/databases; config-derived creds |
| 3389 | RDP | encryption/NLA; validate recovered creds and login rights |
| 3690 | Subversion | list repository/history; inspect recovered source/config |
| 4369 | Erlang EPMD | `epmd-info`; map RabbitMQ/Erlang node ports and exact version |
| 5432 | PostgreSQL | version/current role/databases/schemas/tables/privileges |
| 5900+ | VNC | security type/title; targeted known/default credential only |
| 5985/5986 | WinRM(S) | `/wsman`; shell only with valid creds and remote-login rights |
| 6379 | Redis | `PING`, `INFO`, ACL identity, keyspace/`SCAN`; no-auth is high priority |
| 8009 | AJP | identify Tomcat/AJP version and configuration; exact PoC only |
| 9200 | Elasticsearch | `/`, cluster/version, `_cat/indices`; read-only first |
| 11211 | Memcached | version/stats; unauthenticated cached data within scope |
| 27017 | MongoDB | no-auth/known creds; list DBs/collections/roles read-only first |

See [§01 Recon & Enumeration](01-recon-and-enumeration.md) for commands and completion criteria.

## Credential checks

1. Prefer credentials recovered from the target, vendor documentation, page content, configuration,
   password hints, or an identified product/version.
2. Try anonymous/guest/no-auth where the protocol explicitly supports it.
3. Determine lockout threshold, observation window, rate limit, and prior failures before online
   guessing. A password spray can still lock every account.
4. Record one identity-service matrix and retest only safe, evidence-backed combinations.

Common low-cost checks, when policy permits:

```text
FTP: anonymous / blank or email-style password
SMB: null session, guest / blank
Datastores: documented no-auth mode (Redis/Mongo) before guessing
Product consoles: vendor default for the exact installed version
Generic fallback: admin:admin, admin:password, root:root, product-name:product-name
```

Do not turn this short list into an unbounded brute-force run.

## High-value file locations

### Linux and common web stacks

```text
/etc/passwd                 /etc/shadow                  /etc/sudoers
/etc/crontab                /etc/exports                 /etc/systemd/system/
/proc/self/cmdline          /proc/self/environ           /opt/ and /srv/
/home/*/.ssh/               /home/*/.*history            /root/.ssh/
/var/www/                   /var/log/apache2/            /var/log/nginx/
.env                        wp-config.php                config.php
settings.py                 application.properties      application.yml
```

### Windows and common web stacks

```text
C:\inetpub\wwwroot\web.config
appsettings.json
C:\Windows\Panther\Unattend.xml
C:\Windows\System32\inetsrv\config\applicationHost.config
%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
%USERPROFILE%\.ssh\
```

These paths are leads for a confirmed traversal/LFI or exposed-share finding. Read only the files
needed to establish the foothold and keep real secrets in private target notes.

## Wordlists worth remembering

```text
/usr/share/wordlists/rockyou.txt
/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt
/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
/usr/share/seclists/Usernames/top-usernames-shortlist.txt
/usr/share/seclists/Fuzzing/LFI/
```

Start with a small, relevant list. Change wordlist, extensions, base path, Host, or authentication
state only in response to evidence; a larger list does not fix a wrong origin or soft-404 filter.

## Current scope and priority note

The current public OSCP+ structure has three standalone machines and one AD set; it does not
describe a dedicated buffer-overflow machine. This is a study-priority decision, not proof that
memory corruption is absent from the knowledge base. OffSec's current Body of Knowledge still
includes high-level buffer-overflow theory, cross-compilation, and modifying/updating
memory-corruption exploits. Retain the ability to read and repair a public PoC while prioritizing
enumeration, web footholds, privilege escalation, AD, and documentation.

## Primary references

### Current OffSec policy and scope

- [OSCP+ Exam Guide](https://help.offsec.com/hc/en-us/articles/360040165632-OSCP-Exam-Guide)
- [OSCP+ Exam FAQ](https://help.offsec.com/hc/en-us/articles/4412170923924-OSCP-Exam-FAQ)
- [OSCP+ Body of Knowledge](https://help.offsec.com/hc/en-us/articles/38543335188756-OSCP-Body-of-knowledge)
- [OSCP+ Authoritative References](https://help.offsec.com/hc/en-us/articles/37192004980628-Authoritative-References-List-OSCP)

### Tool and methodology documentation

- [Nmap Reference Guide](https://nmap.org/book/man.html)
- [Nmap service/version detection](https://nmap.org/book/man-version-detection.html)
- [ffuf official documentation](https://github.com/ffuf/ffuf)
- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
