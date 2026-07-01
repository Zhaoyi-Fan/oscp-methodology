# Appendix · Ports, default creds & key locations

Fast lookups you don't want to think about mid-box.

---

## Common ports → first move

| Port | Service | First move |
|---|---|---|
| 21 | FTP | anonymous login; check for web-served upload dir |
| 22 | SSH | version; destination for found creds/keys |
| 25 | SMTP | `VRFY`/`EXPN` user enum |
| 53 | DNS | zone transfer `dig axfr` |
| 80/443 | HTTP(S) | whatweb, dirs, vhosts, source |
| 88 | Kerberos | **it's a domain controller** → §08 |
| 110/143 | POP3/IMAP | creds → read mail |
| 111/2049 | RPC/NFS | `showmount -e`; no_root_squash |
| 135/139/445 | MSRPC/SMB | enum4linux-ng, null session, shares |
| 161/udp | SNMP | community strings, snmpwalk |
| 389/636 | LDAP | `ldapsearch` anonymous bind |
| 1433 | MSSQL | default creds, `xp_cmdshell` |
| 2049 | NFS | mount exports |
| 3306 | MySQL | default/weak creds |
| 3389 | RDP | creds reuse; `xfreerdp` |
| 5432 | PostgreSQL | default creds |
| 5985/5986 | WinRM | `evil-winrm` once you have creds |
| 6379 | Redis | often no auth |

## Default credentials to always try

`admin:admin` · `admin:password` · `root:root` · `root:toor` · `tomcat:tomcat` /
`tomcat:s3cret` · `postgres:postgres` · `sa:` (MSSQL) · product-name as user & pass · vendor defaults.
Also try discovered usernames as their own password.

## Key file locations

**Linux**
```
/etc/passwd /etc/shadow /etc/sudoers /etc/crontab /etc/exports
/home/*/.ssh/id_rsa  /home/*/.bash_history
/var/www/  (wp-config.php, .env, config.php, connection strings)
/var/log/auth.log  /var/log/apache2/access.log   (log poisoning)
```

**Windows**
```
C:\Windows\Panther\Unattend.xml
C:\inetpub\wwwroot\web.config
%userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
C:\Windows\System32\config\SAM  +  \SYSTEM        (need SeBackup/SYSTEM)
C:\Users\*\Desktop\  (proof.txt / local.txt)
```

## Wordlists worth remembering

```
/usr/share/wordlists/rockyou.txt
/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
/usr/share/seclists/Usernames/top-usernames-shortlist.txt
```

## Note on the exam's dropped topic

The standalone **buffer overflow** is no longer part of the current OSCP exam — don't spend prep time
building a BOF rig unless you're targeting a specific older syllabus. Focus effort on enumeration,
web, privesc, and AD.
