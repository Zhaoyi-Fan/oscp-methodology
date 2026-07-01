# 01 · Recon & Enumeration

The phase that decides the box. The goal is a complete, trustworthy map of the attack surface —
every open port, every service, every version — before you touch an exploit.

> 💡 Golden rule: failed boxes are almost always failed enumeration, not failed exploitation.
> When you're stuck, you haven't enumerated enough — go wider and deeper, don't force an exploit.

---

## 1.1 First steps

- Note the target IP; if you get a hostname/domain from a scan, cert, or redirect, **add it to
  `/etc/hosts` immediately** — name-based vhosts and Kerberos won't work until you do.
- Keep one scratch file per target for open ports, creds, and hostnames as you find them.

```bash
echo "<ip>  target.local dc01.target.local" | sudo tee -a /etc/hosts
```

## 1.2 Host discovery (only when given a range)

```bash
nmap -sn <range>/24 -oA sweep              # ping sweep
sudo nmap -PR -sn <range>/24               # ARP (same subnet, most reliable)
```

> 💡 Don't trust "host down" — firewalls drop ping. If scope says a host exists, scan it directly.

## 1.3 Port scanning

Split into fast → detailed so you start working results while the deep scan runs.

```bash
# P1 — find open ports fast (all 65535 TCP)
nmap -p- --min-rate 1000 -T4 -vv <ip> -oN fast_scan.txt

# P2 — version + default scripts on ONLY the open ports
nmap -p 21,22,80 -sC -sV <ip> -oN details.txt

# UDP — top ports only (slow); the ports people miss live here
sudo nmap -sU --top-ports 100 <ip> -oN udp_scan.txt
```

> 💡 UDP is the silent killer — SNMP (161), DNS (53), TFTP (69), IKE (500), NTP (123) hide here
> and are a classic reason a box stalls after a "clean" TCP scan. Always run it.

> 🚩 **EXAM:** AutoRecon is allowed and saves time by running these passes for you:
> `sudo autorecon <ip>`. It automates *enumeration*, not exploitation.

For each open port, ask: **what is it really** (trust `-sV`/banner over the port number), **what
version** (→ `searchsploit`), and **what does it imply** (445 → SMB/AD; 88 → Kerberos → domain
controller; 5985 → WinRM shell path once you have creds).

```bash
searchsploit "<product version>"
```

## 1.4 Service enumeration

### HTTP / HTTPS (80, 443, 8080, 8000, …)

The widest surface — be patient and look before you brute-force.

```bash
whatweb http://<ip>
curl -sI http://<ip>                       # headers, server, redirects

# content discovery
feroxbuster -u http://<ip> -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -t 50 -C 404
ffuf -u http://<ip>/FUZZ -w <wordlist> -e .php,.txt,.bak -mc 200,301,302,403

# virtual hosts (name-based routing hides most of the site)
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt \
     -u http://target.local -H "Host: FUZZ.target.local" -fs <default-response-size>

nikto -h http://<ip>
```

- Read `/robots.txt`, page source, JS files, and HTML comments — versions, endpoints, and creds leak here.
- Recurse into every interesting hit (`/admin` is a new root to fuzz, not a finish line).
- Identify the app precisely: `wpscan` (WordPress), `droopescan`/`joomscan` (Drupal/Joomla). A known
  product is often a known exploit.
- Catalogue every parameter/form (`?id=`, `?file=`, login) for the web-attacks phase.

> 💡 Set `-fs` to the length of the default/"not found" vhost response, or you'll drown in false hits.

### SMB / RPC (139, 445)

A goldmine on Windows/AD — often readable with no credentials.

```bash
enum4linux-ng -A <ip>                      # broad picture in one pass
smbclient -N -L //<ip>                     # list shares, null session
smbmap -H <ip>
netexec smb <ip> -u '' -p '' --shares      # try null and guest
netexec smb <ip> -u 'guest' -p '' --shares

# RPC (works anonymously surprisingly often)
rpcclient -U "" -N <ip>
#  > enumdomusers        list users
#  > querydispinfo       users WITH descriptions  💡 gold mine for planted passwords
#  > enumdomgroups
#  > querygroupmem 0x200 Domain Admins members
```

With any creds, re-run shares and pull users/files:

```bash
netexec smb <ip> -u user -p 'Pass' --shares          # 'Pwn3d!' = local admin — note it
netexec smb <ip> -u user -p 'Pass' --rid-brute       # enumerate all users
smbclient //<ip>/<share> -N                          # recurse ON, prompt OFF, mget *
```

> 💡 Save the user list and note the password policy (lockout threshold) **before** any spraying.

### LDAP (389, 636)

```bash
ldapsearch -x -H ldap://<ip> -b "dc=target,dc=local" "*" "+"
```

Naming contexts, users, descriptions, and group membership without creds on many DCs.

### FTP (21)

```bash
nmap -p21 --script ftp-anon,ftp-syst <ip>
ftp <ip>                                   # try anonymous / anonymous
```

> 💡 Anonymous write + a web-served directory = instant foothold. Always test read AND write.

### SSH (22)

```bash
nmap -p22 --script ssh-auth-methods <ip>
```

Rarely falls to enumeration itself — it's the destination once you find creds or a private key elsewhere.

### SMTP (25, 465, 587)

```bash
nc -nv <ip> 25          # then: VRFY root / VRFY john / EXPN admin
smtp-user-enum -M VRFY -U users.txt -t <ip>
```

Valid-user confirmation feeds spraying and other services.

### DNS (53)

```bash
dig @<ip> <domain> axfr                    # zone transfer = whole namespace
dig @<ip> any <domain> TXT
dnsenum <domain>
```

> 💡 Always attempt AXFR against every nameserver — a successful transfer is a full internal map.

### SNMP (161/udp)

```bash
onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp.txt <ip>   # guess community strings
snmpwalk -v2c -c public <ip> NET-SNMP-EXTEND-MIB::nsExtendObjects # running processes/args
snmp-check <ip>
```

> 💡 A readable community string (`public` first) leaks processes, users, installed software, and
> sometimes credentials sitting in process arguments.

### NFS (111, 2049)

```bash
showmount -e <ip>                          # list exports
sudo mount -t nfs <ip>:/export /mnt/nfs
```

> 💡 Watch for `no_root_squash` on an export — it opens a privesc path later.

### Databases (MSSQL 1433 / MySQL 3306 / PostgreSQL 5432 / Redis 6379 / Mongo 27017)

- Try default/weak creds and **no-auth** (Redis and Mongo are often wide open).
- Once in: read config for reused passwords, dump user/hash tables, and check for command/file R-W.

```bash
redis-cli -h <ip>                          # frequently no auth at all
mysql -h <ip> -u root -p
impacket-mssqlclient user:pass@<ip> -windows-auth
```

### Other high-signal ports

- **88 Kerberos** → it's a domain controller. Pivot to [§08 Active Directory](08-active-directory.md).
- **5985/5986 WinRM** → likely shell once you have creds (`evil-winrm -i <ip> -u u -p p`).
- **3389 RDP** → `xfreerdp /u:u /p:p /v:<ip>`; check for creds reuse.

## 1.5 Before you move on

- [ ] Full TCP range scanned (`-p-`), not just top 1000.
- [ ] Every open port has a version + default-script pass.
- [ ] Top UDP ports checked (SNMP/DNS especially).
- [ ] Web: robots/source/comments read, dirs + vhosts fuzzed and recursed, app + version identified.
- [ ] SMB/RPC: null + guest tried, shares browsed, user list saved, password policy noted.
- [ ] FTP anonymous, DNS AXFR, SNMP community strings all attempted.
- [ ] Every username, credential, and hostname found is in your notes and tried elsewhere.
- [ ] You can state what each open port is and your planned attack for it.
