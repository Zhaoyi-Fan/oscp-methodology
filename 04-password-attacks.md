# 04 · Password attacks and cracking

Two **separate** jobs with **separate** authorisation: guessing credentials against a live service
(**online**, §4.1–§4.7) and cracking looted hashes/files (**offline**, §4.8–§4.18). Possessing a
credential or artifact does **not** authorise the other branch, nor reuse elsewhere — each transition
is a fresh scope gate. Password reuse is a *scoped hypothesis* validated one identity × one service at
a time, **not** "try every credential everywhere".

The loop: `authority/scope → online or offline → inventory identity/service or artifact →
policy/request/format proof → smallest candidate stage → validate the result → stop/escalate/revisit →
record session/evidence → clean sensitive artifacts → route the next authorised action.`

**Routes:** credential/hash/key **discovery** comes from [§05](05-linux-privesc.md)/[§06](06-windows-privesc.md)/
[§10](10-post-exploitation-and-loot.md); AD policy/Kerberos/NTLM **acquisition** from
[§08](08-active-directory.md); web/login endpoint discovery from [§02](02-web-attacks.md); target/
service enumeration from [§01](01-recon-and-enumeration.md); transfers from [§09](09-file-transfers.md).
**Excluded:** LLMNR/NBT-NS/Responder capture and spoofing (a NetNTLM *format* may be handled without a
capture workflow). Never publish a recovered value; treat pot/session/wordlist/extracted material as
sensitive.

Placeholders: `TARGET_HOST`, `TARGET_SERVICE`, `ACCOUNT_ID`, `IDENTITY_LIST`, `CANDIDATE`,
`CANDIDATE_FILE`, `HASH_FILE`, `ARTIFACT_FILE`, `FORMAT_ID`, `MODE`, `RULE_FILE`, `MASK`,
`SESSION_NAME`, `OUTPUT_FILE`, `TIME_BUDGET`. Tool flags and Hashcat mode numbers drift — verify
against the installed version (`hashcat --hash-info`, `--help`; module help); mark unresolved forms
`NEEDS-REVIEW`. Exam tool-allowance claims must come from the current official guide, not stored notes.

**Jump — online:** [scope](#41-scope-evidence-and-online-vs-offline) ·
[identity/policy](#42-canonical-identity-and-effective-policy) ·
[one-cred validation](#43-one-known-credential-validation) · [Hydra](#44-hydra-protocol-cards) ·
[HTTP fidelity](#45-http-authentication-request-fidelity) · [candidates](#46-candidate-generation) ·
[spray/reuse](#47-spray-brute-stuffing-and-reuse). **Offline:**
[intake/identify](#48-offline-intake-and-identification) · [extract](#49-extract-and-normalize-artifacts) ·
[Linux/Kerberos/NTLM](#410-linux-kerberos-and-ntlm-families) · [John](#411-john-workflow) ·
[Hashcat](#412-hashcat-mode-and-session-workflow) · [rules](#413-dictionaries-and-rules) ·
[masks/hybrids](#414-masks-charsets-hybrids-and-combinators) · [resources](#415-resource-and-runtime-control) ·
[validate](#416-recovered-result-validation) · [negative](#417-negative-exhausted-and-revisit) ·
[cleanup](#418-evidence-and-cleanup).

---

> **ONLINE — live-service testing.** No block below crosses into offline cracking without a fresh
> authorisation gate.

## 4.1 Scope, evidence, and online vs offline

A blocking gate before any live request. Confirm written permission for **active authentication**
against exact host(s)/service(s)/port(s), the account population, a maintenance/deconfliction window,
per-account and global attempt caps, and where output is stored. Record operator, time, tool/version,
input counts, and stop conditions in an evidence ledger. If scope, identity, service, or policy is
unclear — **stop and clarify**. This card sends no requests.

## 4.2 Canonical identity and effective policy

Build a **canonical identity list** and prove **effective policy** before any guess.

```text
Canonical identity: domain → realm + sAMAccountName/UPN; local → host + name/SID; app → app namespace.
Classify confirmed / possible / excluded. Exclude machine, disabled, locked, service, protected,
shared/out-of-scope accounts unless each is approved. A username is a candidate, not a credential.
```

```bash
# Effective policy is default domain policy PLUS FGPP/resultant policy + current failure state:
netexec smb TARGET_HOST -u '' -p '' --pass-pol            # default domain policy (→ acquisition §08)
netexec ldap TARGET_HOST -u ACCOUNT_ID -p '<known>' -M maq  # FGPP/PSO presence
```

**Corrections:** local `net accounts` is **not** domain policy; record the exact policy source, DC/PDC,
query time, per-account FGPP/resultant policy, current `badPwdCount`/last-attempt, replication caveats,
and concurrent testers. "Slower", "one password", "below threshold" are **not** zero-risk — if policy/
current failures can't be reliably resolved, it's a **no-go**. Domain policy/Kerberos acquisition is
[§08](08-active-directory.md); §04 keeps the effective-policy input contract.

## 4.3 One-known-credential validation

The single validation card for a spray hit, a recovered credential, or a reuse hypothesis.

```bash
# ONE identity × ONE service, one attempt, classify the result:
netexec smb TARGET_HOST -u ACCOUNT_ID -p '<candidate>'                 # domain vs --local-auth namespace
netexec winrm TARGET_HOST -u ACCOUNT_ID -p '<candidate>'
```

Success is one protocol-specific authentication for the exact identity/service — it is **not**
application authorization, local admin, domain privilege, or remote-execution authority. Stop that
identity on success; do not auto-retry on timeout/ambiguous result. **Correction:** `--local-auth`
changes the identity *namespace* only (a local `Administrator` ≠ the domain `Administrator`) and does
**not** remove lockout/telemetry/availability risk. Close the session; protect/delete cookies/tickets/
output. A confirmed reuse candidate goes back through this card per host — never a subnet-wide default.

## 4.4 Hydra protocol cards

`Authority → exact service/port/TLS → one identity or approved list → bounded candidates →
rate/timeout/failure caps → matched success → stop → output cleanup.` One protocol per card.

```bash
# SSH / FTP — confirm the service and identity namespace first:
hydra -l ACCOUNT_ID -P CANDIDATE_FILE -t 4 -f -o OUTPUT_FILE ssh://TARGET_HOST
hydra -l ACCOUNT_ID -P CANDIDATE_FILE -t 4 -f ftp://TARGET_HOST          # note FTPS/banner/port
```

- `-l`/`-L` single/list user · `-p`/`-P` single/list password · `-s` port · `-t` connection concurrency
  (**not** a safety budget) · `-f` stop on first hit · `-o` output file.
- Bound the candidate **product** (users × passwords), set a per-account/global cap, and treat a
  timeout/transport error as **unknown**, not a credential failure or a retry licence — a blind retry
  may already count as a failed attempt. Do not `-V`-print secrets to a shared terminal/log; stop on
  the first hit, lockout marker, 429/403, or response drift, and clean sensitive output.

## 4.5 HTTP authentication request fidelity

Reconstruct the **exact** request; one text fragment is fragile. Split Basic from form.

**HTTP Basic** — first prove the endpoint issues a `WWW-Authenticate: Basic` challenge (an HTML login
form is **not** Basic):
```bash
hydra -l ACCOUNT_ID -P CANDIDATE_FILE -s PORT -f TARGET_HOST http-get /<exact-path>
```
Classify with status + `WWW-Authenticate` + redirect chain + the protected resource — not a bare `200`/
`401`.

**HTTP form** — capture the real request (method/path/body field names/encoding/headers/cookies) and a
stable, mutually-exclusive failure marker:
```bash
hydra -l ACCOUNT_ID -P CANDIDATE_FILE -f TARGET_HOST \
  http-post-form "/<path>:user=^USER^&pass=^PASS^:F=<invalid-marker>"
# https / non-default port: use https-post-form and -s PORT
```
**Corrections:** the third field is a failure condition, but a single generic string over-triggers —
build both an invalid baseline and (if a test account exists) a valid baseline so the classification is
stable. If each request needs a fresh **CSRF/nonce/cookie**, or there is MFA/CAPTCHA/SSO/JS challenge, a
static template is not faithful — **stop and route to an application-specific test** ([§02](02-web-attacks.md)),
do not strip the control. Never log the `Authorization` header, cookies, or tokens.

## 4.6 Candidate generation

CeWL is an **active crawler**, not an offline generator — bound scope and separate generation from any
login attempt.

```bash
cewl -d 2 -m 6 -w CANDIDATE_FILE http://TARGET_HOST/           # -d crawl depth, -m MIN word length
```

**Corrections:** `-m` is the **minimum word length**, not a maximum word count (verify against the
installed version), and deeper crawl is not automatically "better" — bound depth/pages/same-origin and
respect scope. Page tokens are candidates, not passwords: record provenance, strip personal data and
navigation noise, deduplicate, and form a small justified set gated by the effective policy of §4.2.
Generating a list authorises no login attempt.

## 4.7 Spray, brute, stuffing, and reuse

These are **distinct** distributions, each needing its own authority/policy/budget — pick **one** and
fix the matrix; never default to a users × passwords × services Cartesian product.

```text
brute force  : many candidates → one account
password spray: one candidate → many CONFIRMED accounts
reuse/stuffing: one known credential/hash → a small approved allowlist (validate via §4.3 per host)
username enum : submits NO password guess (still has KDC/telemetry/rate concerns) → reconcile via §4.2
```

**Corrections:** spraying lowers per-account frequency but does **not** remove lockout/throttle/
detection risk — require §4.2's effective FGPP/PDC/current-failure gate and exclusions, and **stop each
successful identity** (no `--continue-on-success` by default). Kerbrute *userenum* is not a password
guess, but a Kerberos spray's failed pre-auth **can** count toward lockout. Remove any fixed seasonal
sample password; route AD specifics to [§08](08-active-directory.md). On any unexpected lockout: stop
globally, notify deconfliction, preserve minimal evidence — do not self-unlock or "spray slower".

---

> **OFFLINE — hash/artifact cracking.** Possessing an artifact does not authorise live validation;
> that is a separate route ([§4.3](#43-one-known-credential-validation)) with fresh authority.

## 4.8 Offline intake and identification

Record **provenance** (where the artifact came from, owner, authorised use), keep the **original
read-only** with a recorded digest, and work on a copy. Identification is a **hypothesis**, not a
verdict.

```bash
sha256sum ARTIFACT_FILE > ARTIFACT_FILE.sha256      # immutable original + digest
hashid '<token>'                                     # or name-that-hash — a candidate SET, not proof
```

Recognisable prefixes are cues: `$1$` md5crypt · `$5$` sha256crypt · `$6$` sha512crypt · `$2*$` bcrypt ·
`$P$`/`$H$` phpass · `$krb5tgs$` Kerberoast · `$krb5asrep$` AS-REP. **Corrections:** `32 hex` is **not**
a unique algorithm (NTLM vs raw-MD5 vs …) — decide from provenance/prefix/length/encoding/salt/
separators and confirm with the parser, not length alone. Preserve bytes: detect BOM/UTF-16/non-ASCII
and record pre/post counts before any conversion (Windows redirection/copy-paste can corrupt tokens).

## 4.9 Extract and normalize artifacts

Each container/version/encryption is a **distinct** variant: `extract → inspect the signature →
confirm the mode with hash-info → check parser counts → run`. Do **not** pin one universal mode.

```bash
ssh2john id_rsa > HASH_FILE            # putty2john for .ppk (a PPK is NOT the same as OpenSSH)
zip2john a.zip > HASH_FILE             # PKZIP vs WinZip-AES vs compressed/multi-file differ
rar2john a.rar > HASH_FILE ; 7z2john a.7z > HASH_FILE   # RAR3-hp / RAR3-p / RAR5 are different
office2john doc.docx > HASH_FILE       # 2007/2010/2013/2016+ are different families
pdf2john file.pdf > HASH_FILE          # PDF revision → a mode family, not one mode
keepass2john db.kdbx > HASH_FILE       # KDF/version/keyfile are hard gates
```

**Corrections:** do **not** blindly strip the first `filename:`/`user:` field with a generic
`cut -d: -f2-` — a separator may be part of a valid format, and extractor outputs differ; use
format-specific normalization, and `--username` only when the chosen mode documents that prefix.
Validate the working copy actually decrypts/opens with structural integrity before declaring the
variant correct (§4.16). Never migrate the note's unverified pins (PPK≠22911, VNC≠7900, Office 2016+
`25300` vs sheet-protection, `22951` PKCS#8) — verify each with `hashcat --hash-info`.

## 4.10 Linux, Kerberos, and NTLM families

**Linux passwd/shadow** — matching files from the same authorised snapshot (acquisition →
[§05](05-linux-privesc.md)/[§10](10-post-exploitation-and-loot.md)):
```bash
unshadow /etc/passwd /etc/shadow > HASH_FILE          # md5crypt 500 / sha256crypt 7400 / sha512crypt 1800 / bcrypt 3200
```

**Windows NTLM / NetNTLM** — record provenance (SAM/local dump vs challenge-response); a NetNTLMv2 is
**not** a database NTLM: NTLM `1000`, LM `3000`, NetNTLMv2 `5600`. Acquisition → [§06](06-windows-privesc.md)/
[§10](10-post-exploitation-and-loot.md); NetNTLM **capture is excluded** (spoofing boundary), format-only
handling is allowed.

**Kerberos** — a token-type + **encryption-type** matrix, not one number (acquisition →
[§08](08-active-directory.md)):
```text
Kerberoast (TGS-REP): etype 23 → 13100 ;  etype 17/18 → 19600/19700
AS-REP:               etype 23 → 18200 ;  AES AS-REP → NEEDS-REVIEW (verify token etype + hash-info)
```
Do **not** fix `13100`/`18200` by the `$krb5*$` prefix alone or migrate another pre-auth family's mode.

## 4.11 John workflow

Confirm the **format** (don't rely on "fastest when unknown"); record session/status/restore/pot.

```bash
john --list=formats | grep -i <family>                 # pick the exact loader
john --format=<FORMAT_ID> --wordlist=CANDIDATE_FILE --session=SESSION_NAME HASH_FILE
john --status --session=SESSION_NAME                    # progress for a long run
john --restore=SESSION_NAME                             # resume the SAME job (input/format must match)
john --show --format=<FORMAT_ID> HASH_FILE              # recovered vs remaining, from the potfile
```

**Corrections:** auto-detection can be ambiguous/wrong and speed depends on format/backend/strategy —
record the selected loader. Distinguish a **new** recovery from an old **potfile** hit; `0g`/exhausted
means *this candidate set* missed, not "no password". Add rules/incremental deliberately (§4.13–§4.14),
time-box (§4.15), and delete the session/pot/derived material in cleanup (§4.18).

## 4.12 Hashcat mode and session workflow

Confirm the mode with **hash-info** before expensive work, and manage the session/potfile explicitly.

```bash
hashcat --hash-info | grep -i <family>                 # confirm the mode number + example schema
hashcat --identify HASH_FILE                            # auxiliary hint only, not authority
hashcat -m MODE HASH_FILE CANDIDATE_FILE --session=SESSION_NAME -o OUTPUT_FILE
hashcat --session=SESSION_NAME --restore                # resume the SAME job
hashcat -m MODE HASH_FILE --show                        # recovered results from the current potfile
```

Watch `Recovered / Progress / Rejected / Restore.Point / Speed`: a rising **Rejected** count means a
format/encoding/separator problem — return to §4.8/§4.9, do **not** `--force` past it. A `--session`
plus a task-specific potfile keeps jobs from cross-contaminating. **Correction:** "loads successfully"
is not proof the mode is *semantically* correct — the digest/salt counts must match the artifact.

## 4.13 Dictionaries and rules

Start with high-signal target-derived candidates (§4.6), then a bounded general list, then rules —
estimate the candidate count first.

```bash
hashcat -m MODE HASH_FILE CANDIDATE_FILE -r RULE_FILE --session=SESSION_NAME   # e.g. best64.rule
john --format=<FORMAT_ID> --wordlist=CANDIDATE_FILE --rules=<ruleset> HASH_FILE
```

**Corrections:** record wordlist provenance/encoding and deduplicate; a ruleset multiplies the keyspace,
so estimate the expansion before running. When building a rule file, use **literal-safe** quoting —
e.g. PowerShell double-quotes expand `$`-prefixed rule operators, silently changing the rule; write
rules with single quotes / here-strings and verify the file content matches what you intended.

## 4.14 Masks, charsets, hybrids, and combinators

Estimate keyspace/ETA **before** running; quote masks/charsets as shell literals.

```bash
# Mask (-a 3): position charsets; ?l?u?d?s + custom sets -1..-4
hashcat -m MODE HASH_FILE -a 3 -1 '?l?u?d' '?1?1?1?1?1?1' --session=SESSION_NAME
# Hybrid: -a 6 = word + mask ; -a 7 = mask + word  (ONE attack mode per job)
hashcat -m MODE HASH_FILE CANDIDATE_FILE -a 6 '?d?d?d'          # word + 3 digits
hashcat -m MODE HASH_FILE -a 7 '?d?d?d' CANDIDATE_FILE          # 3 digits + word
```

**Corrections:** a job has **one** attack mode — you cannot combine `-a 7` and `-a 6` in one command to
build "prefix + word + suffix" (the note's `-a 7 ?u -a 6 ?d?d?s` is invalid). For `-a 7` the operand
order is **mask then wordlist** (the note reversed it). Quote every mask/custom charset so the shell
does not interpret `?`, `$`, or `#`. Use a combinator (two curated wordlists) only when the evidence is
two word-roots, and bound the product. Cap incremental/`--increment` length by evidence and budget, not
"run until it hits".

## 4.15 Resource and runtime control

`-O`, workload, and device flags are **not** free speed — they change support and stability.

```bash
hashcat -b -m MODE            # benchmark = synthetic throughput only; NOT a real-job ETA
hashcat -m MODE HASH_FILE CANDIDATE_FILE -w 2        # workload profile; -w 3 needs a dedicated box
```

**Corrections:** `-O` (optimized kernel) imposes a **mode-specific maximum password length** — only use
it when every candidate fits, or you silently skip longer passwords. `-w 3` is a high workload that
affects system responsiveness/heat — reserve it for a monitored, dedicated device. `--force` is a
**diagnostic hold**, never a default remedy; it can mask driver/runtime problems. Estimate a real ETA
from actual records/salts/rules/device (a peak benchmark ignores salts and rules) and time-box to
`TIME_BUDGET`.

## 4.16 Recovered-result validation

A tool "success" is a candidate result, not a finding.

```bash
# Recompute against the parsed record, OR decrypt a WORKING COPY and verify full structure:
unzip -P '<recovered>' -t ARTIFACT_FILE          # archive integrity test
ssh-keygen -y -f id_rsa                          # key: decrypts with the passphrase?
```

Validate **offline** first (recompute the hash, or open the archive/key/document/database copy and
confirm it is structurally complete). Only then, a **live** validation is a *separate, freshly
authorised* one-attempt route through [§4.3](#43-one-known-credential-validation) — and authentication
success is still not privilege. Do not write the recovered value into logs/docs; if a live secret was
exposed, coordinate rotation rather than claiming a rollback.

## 4.17 Negative, exhausted, and revisit

A bounded negative is a **valid** result. Distinguish the states and decide deliberately:

```text
tool/format failure  → fix mode/encoding/parser (§4.8/§4.9), do not conclude "no password"
candidate exhausted  → this set missed; Hashcat "Exhausted" can accompany PARTIAL recovery
partial recovery     → some digests cracked, others remain
old potfile hit      → already recovered earlier; not a new result
```

Do **not** treat every hash as requiring "rockyou + best64 at minimum" — triage by artifact value/cost/
format, estimate candidates/time, run staged (target-derived → bounded general → rules → evidence-backed
mask/hybrid), and accept an exhausted/too-costly stop. Only new candidate evidence, a fixed format, or an
approved larger budget justifies a revisit; a `--restore` requires a matching input/session fingerprint.

## 4.18 Evidence and cleanup

Record counts and clean sensitive state.

```text
- Ledger: expected/loaded/rejected/recovered/remaining, salt/digest groups, input+session fingerprint,
  tool/version/mode, timestamps — never the secret value, raw hash, cookie, or token.
- Remove: original/working artifact copies, extracted HASH_FILE, wordlists with org terms, potfiles,
  .restore/session files, OUTPUT_FILE, decrypted copies, and shell-history/clipboard exposure.
- Distinguish an exhausted stop from a solved job; retain only non-secret auditable metadata.
```

Route onward with fresh scope: reuse/validation via [§4.3](#43-one-known-credential-validation),
discovery back to [§05](05-linux-privesc.md)/[§06](06-windows-privesc.md)/[§10](10-post-exploitation-and-loot.md),
AD/Kerberos to [§08](08-active-directory.md), lateral movement to [§07](07-pivoting-and-tunneling.md).

## References

- Hashcat mode numbers, `*2john` extractor output, and John format names drift by version — confirm with
  `hashcat --hash-info` / `--help` and `john --list=formats`, and mark unverified pins `NEEDS-REVIEW`.
  Wallet/mail/disk/router/extended families stay deferred until an independent source scenario and
  current verification exist.
- Chapter handoffs are linked inline: recon [§01](01-recon-and-enumeration.md), web
  [§02](02-web-attacks.md), Linux [§05](05-linux-privesc.md), Windows [§06](06-windows-privesc.md),
  pivoting [§07](07-pivoting-and-tunneling.md), Active Directory [§08](08-active-directory.md),
  transfers [§09](09-file-transfers.md), loot [§10](10-post-exploitation-and-loot.md).
