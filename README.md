# OSCP Methodology

A lab-tested, checklist-style methodology for the full OSCP kill chain — from first packet to
domain admin. Built as a **cheatsheet, not a textbook**: command-first, evidence-driven, and
organized so I can find the right move under exam pressure without reading chapters of prose.

> ⚠️ For authorized penetration testing, lab work, and exam preparation only.

## How to use this

- Each section is a phase of the chain. Work them in order on a fresh target, and **re-run the
  relevant sections after every new foothold** — a new host or credential resets the process.
- Start each independent target with the [standalone foothold loop](00-standalone-foothold-loop.md).
  It controls time-boxing, evidence, hypothesis ranking, and the hand-off between enumeration and
  web testing.
- Every section ends with a **"before you move on"** checklist. Complete each applicable item; mark
  the rest `N/A` or deferred with a reason and a concrete trigger for revisiting it.
- Commands use `<target>`, `<ip>`, `<port>` placeholders — swap in your values.

### Legend

| Marker | Meaning |
|--------|---------|
| 🚩 **EXAM** | An OSCP exam rule or restriction to keep in mind. *Always verify against the current PEN-200 exam guide — rules change.* |
| 💡 | A tip or gotcha worth remembering. |
| ⛔ | A common rabbit hole / time sink. |

### 🚩 OSCP tooling rules (verified 2026-07-10; re-check before use)

The [OSCP+ Exam Guide](https://help.offsec.com/hc/en-us/articles/360040165632-OSCP-Exam-Guide)
and [Exam FAQ](https://help.offsec.com/hc/en-us/articles/4412170923924-OSCP-Exam-FAQ) are the
authority, not this repository.

- **Metasploit / Meterpreter:** restricted to **one** target machine for the whole exam. Even a
  module's `check` action locks the choice. `msfvenom` and `exploit/multi/handler` may be used
  against all targets, but a Meterpreter payload is still restricted.
- **Prohibited:** automated exploitation tools such as SQLmap/SQLninja, mass vulnerability
  scanners, commercial tools or services (including Burp Suite Professional), spoofing, denial of
  service, and any tool feature that performs a restricted action.
- **AI/LLMs:** prohibited during both the exam and report-writing phase.
- OffSec explicitly names tools such as Nmap/NSE, Nikto, Burp Community, and DirBuster as allowed
  examples. For any wrapper or automation tool not named by OffSec, inspect what it actually does
  and verify the current policy instead of relying on an “allowed tools” blog post.

## The chain

| # | Section | Status |
|---|---------|--------|
| 00 | [Standalone foothold loop](00-standalone-foothold-loop.md) | ✅ |
| 01 | [Recon & enumeration](01-recon-and-enumeration.md) | ✅ |
| 02 | [Web attacks (foothold via web)](02-web-attacks.md) | ✅ |
| 03 | [Shells, payloads & upgrades](03-shells-and-payloads.md) | ✅ |
| 04 | [Password attacks & cracking](04-password-attacks.md) | ✅ |
| 05 | [Linux privilege escalation](05-linux-privesc.md) | ✅ |
| 06 | [Windows privilege escalation](06-windows-privesc.md) | ✅ |
| 07 | [Pivoting & tunneling](07-pivoting-and-tunneling.md) | ✅ |
| 08 | [Active Directory (initial access → domain dominance)](08-active-directory.md) | ✅ |
| 09 | [File transfers](09-file-transfers.md) | ✅ |
| 10 | [Post-exploitation & loot](10-post-exploitation-and-loot.md) | ✅ |
| A | [Appendix: ports, credentials, paths & references](appendix-ports-and-references.md) | ✅ |

## License

MIT — see [LICENSE](LICENSE). Techniques and commands here are common industry knowledge; the
structure, wording, and checklists are my own. No proprietary course material is reproduced.
