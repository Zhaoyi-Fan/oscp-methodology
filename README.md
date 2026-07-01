# OSCP Methodology

A field-tested, checklist-style methodology for the full OSCP kill chain — from first packet to
domain admin. Built as a **cheatsheet, not a textbook**: terse, command-first, and organized so I
can find the right move under exam pressure without reading paragraphs.

> ⚠️ For authorized penetration testing, lab work, and exam preparation only.

## How to use this

- Each section is a phase of the chain. Work them in order on a fresh target, and **re-run the
  relevant sections after every new foothold** — a new host or credential resets the process.
- Every section ends with a **"before you move on"** checklist. If you can't tick every box, you
  haven't finished enumerating that surface.
- Commands use `<target>`, `<ip>`, `<port>` placeholders — swap in your values.

### Legend

| Marker | Meaning |
|--------|---------|
| 🚩 **EXAM** | An OSCP exam rule or restriction to keep in mind. *Always verify against the current PEN-200 exam guide — rules change.* |
| 💡 | A tip or gotcha worth remembering. |
| ⛔ | A common rabbit hole / time sink. |

### 🚩 OSCP tooling rules (verify current guide)

- **Metasploit / Meterpreter:** may be used on **only one** target machine for the whole exam.
  Plan which one. `msfvenom` and the multi-handler are fine to use freely.
- **Banned entirely:** automated exploitation tools (e.g. **SQLMap**, SQLNinja), commercial tools
  (Burp Pro scanner, Nessus/Nexpose/Canvas/Core Impact), and spoofing/DoS.
- **Fine:** manual tooling, `nmap` + NSE, directory/vhost fuzzers, `enum4linux-ng`, `netexec`,
  and enumeration automators like AutoRecon (they enumerate, they don't exploit).

## The chain

| # | Section | Status |
|---|---------|--------|
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
| A | [Appendix: ports, default creds, key file locations](appendix-ports-and-references.md) | ✅ |

## License

MIT — see [LICENSE](LICENSE). Techniques and commands here are common industry knowledge; the
structure, wording, and checklists are my own. No proprietary course material is reproduced.
