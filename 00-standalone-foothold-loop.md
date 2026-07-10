# 00 · Standalone Foothold Loop

Use this page as the controller for each standalone target. The aim is not to run every command;
it is to maintain a reliable attack-surface map, keep the strongest hypotheses at the top, and
turn one observed capability into low-privileged access.

> **Authorized targets only.** Exam rules change. Before an exam, re-check the current
> [OSCP+ Exam Guide](https://help.offsec.com/hc/en-us/articles/360040165632-OSCP-Exam-Guide)
> and [OSCP+ Exam FAQ](https://help.offsec.com/hc/en-us/articles/4412170923924-OSCP-Exam-FAQ).
> AI/LLM use is prohibited during the exam and report-writing phase.

---

## 0.1 Define success

A foothold is a reproducible low-privileged execution or login path, not merely a promising
version number or a one-off error. Work toward one of these capabilities:

1. **Authenticate** — a recovered/default credential reaches SSH, WinRM, SMB, a database, or an
   administrative web function.
2. **Read** — retrieve source, configuration, keys, password hashes, or other material that creates
   an authentication or execution path.
3. **Write** — place controlled content in a location that is interpreted, executed, or consumed
   by a privileged application.
4. **Execute** — prove command execution with a harmless command, then convert it to a stable shell.
5. **Reach** — use SSRF, a proxy function, or a newly discovered hostname to expose a stronger
   internal-only surface.

Do not confuse a vulnerability label with a path to access. Write down the missing link:
`file upload → stored where? → served how? → executable by which handler?`.

## 0.2 Start a target workspace

```bash
export RHOST='<ip>'
export LHOST='<tun0-ip>'
export NAME='standalone-1'
mkdir -p "$NAME"/{scans,web,files,exploit,screens}
cd "$NAME"
date -Is | tee timeline.txt
```

Keep four small ledgers. Tables beat a long stream of prose when time is tight.

### Surface map

| Port / origin | Protocol and product | Evidence | Access tried | Next decisive test |
|---|---|---|---|---|
| `<port>` | `<service/version>` | `<banner/path>` | `<anon/guest/creds>` | `<one test>` |

For web, an **origin** is the full combination of scheme, hostname, and port. Treat
`http://<ip>`, `http://app.<domain>`, and `https://app.<domain>:8443` as different surfaces.

### Identity and credential map

| Username / identity | Password, hash, or key | Source | Confirmed on | Still to try |
|---|---|---|---|---|
| `<user>` | `<value or reference>` | `<where found>` | `<service>` | `<other services>` |

Use a private exam/lab note for real secrets. Never place them in this repository.

### Web entry-point map

| Proxy request | Path | Method / type | Auth state | Parameters / headers | Baseline |
|---|---|---|---|---|---|
| `#` | `/path` | `POST JSON` | `guest` | `id, file, X-*` | `200 / 4312 B / 80 ms` |

### Hypothesis queue

| Priority | Observation | Hypothesis | One decisive test | Result / timestamp |
|---|---|---|---|---|
| 1 | `<fact>` | `<possible path>` | `<controlled comparison>` | `<result>` |

Facts and guesses must stay separate. “Apache 2.4.x” is evidence; “vulnerable to exploit Y” is a
hypothesis until the exact build, configuration, and prerequisites match.

## 0.3 Launch parallel discovery lanes

Run a quick pass, a full TCP pass, and a small UDP pass. Start manual interaction as soon as the
first result arrives; do not wait for every scan to finish.

```bash
# Quick orientation
sudo nmap -n -Pn -sS --top-ports 1000 -T4 --max-retries 2 \
  -oA scans/tcp-quick "$RHOST"

# Complete TCP range
sudo nmap -n -Pn -sS -p- -T4 --min-rate 1000 --max-retries 2 \
  -oA scans/tcp-full "$RHOST"

# Common UDP services; -sV helps resolve some open|filtered results
sudo nmap -n -Pn -sU --top-ports 100 -sV --version-light -T3 \
  -oA scans/udp-top100 "$RHOST"
```

Extract open TCP ports and run a focused pass:

```bash
ports=$(awk -F/ '/^[0-9]+\/tcp[[:space:]]+open/{print $1}' \
  scans/tcp-full.nmap | paste -sd, -)
test -n "$ports" && sudo nmap -n -Pn -sC -sV -p "$ports" \
  -oA scans/tcp-services "$RHOST"
```

`--min-rate 1000` is a fast lab/VPN starting point, not ground truth. If results are sparse,
inconsistent, or a service behaves strangely, repeat the relevant ports more slowly without a
minimum rate. Read [§01 Recon & Enumeration](01-recon-and-enumeration.md) for the deep passes.

## 0.4 Rank surfaces by evidence

Work the top two high-signal surfaces rather than giving equal time to every port.

| Signal | Priority | Why |
|---|---:|---|
| Anonymous/no-auth read or write; exposed config/source/key | 1 | Already provides a useful capability |
| User-controlled web input, upload, admin function, API, or hidden vhost | 1 | Direct route to auth, file access, or execution |
| Exact product/plugin version with a matching public PoC | 2 | Strong only after prerequisites are verified |
| Recovered username/credential not yet tried across services | 2 | Reuse frequently closes the chain |
| Generic banner, speculative exploit, or broad brute force | 3 | Weak evidence; keep time-boxed |

For every open service, answer:

- Did I verify the protocol rather than trust the port number?
- Did I try anonymous, guest, no-auth, and each safely testable recovered credential without
  violating the known lockout threshold, observation window, or scope?
- Can I list, read, upload, write, execute, or query anything?
- Did the banner, certificate, redirect, share, or response reveal another hostname or username?
- Is the version exact, and does the proposed exploit match OS, architecture, configuration,
  authentication, and path prerequisites?
- What single test would most clearly strengthen or kill this hypothesis?

## 0.5 Run the web foothold loop

Web is not one port. Repeat this loop for every origin and again after authentication.

1. **Resolve names.** Add every redirect, certificate SAN, email domain, page reference, and service
   hostname to `/etc/hosts`; then test it over every relevant web port.
2. **Browse normally through Burp Community.** Exercise registration, login, reset, search, upload,
   import/export, profile, admin, and API workflows. Preserve representative raw requests.
3. **Map before exploiting.** Record paths, methods, content types, hidden fields, JSON keys,
   cookies, custom headers, filenames, IDs, and auth state.
4. **Discover content and parameters.** Fuzz the root and each interesting directory; inspect JS,
   source maps, API documentation, backups, and alternate methods. See
   [§01.5 HTTP](01-recon-and-enumeration.md#15-http--https).
5. **Baseline responses.** Record status, byte/word/line count, redirect location, visible marker,
   and timing for a valid request and an invalid control.
6. **Change one variable.** Use matched true/false or fast/slow pairs. A single error is a lead, not
   confirmation.
7. **Convert capability to access.** Use the ladder in
   [§02 Web Attacks](02-web-attacks.md#24-convert-findings-into-a-foothold).

High-value input names include `file`, `page`, `path`, `template`, `cmd`, `host`, `url`, `redirect`,
`callback`, `image`, `document`, `id`, `user`, `role`, `format`, and `debug`. Names are only hints;
test every input context, including cookies and headers.

## 0.6 Time-box without becoming mechanical

Use checkpoints to force a change of perspective. They are decision prompts, not rigid exam rules.

### First 10 minutes

- Read the control-panel objective and create the ledgers.
- Start quick/full TCP and top-UDP scans.
- Manually open every obvious HTTP(S) origin and capture redirects, titles, and hostnames.

### By roughly 30 minutes

- Run targeted scripts/version detection on all discovered ports.
- Attempt anonymous/no-auth/guest access and inspect readable content.
- Build the first web entry-point map and start directory plus vhost discovery.
- Put the best three hypotheses in ranked order.

### Every 20–30 minutes after that

Ask:

- What new fact did this line of testing produce?
- What prerequisite for the proposed exploit is still unproven?
- Have I tested the same origin after adding the hostname or logging in?
- Did I inspect non-GET inputs, JS/API calls, cookies, headers, uploads, and alternate methods?
- Did I place every newly found credential into the cross-service matrix and test it only where
  the known lockout policy and protocol scope make that safe?
- Could the fast scan have missed a port, or could UDP/hostname routing expose another surface?

If a hypothesis produces no new evidence for about 20 minutes, record it and rotate to the next
surface. Return only when new evidence changes its probability. Do not spend an hour tuning a
payload for a vulnerability that has never been confirmed.

If two consecutive checkpoints on one standalone host produce no new evidence, preserve the queue
and rotate to another standalone target. This protects the chance of collecting multiple initial-
access scores. Return when a later hostname, credential, version, or cross-host pattern changes the
stalled host's evidence.

## 0.7 Re-enumeration triggers

Enumeration is cyclical. Restart the relevant parts of the loop after any of these events:

- a hostname, domain, certificate name, username, credential, key, or hash appears;
- a login changes from unauthenticated to authenticated;
- source code or a configuration file reveals routes, ports, paths, or dependencies;
- an upload location, writable share, or database privilege becomes known;
- a shell reveals listening services, interfaces, scheduled tasks, or local-only applications;
- a target is reverted or a scan and manual observation disagree.

At minimum, a new credential resets SMB, WinRM, RDP, SSH, FTP, databases, HTTP Basic auth, and web
login checks that are safe for the known lockout policy and observation window. A new hostname
resets web discovery.

## 0.8 Before leaving the foothold phase

- [ ] The low-privileged access path works a second time from clean steps.
- [ ] The exact vulnerable request, PoC edits, payload location, listener, and callback are recorded.
- [ ] A stable shell or interactive login is available; see [§03](03-shells-and-payloads.md).
- [ ] `whoami`/`id`, hostname, interfaces, OS, and architecture are captured.
- [ ] Required proof is submitted and screenshotted exactly as the current exam guide requires.
- [ ] Newly obtained credentials and hostnames have been fed back into enumeration.
- [ ] The privilege-escalation checklist starts immediately; do not keep polishing the foothold.
