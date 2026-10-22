---
name: "php-patch-verify"
description: "Verify whether a PHP install is patched against the Oct 2026 critical RCE pair (CVE-2026-109618 OOM corruption, CVE-2026-109619 stale global state) and audit the CERT-EU interim mitigations. Read-only and non-intrusive: detects version and SAPI, inspects php.ini / FPM pool settings, reads remote version banners. Does NOT exploit either CVE. USE WHEN php patch, php vulnerability, CVE-2026-109618, CVE-2026-109619, php rce, verify patch, check php version, php mitigation, memory_limit, post_max_size, session.upload_progress, fatal_error_backtraces, mod_php, php-fpm, is this patched, confirm patched, app1 app2 app3 php."
metadata:
  source: authored
  authored: 2026-10-22
---
# php-patch-verify

Confirms whether a PHP installation is fixed against the two critical
unauthenticated-RCE vulnerabilities disclosed on 20–21 October 2026, and
audits the interim mitigations CERT-EU recommends where patching has to wait.

- **CVE-2026-109618** (CVSS 9.2) — memory corruption during out-of-memory handling.
- **CVE-2026-109619** (CVSS 9.2) — stale global state reused across requests.

Fixed releases: **8.5.12, 8.4.27, 8.3.36, 8.2.35**. Branches 8.1 and older are
end-of-life; only a vendor or source backport fixes them.

## How to test a host — the short version

1. **Is it PHP?** `bun Tools/CheckHost.ts --url https://HOST/ --fingerprint`
   (the version banner is often off, so confirm it is PHP first).
2. **What version?** On the host: `bun Tools/CheckHost.ts --local`. This is the
   only step that *proves* the patch. A remote `--url` banner is a hint, not proof.
3. **Are the mitigations in place?** `--local` or `--ini FILE`, plus
   `--nginx` / `--apache` / `--systemd` / `--cgroup`. Add `--probe` to a `--url`
   run to test them against a live host.
4. **Fix if needed:** `bun Tools/Harden.ts --sapi SAPI --version X.Y.Z` prints the
   config; apply it (confirmed), restart workers, then re-run steps 2–3.
5. **Record:** add `--html` for a shareable page, or `--json` for SIEM / CI.

Only step 2 on the host proves the patch. Everything remote is a hint or a
hardening test, never proof of the fix.

## Scope — what this skill does and does not do

**Does:** version detection, SAPI identification, configuration auditing of the
exact settings in the advisory, and remote version-banner reading. It is
read-only and safe to run against production app1, app2 and app3.

**Does not:** send crafted payloads, attempt to trigger either vulnerability, or
prove exploitability. A verifier answers "is the fix in place"; it does not
attack. An actual exploitation test is a separate, scoped engagement — not this
skill. This boundary is deliberate: it keeps the tool safe to run on live
systems and keeps its output trustworthy as patch evidence.

## When to use

- After deploying a PHP update, to confirm every host now reports a fixed version.
- To audit the interim mitigations on a host that cannot be patched yet.
- To sweep a fleet (app1, app2, app3) and produce a pass/fail record per host.

## Authorization

Run only against systems you are authorized to assess — here, your-org's own
estate. The tool touches only version strings, config files and response
headers, but the authorization rule stands.

## The tools

Two CLIs, run with bun. `CheckHost.ts` verifies; `Harden.ts` generates config.
Neither exploits a CVE, and `Harden.ts` only prints or writes files you review —
it never touches a running service.

### CheckHost.ts — verify (read-only)

```bash
cd ~/.soma/skills/php-patch-verify/Tools

# PHP layer — pick one:
bun CheckHost.ts --local                               # on the host (php -v, php -i)
bun CheckHost.ts --ini /etc/php/8.3/fpm/pool.d/app3.conf --uploads
bun CheckHost.ts --url https://host.example.com/      # remote banner (headers only)
bun CheckHost.ts --url https://host/ --fingerprint  # is this PHP? (safe GETs)
bun CheckHost.ts --url https://host/ --probe       # active: banner gone + body-size cap
bun CheckHost.ts --version 8.3.36

# Server layer (O2) — combine freely, with or without a PHP-layer mode:
bun CheckHost.ts --local \
  --nginx /etc/nginx/nginx.conf \
  --systemd /etc/systemd/system/php8.3-fpm.service.d/memory.conf \
  --cgroup
# also: --apache /etc/apache2/apache2.conf
```

Flags: `--uploads` raises the body-size ceiling from 8M to 32M; `--json` emits
machine-readable output for Logpush / SIEM / CI. By default it exits 0, so a normal run is not shown as an error. Add
`--strict` to make the exit non-zero when action is required, for a cron or
pipeline gate. `--no-color` disables ANSI colour.

### Harden.ts — generate mitigation config (O1, generate-only)

Emits ready-to-review drop-ins tailored to the SAPI, version and whether the app
needs uploads: the PHP settings (as `php_admin_value` so apps can't override),
nginx and Apache request limits, and a systemd cgroup memory bound — with the
advisory's warning against `RLIMIT_AS` / `RLIMIT_DATA`.

```bash
bun Harden.ts --sapi fpm --version 8.3.36            # print FPM + server + cgroup config
bun Harden.ts --sapi apache --version 8.5.12 --uploads
bun Harden.ts --sapi ini                             # plain php.ini fragment
bun Harden.ts --sapi fpm --version 8.3.36 --out ./hardening   # also write files
```

Applying the output is a separate, confirmed step — see `Workflows/MitigateHost.md`.
Per soma policy, a change to a live host is a proposal, principal-gated, never
auto-applied. Back up, apply, restart every worker, then re-run `CheckHost.ts`.

## Observe vs. test — what each mode can actually prove

A remote banner is observation. It can be stale, spoofed, or switched off, so it
can never prove the patch level. There are three honestly different strengths of
evidence, and the tool is explicit about which one it is giving:

- **Observe (`--url`).** Reads the version banner and the `PHPSESSID` cookie. A
  hint only. `expose_php=Off` hides the version entirely, so a clean banner proves
  nothing about the patch.
- **Test the hardening (`--url --probe`).** Sends benign requests and asserts on
  the response: that the PHP banner is really gone, and that a benign oversized
  POST is rejected (413/400), proving the request-size cap is enforced rather than
  merely configured. It is an active test, but of the mitigations, not the CVE.
  Behind Access it tests the edge, not the origin, and says so.
- **Verify the patch (`--local`), authoritative.** Runs `php -v` / `php -i` on the
  host. This is the only thing that proves the running version is fixed. Fan it out
  across the fleet over SSH or a config tool, e.g.:

  ```bash
  for h in app1 app2 app3; do
    ssh "$h" 'bun ~/.soma/skills/php-patch-verify/Tools/CheckHost.ts --local --json'
  done
  ```

What the tool deliberately does **not** do is prove the RCE fix remotely by firing
the exploit. The only ways to know a host is patched are the on-host version check
above, or a controlled exploit attempt in a non-production lab under its own
authorization — a separate pentest engagement, not this skill. So for a host like
`app1.example.com` where all we can see from outside is the header, the honest
next step is an on-host `--local` run, not a remote guess.

### Mode choice

| Question | Mode |
|----------|------|
| Is the running version actually fixed? | `--local` on the host (authoritative) |
| Are the mitigations configured? | `--local` or `--ini <pool/ini file>` |
| Quick external view of app3 from outside | `--url` (banner only; cannot confirm patch level) |
| Is this even PHP? (banner may be off) | `--url --fingerprint` |
| Test the mitigations against a live host | `--url --probe` |

The remote banner is a hint, not proof. `expose_php=Off` (correct hardening)
hides the version entirely, so a clean banner check still needs a `--local` or
`--ini` run on the host to confirm the patch.

## Reading the report

One overall verdict, then the checks grouped by severity (failures first).

- **Overall verdict:** `PATCHED` (version at or above the fix, nothing failing),
  `ACTION REQUIRED` (a vulnerable version or any FAIL), or `INCONCLUSIVE` (could
  not determine — usually a remote scan with the banner off, meaning "run `--local`").
- **Per check:**
  - `FAIL` — a real problem: a vulnerable version, or a mitigation that is off.
  - `WARN` — a gap to tighten: no body-size cap, banner exposed, a missing limit.
  - `PASS` — the control is in place.
  - `INFO` — context, not pass/fail: response headers, fingerprint tells.
- Each line shows a code (`VER`, `M1`, `T1`, `FP`) and a one-line fix. The summary
  line repeats the counts and the overall verdict.
- Exit is 0 by default; add `--strict` to exit non-zero on `ACTION REQUIRED` for CI.

## What it checks

| Code | Check | Maps to |
|------|-------|---------|
| VER  | Installed version vs. the fixed release for its branch; EOL branches flagged | Patch status |
| SAPI | mod_php flagged as the PHP team's highest-risk setup | Prioritisation |
| M1   | `memory_limit=-1`, enforced via `php_admin_value` | CVE-2026-109618 |
| M2   | `post_max_size` ≤ 8M (or 32M with `--uploads`) | CVE-2026-109618 |
| M3   | `upload_max_filesize` ≤ `post_max_size` | CVE-2026-109618 |
| M4   | `session.upload_progress.enabled=0` | CVE-2026-109619 |
| M5   | `fatal_error_backtraces=0` (PHP 8.5 only) | CVE-2026-109619 |
| H1   | `expose_php=Off` | Hardening / banner |
| NGX1/2 | nginx `client_max_body_size`, header buffers | CVE-2026-109618 |
| APA1-4 | Apache `LimitRequestBody` / `LimitRequest*` | CVE-2026-109618 |
| SYS1 | systemd `LimitAS`/`LimitDATA` present → FAIL (advisory warns against these) | CVE-2026-109618 |
| SYS2/CG1 | systemd `MemoryMax` / cgroup `memory.max` bound | Availability boundary |

Limits the tool cannot see on its own, and that the report calls out:

- Whether a setting is **locked** with `php_admin_value` versus merely set — `php -i`
  shows the effective value, not the lock. Confirm the lock in the FPM pool or
  Apache config.
- Web-server / proxy request-size limits (decoded body size, field count,
  multipart parts, header count and nesting), and container / cgroup memory
  limits. These live in nginx/Apache/HAProxy/Cloudflare and the container
  runtime, not in PHP config, so verify them there. Do not use `RLIMIT_AS` /
  `RLIMIT_DATA` — the advisory warns they can trigger the vulnerable path.
- Worker restarts. Several mitigations only take effect after every worker
  restarts; the tool reminds but cannot confirm it.

## Relationship to the Cloudflare Zero Trust work

Putting app3 (and optionally app1/app2) behind Cloudflare Access reduces who can
reach the vulnerable code, but **Access is not a patch** — an authenticated
user, or any gap in the policy, still reaches PHP. Cloudflare WAF managed rules
can block known exploit signatures at the edge as defence-in-depth. Patching to
a fixed version remains the only full fix. Use this skill to prove the patch
regardless of what sits in front of the app.

Primary source: CERT-EU Security Advisory 2026-018
(<https://cert.europa.eu/publications/security-advisories/2026-018>).

See `Workflows/VerifyFleet.md` for the host-sweep procedure and
`references/Advisory.md` for the full CERT-EU text and mitigation rationale.
