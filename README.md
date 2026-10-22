# php-patch-verify

A portable **Agent Skill** that checks whether a PHP installation is patched
against the October 2026 remote-code-execution pair, and audits the interim
mitigations while you patch. The same `SKILL.md` works in **Claude**, **Claude
Code**, **Cursor**, **Codex**, and other tools that read the Agent Skills
standard.

Foundation: **CERT-EU Security Advisory 2026-018**
<https://cert.europa.eu/publications/security-advisories/2026-018>

- **CVE-2026-109618** — memory corruption during OOM handling (CVSS 9.2, unauth RCE).
- **CVE-2026-109619** — stale global state reused across requests (CVSS 9.2, unauth RCE).
- Fixed in PHP **8.5.12, 8.4.27, 8.3.36, 8.2.35**. Branches 8.1 and older are end-of-life.

It **verifies, it does not exploit.** It reads versions, inspects config, and
sends only benign requests. It never attempts to trigger either vulnerability,
so it is safe to run against production.

## Install

The repo is the skill folder (`SKILL.md` at the root). Put it where your tool
loads skills, by clone or symlink.

```bash
# Claude Code (user-level)
git clone <this-repo> ~/.claude/skills/php-patch-verify
# Cursor (also reads ~/.claude/skills for compatibility)
git clone <this-repo> ~/.cursor/skills/php-patch-verify
# Codex
git clone <this-repo> ~/.codex/skills/php-patch-verify
```

Requirement: [bun](https://bun.sh) to run the tools.

## Using it from an agent

1. **Automatically** — describe the task ("is this PHP patched", "check PHP
   version", "CVE-2026-109618") and the agent loads the skill from its
   description.
2. **Explicitly** — `/php-patch-verify` where the tool exposes skills as slash
   commands.

The agent then follows `SKILL.md`, running the tools below.

## Tools

```bash
# Verify (read-only)
bun Tools/CheckHost.ts --local                     # on the host: php -v, php -i
bun Tools/CheckHost.ts --url https://host/          # remote banner + cookie
bun Tools/CheckHost.ts --url https://host/ --probe  # active: banner-hidden + body-size cap
bun Tools/CheckHost.ts --url https://host/ --fingerprint  # is this PHP? (safe GETs)
bun Tools/CheckHost.ts --local --nginx /etc/nginx/nginx.conf --systemd unit.conf --cgroup
# output: --html (page), --json (SIEM/CI), --strict (CI exit), --no-color

# Generate mitigation config (generate-only; never touches a service)
bun Tools/Harden.ts --sapi fpm --version 8.3.36 [--uploads]
```

## Three strengths of evidence

| Mode | Strength | Proves |
|------|----------|--------|
| `--url` | observe | A hint. The banner can be stale, spoofed, or off. |
| `--url --probe` | active test | The hardening: banner hidden, body-size cap enforced. Not the CVE. |
| `--local` | proof | The running version. The only way to confirm the patch. |

Proving the RCE fix itself needs the on-host `--local` version check, or a
controlled lab exploit under separate authorization. This skill does not do the
latter.

## Layout

```
SKILL.md                     the skill entry point (Agent Skills format)
Tools/CheckHost.ts           verify: version + PHP config + nginx/apache/systemd/cgroup
Tools/Harden.ts              generate: PHP + server + cgroup + edge config
Workflows/VerifyFleet.md     sweep a fleet and record pass/fail
Workflows/MitigateHost.md    generate -> confirm-apply -> re-verify
references/Advisory.md       the CERT-EU advisory, for the checklist
```

Reference: CERT-EU Security Advisory 2026-018. Only the PHP update fully fixes
these vulnerabilities; mitigations reduce exposure.
