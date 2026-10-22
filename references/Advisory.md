# Source advisory — PHP critical RCE pair (October 2026)

CERT-EU Security Advisory 2026-018, v1.1, 21 October 2026.
<https://cert.europa.eu/publications/security-advisories/2026-018>
Reproduced for the skill's checklist.

## Summary

On 20 Oct 2026 the PHP project announced a security release for two critical
vulnerabilities. Fixes shipped 21 Oct 2026 13:30 UTC in PHP 8.5.12, 8.4.27,
8.3.36 and 8.2.35. Both allow unauthenticated remote code execution. PoCs
began circulating, so treat exploitation as likely in the wild. Patch
immediately; where that is not feasible, isolate internet-facing apps until a
fix is applied and verified.

## CVE-2026-109618 (GHSA-w8hw-w9fx-j79w, CVSS 9.2) — OOM memory corruption

PHP enforces `memory_limit` via `longjmp()` to abort an over-limit request,
raising an OOM error. This can interrupt PHP while request data is only
partially initialised (e.g. parsing a multipart file upload). Cleanup may then
free memory that was never initialised and may still hold attacker-controlled
data from earlier allocations.

## CVE-2026-109619 (GHSA-6wmf-4rv5-p3rp, CVSS 9.2) — stale global state

Internal state owned by a request can survive after its backing memory is freed
(e.g. after a fatal error). A later request on the same worker may use that
stale state before initialisation resets it.

## Affected

Every PHP install serving web requests: PHP-FPM, Apache mod_php, php-cgi,
FrankenPHP, LiteSpeed. **mod_php is the highest-risk setup.** One unauthenticated
request can trigger the attack before any application code runs.

- PHP 8.5 < 8.5.12
- PHP 8.4 < 8.4.27
- PHP 8.3 < 8.3.36
- PHP 8.2 < 8.2.35
- PHP 8.1 and older (EOL) — no project updates; vendor/source backports only.

Products that embed PHP may be affected even without a visible PHP install.
See NCSC-NL php2shell repo to identify embedded-PHP third-party software.

## Recommendation

Update to a fixed release ASAP. Distro/LTS vendors received patches in advance.
Minimal source backports exist for 7.4, 8.0, 8.1. rpms.remirepo.net will lag on
release day — switch to distro packages or build from source. Where patching is
not feasible, isolate internet-facing resources until fixed and verified.

## Temporary mitigations (reduce exposure; only the update fully fixes these)

CVE-2026-109618 (OOM corruption):
- `memory_limit=-1` set so apps cannot override (`php_admin_value` in FPM pool
  or Apache). Verify no pool/dir/app puts a finite limit back.
- Low `post_max_size`: 8M if no uploads needed, 32M if uploads required. Keep
  `upload_max_filesize` below `post_max_size`.
- Enforce decoded request-size, input-field-count, multipart-part-count,
  header-count and nesting-depth limits at the web server / proxy, including for
  requests with no usable Content-Length.
- Use a container/cgroup memory limit as an availability boundary that kills
  only the affected worker. Do NOT use RLIMIT_AS / RLIMIT_DATA — they can
  trigger the vulnerable allocation failure.

CVE-2026-109619 (stale global state):
- `session.upload_progress.enabled=0`, then restart every worker. Apply in
  php.ini / FPM pool / server config — not `ini_set()` or FPM `.user.ini`.
- On PHP 8.5, `fatal_error_backtraces=0`, then restart every worker.
- Remove invalid/deprecated per-request settings that emit diagnostics before
  initialisation. Hiding diagnostics (error_reporting, display_errors, @) does
  not help.
- Fix reachable fatal errors and execution timeouts, including in callbacks,
  upload/import processing and cleanup.

## References

- CERT-EU Security Advisory 2026-018: https://cert.europa.eu/publications/security-advisories/2026-018

- https://www.php.net/index.php#2026-10-20-1
- https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w
- https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp
- https://github.com/NCSC-NL/php2shell
