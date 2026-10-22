#!/usr/bin/env bun
/**
 * PHP Patch & Mitigation Verifier
 *
 * Verifies whether a PHP installation is patched against the October 2026
 * critical RCE pair (CVE-2026-109618 OOM corruption, CVE-2026-109619 stale
 * global state) and audits the CERT-EU interim mitigations.
 *
 * SCOPE: This tool is read-only and non-intrusive. It detects versions and
 * inspects configuration. It never sends crafted payloads and never attempts
 * to trigger either vulnerability. It is safe to run against production.
 *
 * Modes (pick one):
 *   --local                 Run `php -v` and `php -i` on this host.
 *   --ini <file>            Parse a php.ini / FPM pool .conf and audit settings.
 *   --url <url>             Read HTTP response headers only; extract the PHP
 *                           version banner if the server exposes one.
 *   --version <x.y.z>       Evaluate a version string with no host access.
 *
 * Options:
 *   --uploads               Target app legitimately needs file uploads
 *                           (relaxes the post_max_size ceiling to 32M).
 *   --json                  Emit the report as JSON.
 *
 * Exit code: 0 if PATCHED and no FAIL checks; 1 otherwise. Good for CI / cron.
 */

import { readFileSync } from "fs";
import { execFileSync } from "child_process";

// ── Fixed releases (CERT-EU advisory v1.1, 21 Oct 2026) ──────────────
// A branch is patched at or above these patch levels.
const FIXED: Record<string, [number, number, number]> = {
  "8.5": [8, 5, 12],
  "8.4": [8, 4, 27],
  "8.3": [8, 3, 36],
  "8.2": [8, 2, 35],
};
const EOL_BRANCHES = ["8.1", "8.0", "7.4", "7.3", "7.2", "7.1", "7.0", "5"];

type Status = "PASS" | "FAIL" | "WARN" | "INFO";
interface Check {
  id: string;
  status: Status;
  title: string;
  detail: string;
}

// ── Version handling ─────────────────────────────────────────────────

function parseVersion(v: string): [number, number, number] | null {
  const m = v.match(/(\d+)\.(\d+)\.(\d+)/);
  if (!m) return null;
  return [Number(m[1]), Number(m[2]), Number(m[3])];
}

function cmp(a: [number, number, number], b: [number, number, number]): number {
  for (let i = 0; i < 3; i++) if (a[i] !== b[i]) return a[i] - b[i];
  return 0;
}

function evalVersion(raw: string, checks: Check[]): "patched" | "vulnerable" | "unknown" {
  const parsed = parseVersion(raw);
  if (!parsed) {
    checks.push({ id: "VER", status: "WARN", title: "PHP version",
      detail: `Could not parse a version from "${raw}". Check manually.` });
    return "unknown";
  }
  const branch = `${parsed[0]}.${parsed[1]}`;
  const verStr = parsed.join(".");

  if (EOL_BRANCHES.some((b) => branch === b || branch.startsWith(b + "."))) {
    checks.push({ id: "VER", status: "FAIL", title: "PHP version",
      detail: `${verStr} is on end-of-life branch ${branch}. The PHP project ships no updates for it. ` +
        `A vendor/LTS backport or a source backport (7.4/8.0/8.1) may exist; confirm with your vendor. ` +
        `Treat as vulnerable until a backported fix is confirmed installed.` });
    return "vulnerable";
  }

  const fix = FIXED[branch];
  if (!fix) {
    checks.push({ id: "VER", status: "WARN", title: "PHP version",
      detail: `${verStr}: branch ${branch} is not in the advisory's fixed list. ` +
        `If it is newer than 8.5, it is almost certainly fixed; confirm against php.net.` });
    return "unknown";
  }

  if (cmp(parsed, fix) >= 0) {
    checks.push({ id: "VER", status: "PASS", title: "PHP version",
      detail: `${verStr} is at or above the fixed release ${fix.join(".")} for branch ${branch}. Patched.` });
    return "patched";
  }
  checks.push({ id: "VER", status: "FAIL", title: "PHP version",
    detail: `${verStr} is BELOW the fixed release ${fix.join(".")} for branch ${branch}. ` +
      `Vulnerable to CVE-2026-109618 and CVE-2026-109619. Update now.` });
  return "vulnerable";
}

// ── ini parsing helpers ──────────────────────────────────────────────

type IniMap = Record<string, string>;

function parsePhpIni(text: string): IniMap {
  // Handles `php -i` output ("key => value => value"), php.ini ("key = value"),
  // and FPM pool lines ("php_admin_value[key] = value").
  const map: IniMap = {};
  for (const line of text.split(/\r?\n/)) {
    const l = line.trim();
    if (!l || l.startsWith(";") || l.startsWith("#") || l.startsWith("[")) continue;

    // php -i : "memory_limit => 128M => 128M"  (take the local/first value)
    const arrow = l.match(/^([A-Za-z0-9_.]+)\s*=>\s*([^=]*?)(?:\s*=>.*)?$/);
    if (arrow) { map[arrow[1].toLowerCase()] = arrow[2].trim(); continue; }

    // FPM pool: php_admin_value[memory_limit] = -1  /  php_value[...] = ...
    const fpm = l.match(/^php_(?:admin_)?(?:value|flag)\[([^\]]+)\]\s*=\s*(.*)$/i);
    if (fpm) { map[fpm[1].toLowerCase()] = fpm[2].trim(); continue; }

    // plain ini: key = value
    const kv = l.match(/^([A-Za-z0-9_.]+)\s*=\s*(.*)$/);
    if (kv) map[kv[1].toLowerCase()] = kv[2].trim();
  }
  return map;
}

function toBytes(v: string | undefined): number | null {
  if (v == null) return null;
  const s = v.trim();
  if (s === "" ) return null;
  const m = s.match(/^(-?\d+)\s*([KMG])?$/i);
  if (!m) return null;
  let n = Number(m[1]);
  const unit = (m[2] || "").toUpperCase();
  if (unit === "K") n *= 1024;
  else if (unit === "M") n *= 1024 * 1024;
  else if (unit === "G") n *= 1024 * 1024 * 1024;
  return n;
}

function isOff(v: string | undefined): boolean {
  if (v == null) return false;
  const s = v.trim().toLowerCase();
  return s === "0" || s === "off" || s === "false" || s === "no" || s === "";
}

// ── Mitigation audit ─────────────────────────────────────────────────

function auditConfig(ini: IniMap, opts: { uploads: boolean; branch?: string }, checks: Check[]) {
  const uploadCeil = opts.uploads ? 32 * 1024 * 1024 : 8 * 1024 * 1024;
  const ceilLabel = opts.uploads ? "32M" : "8M";

  // CVE-2026-109618 ── memory_limit must be -1, enforced so apps can't override.
  const ml = ini["memory_limit"];
  if (ml === undefined) {
    checks.push({ id: "M1", status: "INFO", title: "memory_limit (CVE-2026-109618)",
      detail: "Not visible in the supplied data. Advisory: set memory_limit=-1 via php_admin_value so no pool/dir/app can set a finite limit." });
  } else if (ml.trim() === "-1") {
    checks.push({ id: "M1", status: "PASS", title: "memory_limit (CVE-2026-109618)",
      detail: "memory_limit=-1. Confirm it is set with php_admin_value (FPM) or Apache so applications cannot override it; php -i alone cannot prove the lock." });
  } else {
    checks.push({ id: "M1", status: "FAIL", title: "memory_limit (CVE-2026-109618)",
      detail: `memory_limit=${ml}. A finite, controllable limit keeps the vulnerable OOM path reachable. Advisory mitigation is memory_limit=-1 enforced via php_admin_value. (Only the patch fully fixes this.)` });
  }

  // post_max_size ceiling.
  const pms = toBytes(ini["post_max_size"]);
  if (pms === null) {
    checks.push({ id: "M2", status: "INFO", title: "post_max_size (CVE-2026-109618)",
      detail: `Not visible. Advisory: keep post_max_size low — ${ceilLabel} for this profile.` });
  } else if (pms <= uploadCeil) {
    checks.push({ id: "M2", status: "PASS", title: "post_max_size (CVE-2026-109618)",
      detail: `post_max_size=${ini["post_max_size"]} is within the ${ceilLabel} ceiling.` });
  } else {
    checks.push({ id: "M2", status: "WARN", title: "post_max_size (CVE-2026-109618)",
      detail: `post_max_size=${ini["post_max_size"]} exceeds the ${ceilLabel} ceiling for this profile. Lower it to shrink the attack surface.` });
  }

  // upload_max_filesize <= post_max_size.
  const umf = toBytes(ini["upload_max_filesize"]);
  if (umf !== null && pms !== null) {
    if (umf <= pms) {
      checks.push({ id: "M3", status: "PASS", title: "upload_max_filesize (CVE-2026-109618)",
        detail: `upload_max_filesize=${ini["upload_max_filesize"]} ≤ post_max_size. Good.` });
    } else {
      checks.push({ id: "M3", status: "WARN", title: "upload_max_filesize (CVE-2026-109618)",
        detail: `upload_max_filesize=${ini["upload_max_filesize"]} is larger than post_max_size. Keep it below post_max_size.` });
    }
  }

  // CVE-2026-109619 ── session.upload_progress.enabled must be 0.
  const sup = ini["session.upload_progress.enabled"];
  if (sup === undefined) {
    checks.push({ id: "M4", status: "INFO", title: "session.upload_progress.enabled (CVE-2026-109619)",
      detail: "Not visible. Advisory: set session.upload_progress.enabled=0 in php.ini / FPM pool / server config (not ini_set or .user.ini) and restart every worker." });
  } else if (isOff(sup)) {
    checks.push({ id: "M4", status: "PASS", title: "session.upload_progress.enabled (CVE-2026-109619)",
      detail: "Disabled. Confirm it is set before request parsing (php.ini or FPM pool, not .user.ini) and that all workers were restarted." });
  } else {
    checks.push({ id: "M4", status: "FAIL", title: "session.upload_progress.enabled (CVE-2026-109619)",
      detail: `Set to "${sup}". This leaves a confirmed stale-state path open. Set it to 0 and restart every worker.` });
  }

  // fatal_error_backtraces must be 0 on 8.5 only.
  const feb = ini["fatal_error_backtraces"];
  const is85 = opts.branch === "8.5";
  if (is85) {
    if (feb === undefined) {
      checks.push({ id: "M5", status: "INFO", title: "fatal_error_backtraces (CVE-2026-109619, PHP 8.5)",
        detail: "Not visible. On PHP 8.5, set fatal_error_backtraces=0 and restart every worker." });
    } else if (isOff(feb)) {
      checks.push({ id: "M5", status: "PASS", title: "fatal_error_backtraces (CVE-2026-109619, PHP 8.5)",
        detail: "Disabled on 8.5. Blocks the confirmed fatal-backtrace path." });
    } else {
      checks.push({ id: "M5", status: "FAIL", title: "fatal_error_backtraces (CVE-2026-109619, PHP 8.5)",
        detail: `Set to "${feb}" on 8.5. Set it to 0 and restart every worker.` });
    }
  }

  // expose_php — hardening; also drives whether remote banner leaks the version.
  const ep = ini["expose_php"];
  if (ep !== undefined) {
    if (isOff(ep)) {
      checks.push({ id: "H1", status: "PASS", title: "expose_php (hardening)",
        detail: "Off. The server will not advertise its PHP version in the X-Powered-By header." });
    } else {
      checks.push({ id: "H1", status: "WARN", title: "expose_php (hardening)",
        detail: "On. The PHP version is advertised to anyone. Consider expose_php=Off; it does not fix the CVEs but removes a free banner for attackers." });
    }
  }
}

// ── SAPI risk note ───────────────────────────────────────────────────

function sapiNote(sapi: string, checks: Check[]) {
  const s = sapi.toLowerCase();
  if (s.includes("apache") || s.includes("mod_php")) {
    checks.push({ id: "SAPI", status: "WARN", title: "SAPI",
      detail: `${sapi}: mod_php is the PHP team's highest-risk setup for this pair. Prioritise patching these hosts first.` });
  } else {
    checks.push({ id: "SAPI", status: "INFO", title: "SAPI",
      detail: `${sapi}. All web SAPIs are affected (PHP-FPM, mod_php, php-cgi, FrankenPHP, LiteSpeed); mod_php is highest risk.` });
  }
}

// ── Server-layer audits (O2: controls that do not live in PHP) ───────

function auditNginx(file: string, uploads: boolean, checks: Check[]) {
  let text = "";
  try { text = readFileSync(file, "utf8"); }
  catch (e) { checks.push({ id: "NGX", status: "WARN", title: "nginx config",
    detail: `Cannot read ${file}: ${(e as Error).message}` }); return; }
  const ceil = uploads ? 32 * 1024 * 1024 : 8 * 1024 * 1024;
  const ceilLabel = uploads ? "32M" : "8M";
  const m = text.match(/client_max_body_size\s+([0-9]+[kKmMgG]?)/);
  if (!m) {
    checks.push({ id: "NGX1", status: "WARN", title: "nginx client_max_body_size (CVE-2026-109618)",
      detail: `Not set in ${file}. nginx defaults to 1M, but set it explicitly to ${ceilLabel} to match post_max_size and cap decoded body size.` });
  } else {
    const b = toBytes(m[1]);
    if (b !== null && b <= ceil) {
      checks.push({ id: "NGX1", status: "PASS", title: "nginx client_max_body_size (CVE-2026-109618)",
        detail: `client_max_body_size ${m[1]} is within the ${ceilLabel} ceiling.` });
    } else {
      checks.push({ id: "NGX1", status: "WARN", title: "nginx client_max_body_size (CVE-2026-109618)",
        detail: `client_max_body_size ${m[1]} exceeds the ${ceilLabel} ceiling. Lower it to shrink the request-size attack surface.` });
    }
  }
  if (/large_client_header_buffers/.test(text)) {
    checks.push({ id: "NGX2", status: "PASS", title: "nginx header buffers",
      detail: "large_client_header_buffers is set, capping header count/size." });
  } else {
    checks.push({ id: "NGX2", status: "INFO", title: "nginx header buffers",
      detail: "large_client_header_buffers not set. Consider `large_client_header_buffers 4 8k;` to cap header count and size." });
  }
}

function auditApache(file: string, uploads: boolean, checks: Check[]) {
  let text = "";
  try { text = readFileSync(file, "utf8"); }
  catch (e) { checks.push({ id: "APA", status: "WARN", title: "Apache config",
    detail: `Cannot read ${file}: ${(e as Error).message}` }); return; }
  const ceil = uploads ? 32 * 1024 * 1024 : 8 * 1024 * 1024;
  const ceilLabel = uploads ? "32M" : "8M";
  const lrb = text.match(/LimitRequestBody\s+(\d+)/i);
  if (!lrb) {
    checks.push({ id: "APA1", status: "WARN", title: "Apache LimitRequestBody (CVE-2026-109618)",
      detail: `Not set in ${file}. Default is unlimited. Set LimitRequestBody to ~${ceilLabel} (${ceil} bytes) to cap body size.` });
  } else {
    const b = Number(lrb[1]);
    if (b > 0 && b <= ceil) {
      checks.push({ id: "APA1", status: "PASS", title: "Apache LimitRequestBody (CVE-2026-109618)",
        detail: `LimitRequestBody ${b} is within the ${ceilLabel} ceiling.` });
    } else {
      checks.push({ id: "APA1", status: "WARN", title: "Apache LimitRequestBody (CVE-2026-109618)",
        detail: `LimitRequestBody ${b} (0 = unlimited) exceeds the ${ceilLabel} ceiling. Lower it.` });
    }
  }
  for (const [dir, id] of [["LimitRequestFields", "APA2"], ["LimitRequestFieldSize", "APA3"], ["LimitRequestLine", "APA4"]] as const) {
    if (new RegExp(dir, "i").test(text)) {
      checks.push({ id, status: "PASS", title: `Apache ${dir}`, detail: `${dir} is set.` });
    } else {
      checks.push({ id, status: "INFO", title: `Apache ${dir}`, detail: `${dir} not set; consider capping it.` });
    }
  }
}

function auditSystemd(file: string, checks: Check[]) {
  let text = "";
  try { text = readFileSync(file, "utf8"); }
  catch (e) { checks.push({ id: "SYS", status: "WARN", title: "systemd unit",
    detail: `Cannot read ${file}: ${(e as Error).message}` }); return; }
  // The advisory: use cgroup MemoryMax, NOT RLIMIT_AS/RLIMIT_DATA.
  const badAS = /^\s*LimitAS\s*=/im.test(text);
  const badDATA = /^\s*LimitDATA\s*=/im.test(text);
  if (badAS || badDATA) {
    checks.push({ id: "SYS1", status: "FAIL", title: "systemd RLIMIT (CVE-2026-109618)",
      detail: `${[badAS && "LimitAS", badDATA && "LimitDATA"].filter(Boolean).join(" and ")} is set in ${file}. ` +
        `The advisory warns these (RLIMIT_AS/RLIMIT_DATA) can TRIGGER the vulnerable allocation failure. Remove them and bound memory with cgroup MemoryMax instead.` });
  } else {
    checks.push({ id: "SYS1", status: "PASS", title: "systemd RLIMIT (CVE-2026-109618)",
      detail: "No LimitAS / LimitDATA set. Good — those can trigger the vulnerable path." });
  }
  if (/^\s*MemoryMax\s*=/im.test(text)) {
    checks.push({ id: "SYS2", status: "PASS", title: "systemd MemoryMax",
      detail: "MemoryMax is set — a cgroup availability boundary that kills only this unit." });
  } else {
    checks.push({ id: "SYS2", status: "INFO", title: "systemd MemoryMax",
      detail: "MemoryMax not set. Add a cgroup memory bound (MemoryMax=) so an OOM kills the worker, not the host." });
  }
}

function auditCgroup(path: string | undefined, checks: Check[]) {
  // cgroup v2 first, then v1.
  const v2 = path || "/sys/fs/cgroup/memory.max";
  const v1 = "/sys/fs/cgroup/memory/memory.limit_in_bytes";
  let raw: string | null = null;
  let src = v2;
  try { raw = readFileSync(v2, "utf8").trim(); }
  catch {
    try { raw = readFileSync(v1, "utf8").trim(); src = v1; }
    catch { raw = null; }
  }
  if (raw === null) {
    checks.push({ id: "CG1", status: "INFO", title: "cgroup memory bound",
      detail: `Could not read a cgroup memory limit (tried ${v2}${path ? "" : " and " + v1}). Run on the host/container, or pass --cgroup <path>.` });
    return;
  }
  // v2 "max" or v1 a huge sentinel = unlimited.
  if (raw === "max" || /^(9223372036854771712|18446744073709551615)$/.test(raw)) {
    checks.push({ id: "CG1", status: "WARN", title: "cgroup memory bound",
      detail: `${src} = ${raw} (unlimited). Set a memory bound so an OOM kills the worker, not the host.` });
  } else {
    checks.push({ id: "CG1", status: "PASS", title: "cgroup memory bound",
      detail: `${src} = ${raw} bytes. A bounded worker limits OOM blast radius. (Confirm it is a cgroup limit, not RLIMIT_AS/DATA.)` });
  }
}

// ── Modes ────────────────────────────────────────────────────────────

function runLocal(checks: Check[], opts: { uploads: boolean }): string | undefined {
  let vout = "";
  try {
    vout = execFileSync("php", ["-v"], { encoding: "utf8" });
  } catch {
    checks.push({ id: "VER", status: "FAIL", title: "PHP version",
      detail: "`php` is not on PATH on this host. Run this on the host that serves the app, or point --ini at its config." });
    return undefined;
  }
  const verLine = vout.split(/\r?\n/)[0] || "";
  const ver = (verLine.match(/PHP (\d+\.\d+\.\d+)/) || [])[1] || verLine;
  const verdict = evalVersion(ver, checks);
  const branch = (parseVersion(ver) || []).slice(0, 2).join(".");

  // SAPI from `php -v` second token or `php -i`.
  let sapi = "cli";
  try {
    const iout = execFileSync("php", ["-i"], { encoding: "utf8" });
    const sm = iout.match(/Server API\s*=>\s*(.+)/);
    if (sm) sapi = sm[1].trim();
    sapiNote(sapi, checks);
    auditConfig(parsePhpIni(iout), { uploads: opts.uploads, branch }, checks);
  } catch {
    checks.push({ id: "CFG", status: "WARN", title: "Configuration",
      detail: "Could not run `php -i` to read the effective configuration. Supply the config with --ini instead." });
  }
  return verdict;
}

async function runUrl(url: string, checks: Check[]) {
  let res: Response;
  try {
    res = await fetch(url, { method: "GET", redirect: "manual" });
  } catch (e) {
    checks.push({ id: "VER", status: "WARN", title: "PHP version (remote banner)",
      detail: `Could not reach ${url}: ${(e as Error).message}` });
    return;
  }
  const xp = res.headers.get("x-powered-by") || "";
  const srv = res.headers.get("server") || "";
  const banner = (xp + " " + srv).match(/PHP\/(\d+\.\d+\.\d+)/);
  checks.push({ id: "HTTP", status: "INFO", title: "Response headers",
    detail: `HTTP ${res.status}. Server: "${srv || "(none)"}". X-Powered-By: "${xp || "(none)"}".` });
  if (banner) {
    evalVersion(banner[1], checks);
    checks.push({ id: "BANNER", status: "WARN", title: "Version banner exposed",
      detail: "The server advertised its PHP version. Set expose_php=Off so this banner is not handed to attackers." });
  } else {
    checks.push({ id: "VER", status: "INFO", title: "PHP version (remote banner)",
      detail: "No PHP version in the response headers. Either this is not PHP, or expose_php is Off (good). " +
        "The banner cannot confirm the patch level — run --local or --ini on the host to verify the actual version." });
  }
  // PHPSESSID is a second PHP tell, independent of the header.
  const cookies = typeof (res.headers as any).getSetCookie === "function"
    ? (res.headers as any).getSetCookie() as string[]
    : [res.headers.get("set-cookie") || ""];
  if (cookies.some((c) => /(^|[\s;])PHPSESSID=/i.test(c))) {
    checks.push({ id: "COOKIE", status: "WARN", title: "PHPSESSID cookie (fingerprint)",
      detail: "The default PHPSESSID cookie is set, which fingerprints PHP regardless of the header. Rename it with session.name." });
  } else if (cookies.some((c) => c.trim() !== "")) {
    checks.push({ id: "COOKIE", status: "PASS", title: "Session cookie (fingerprint)",
      detail: "No default PHPSESSID cookie seen — the session cookie does not advertise PHP." });
  }
}

// ── Active probe (opt-in): TEST enforcement, not just observe headers ──
// Sends benign requests and asserts on the response. It does NOT attempt to
// trigger either CVE — it cannot confirm the patch, only the hardening.
async function runProbe(url: string, sizeBytes: number, checks: Check[]) {
  // 1. Header-hygiene TEST: assert the PHP banner is actually gone.
  try {
    const r = await fetch(url, { method: "GET", redirect: "manual" });
    const xp = r.headers.get("x-powered-by") || "";
    if (/PHP/i.test(xp)) {
      checks.push({ id: "T1", status: "FAIL", title: "banner-hidden test",
        detail: `X-Powered-By still exposes "${xp}". The leak is NOT closed. Apply the Transform Rule and/or expose_php=Off.` });
    } else {
      checks.push({ id: "T1", status: "PASS", title: "banner-hidden test",
        detail: "No PHP version in X-Powered-By on a live request. The header leak is closed at this layer." });
    }
  } catch (e) {
    checks.push({ id: "T1", status: "WARN", title: "banner-hidden test", detail: `GET failed: ${(e as Error).message}` });
  }

  // 2. Body-size enforcement TEST: a benign oversized POST should be rejected
  //    (413/400) before the app, proving the request-size cap is enforced.
  const body = "probe=" + "A".repeat(Math.max(0, sizeBytes - 6));
  try {
    const r = await fetch(url, { method: "POST", redirect: "manual",
      headers: { "content-type": "application/x-www-form-urlencoded" }, body });
    const mb = (sizeBytes / 1048576).toFixed(1);
    if (r.status === 413 || r.status === 400) {
      checks.push({ id: "T2", status: "PASS", title: "body-size cap test",
        detail: `A benign ${mb}MB POST was rejected with HTTP ${r.status}. The request-size cap is enforced at this layer.` });
    } else if (r.status === 301 || r.status === 302 || r.status === 303) {
      checks.push({ id: "T2", status: "INFO", title: "body-size cap test",
        detail: `The ${mb}MB POST was redirected (HTTP ${r.status}), likely to an Access/login page, so the cap was not exercised at the origin. Test from inside the trust boundary, or against the proxy directly.` });
    } else {
      checks.push({ id: "T2", status: "WARN", title: "body-size cap test",
        detail: `A ${mb}MB POST returned HTTP ${r.status}, not 413/400. The body-size cap may be higher than ${mb}MB or not enforced here. Lower post_max_size / client_max_body_size, or raise --probe-size to match.` });
    }
  } catch (e) {
    checks.push({ id: "T2", status: "WARN", title: "body-size cap test", detail: `POST failed: ${(e as Error).message}` });
  }
}

// ── Fingerprint (opt-in): is this even PHP? Short, safe GETs only ─────
// Probabilistic, never proof. A fixed small list — not content discovery.
async function runFingerprint(url: string, checks: Check[]) {
  const base = url.replace(/\/+$/, "");
  const tells: string[] = [];
  const get = async (path: string) => {
    try { return await fetch(base + path, { method: "GET", redirect: "manual" }); }
    catch { return null; }
  };

  // 1. Framework / PHP session cookies (independent of the version banner).
  const r0 = await get("/");
  if (r0) {
    const cookies = typeof (r0.headers as any).getSetCookie === "function"
      ? (r0.headers as any).getSetCookie() as string[]
      : [r0.headers.get("set-cookie") || ""];
    const m = cookies.join("; ").match(/\b(PHPSESSID|laravel_session|symfony|ci_session|CAKEPHP|XSRF-TOKEN|wordpress_[a-z]*)/i);
    if (m) { tells.push(`cookie ${m[1]}`);
      checks.push({ id: "FP1", status: "INFO", title: "Framework cookie (fingerprint)",
        detail: `Set-Cookie includes "${m[1]}", a PHP-stack tell.` }); }
  }

  // 2. Does a .php entry point execute (vs 404, vs raw source)?
  const rphp = await get("/index.php");
  if (rphp && rphp.status < 400) {
    const body = await rphp.text().catch(() => "");
    if (/<\?php/i.test(body)) {
      tells.push(".php source exposed");
      checks.push({ id: "FP2", status: "WARN", title: ".php not executed (fingerprint)",
        detail: "/index.php returned raw PHP source (`<?php` visible). PHP is present but the server is not executing it — a serious misconfiguration to fix." });
    } else {
      tells.push(`/index.php ${rphp.status}`);
      checks.push({ id: "FP2", status: "INFO", title: ".php endpoint (fingerprint)",
        detail: `GET /index.php returned HTTP ${rphp.status}, consistent with a PHP front controller.` });
    }
  }

  // 3. A few well-known PHP app paths (fixed list, not enumeration).
  for (const p of ["/wp-login.php", "/xmlrpc.php", "/administrator/"]) {
    const r = await get(p);
    if (r && [200, 301, 302].includes(r.status)) {
      tells.push(`${p} ${r.status}`);
      checks.push({ id: "FP3", status: "INFO", title: "Known PHP app path (fingerprint)",
        detail: `${p} responded HTTP ${r.status}, a PHP-application tell.` });
    }
  }

  checks.push({ id: "FP", status: "INFO", title: "PHP fingerprint verdict",
    detail: tells.length
      ? `Likely PHP. Tells: ${tells.join(", ")}. Fingerprinting is probabilistic — confirm the version on the host with --local.`
      : "No PHP tells from a short safe probe (banner, cookies, /index.php, known paths all silent). It may not be PHP, or it is well hardened. Confirm with --local." });
}

// ── Reporting ────────────────────────────────────────────────────────

function render(checks: Check[], verdict: string | undefined, json: boolean, color: boolean, subtitle: string): boolean {
  const anyFail = checks.some((c) => c.status === "FAIL");
  const shouldFail = anyFail || verdict === "vulnerable";
  const overall = verdict === "patched" && !anyFail ? "PATCHED"
    : shouldFail ? "ACTION REQUIRED"
    : "INCONCLUSIVE";

  if (json) {
    console.log(JSON.stringify({ overall, versionVerdict: verdict ?? "unknown", checks }, null, 2));
    return shouldFail;
  }

  // ANSI helpers (disabled with --no-color or NO_COLOR).
  const c = (code: string, s: string) => color ? `\x1b[${code}m${s}\x1b[0m` : s;
  const bold = (s: string) => c("1", s);
  const dim = (s: string) => c("2", s);
  const paint: Record<Status, (s: string) => string> = {
    PASS: (s) => c("32", s), FAIL: (s) => c("31;1", s),
    WARN: (s) => c("33", s), INFO: (s) => c("36", s),
  };
  const counts = { PASS: 0, FAIL: 0, WARN: 0, INFO: 0 };
  for (const ch of checks) counts[ch.status]++;
  const overallColor = overall === "PATCHED" ? paint.PASS
    : overall === "ACTION REQUIRED" ? paint.FAIL : paint.WARN;

  // Wrap detail to a hanging indent so long lines stay readable.
  const wrap = (text: string, width: number, indent: string): string => {
    const words = text.split(/\s+/); const lines: string[] = []; let line = "";
    for (const w of words) {
      if ((line + " " + w).trim().length > width) { lines.push(line); line = w; }
      else line = (line ? line + " " : "") + w;
    }
    if (line) lines.push(line);
    return lines.map((l) => indent + l).join("\n");
  };

  const out: string[] = [];
  out.push("");
  out.push(`  ${bold("PHP patch & mitigation report")}`);
  out.push(`  ${dim(subtitle + "  ·  ")}${overallColor(bold(overall))}`);

  // Grouped by severity, failures first.
  const order: Status[] = ["FAIL", "WARN", "PASS", "INFO"];
  const labels: Record<Status, string> = { FAIL: "FAIL", WARN: "WARN", PASS: "PASS", INFO: "INFO" };
  for (const sev of order) {
    const group = checks.filter((ch) => ch.status === sev);
    if (!group.length) continue;
    out.push("");
    out.push(`  ${paint[sev](bold(labels[sev]))} ${dim("".padEnd(0))}`);
    for (const ch of group) {
      out.push(`    ${bold(ch.title)} ${dim("(" + ch.id + ")")}`);
      out.push(dim(wrap(ch.detail, 82, "      ")));
    }
  }

  out.push("");
  const summary = [
    paint.PASS(`${counts.PASS} pass`),
    paint.FAIL(`${counts.FAIL} fail`),
    paint.WARN(`${counts.WARN} warn`),
    paint.INFO(`${counts.INFO} info`),
  ].join(dim("  ·  "));
  out.push(`  ${summary}  ${dim("·")}  ${overallColor(bold(overall))}`);
  out.push(`  ${dim("CVE-2026-109618 / CVE-2026-109619 (CERT-EU, 21 Oct 2026). Only the update fully fixes these.")}`);
  out.push("");
  console.log(out.join("\n"));
  return shouldFail;
}

// ── HTML report (for --html; publishable as a page) ──────────────────

function buildHtml(checks: Check[], verdict: string | undefined, subtitle: string): string {
  const anyFail = checks.some((c) => c.status === "FAIL");
  const overall = verdict === "patched" && !anyFail ? "PATCHED"
    : anyFail || verdict === "vulnerable" ? "ACTION REQUIRED" : "INCONCLUSIVE";
  const counts = { PASS: 0, FAIL: 0, WARN: 0, INFO: 0 };
  for (const ch of checks) counts[ch.status]++;
  const esc = (s: string) => s.replace(/[&<>"]/g, (m) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[m]!));
  const order: Status[] = ["FAIL", "WARN", "PASS", "INFO"];
  const when = new Date().toISOString().replace("T", " ").slice(0, 16) + " UTC";

  const groups = order.map((sev) => {
    const g = checks.filter((ch) => ch.status === sev);
    if (!g.length) return "";
    const rows = g.map((ch) => `
      <div class="row ${sev.toLowerCase()}">
        <span class="badge ${sev.toLowerCase()}">${sev}</span>
        <div class="body"><div class="title">${esc(ch.title)} <span class="id">${esc(ch.id)}</span></div>
          <div class="detail">${esc(ch.detail)}</div></div>
      </div>`).join("");
    return `<section><h2 class="${sev.toLowerCase()}">${sev} <span class="n">${g.length}</span></h2>${rows}</section>`;
  }).join("");

  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>PHP report · ${esc(subtitle)}</title>
<style>
  :root{--bg:#f6f7f9;--card:#fff;--ink:#1a1d23;--muted:#5c6470;--line:#e4e7ec;
    --pass:#15803d;--fail:#b91c1c;--warn:#b45309;--info:#0e7490;
    --passbg:#dcfce7;--failbg:#fee2e2;--warnbg:#fef3c7;--infobg:#cffafe;}
  @media (prefers-color-scheme:dark){:root:not([data-theme="light"]){
    --bg:#0f1115;--card:#171a21;--ink:#e6e8eb;--muted:#9aa3af;--line:#262b34;
    --pass:#4ade80;--fail:#f87171;--warn:#fbbf24;--info:#22d3ee;
    --passbg:#0f2a1a;--failbg:#2a1313;--warnbg:#2a2110;--infobg:#0c2a30;}}
  :root[data-theme="dark"]{--bg:#0f1115;--card:#171a21;--ink:#e6e8eb;--muted:#9aa3af;--line:#262b34;
    --pass:#4ade80;--fail:#f87171;--warn:#fbbf24;--info:#22d3ee;
    --passbg:#0f2a1a;--failbg:#2a1313;--warnbg:#2a2110;--infobg:#0c2a30;}
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;padding:24px 16px}
  .wrap{max-width:760px;margin:0 auto}
  header{display:flex;flex-wrap:wrap;align-items:baseline;gap:8px 12px;margin-bottom:4px}
  h1{font-size:19px;margin:0}
  .sub{color:var(--muted);font-size:13px}
  .overall{margin-left:auto;font-weight:700;font-size:13px;padding:4px 10px;border-radius:999px}
  .overall.action{color:var(--fail);background:var(--failbg)}
  .overall.patched{color:var(--pass);background:var(--passbg)}
  .overall.inconclusive{color:var(--warn);background:var(--warnbg)}
  .meta{color:var(--muted);font-size:12px;margin:0 0 18px}
  section{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:6px 14px 14px;margin:0 0 14px}
  h2{font-size:12px;letter-spacing:.08em;margin:12px 2px 8px;text-transform:uppercase}
  h2.fail{color:var(--fail)}h2.warn{color:var(--warn)}h2.pass{color:var(--pass)}h2.info{color:var(--info)}
  h2 .n{color:var(--muted);font-weight:500}
  .row{display:flex;gap:12px;padding:10px 2px;border-top:1px solid var(--line)}
  .badge{flex:0 0 auto;align-self:flex-start;font-size:11px;font-weight:700;padding:2px 8px;border-radius:6px;letter-spacing:.04em}
  .badge.fail{color:var(--fail);background:var(--failbg)}.badge.warn{color:var(--warn);background:var(--warnbg)}
  .badge.pass{color:var(--pass);background:var(--passbg)}.badge.info{color:var(--info);background:var(--infobg)}
  .title{font-weight:600}
  .id{color:var(--muted);font-weight:400;font-size:12px}
  .detail{color:var(--muted);font-size:13.5px;margin-top:2px}
  footer{color:var(--muted);font-size:12px;margin-top:4px;text-align:center}
</style></head>
<body><div class="wrap">
  <header><h1>PHP patch &amp; mitigation report</h1>
    <span class="overall ${overall === "PATCHED" ? "patched" : overall === "ACTION REQUIRED" ? "action" : "inconclusive"}">${overall}</span></header>
  <p class="meta">${esc(subtitle)} · ${when} · ${counts.PASS} pass · ${counts.FAIL} fail · ${counts.WARN} warn · ${counts.INFO} info</p>
  ${groups}
  <footer>CVE-2026-109618 / CVE-2026-109619 (CERT-EU, 21 Oct 2026). Only the PHP update fully fixes these; mitigations reduce exposure. Generated by php-patch-verify.</footer>
</div></body></html>`;
}

// ── Main ─────────────────────────────────────────────────────────────

async function main() {
  const args = process.argv.slice(2);
  const has = (f: string) => args.includes(f);
  const val = (f: string) => { const i = args.indexOf(f); return i >= 0 ? args[i + 1] : undefined; };
  const opts = { uploads: has("--uploads") };
  const json = has("--json");
  const checks: Check[] = [];
  let verdict: string | undefined;

  const hasPrimary = has("--version") || has("--ini") || has("--url") || has("--local");
  const hasServer = has("--nginx") || has("--apache") || has("--systemd") || has("--cgroup");

  if (!hasPrimary && !hasServer) {
    console.log(`PHP Patch & Mitigation Verifier (read-only, non-intrusive)

PHP layer:
  bun CheckHost.ts --local                   Check this host (php -v, php -i)
  bun CheckHost.ts --ini <file> [--uploads]  Audit a php.ini / FPM pool file
  bun CheckHost.ts --url <url>               Read remote banner + cookie (headers only)
  bun CheckHost.ts --url <url> --probe       Active test: banner-hidden + body-size cap
  bun CheckHost.ts --url <url> --fingerprint Detect whether the host is PHP (safe GETs)
  bun CheckHost.ts --version 8.3.36          Evaluate a version string

Server layer (combine freely, with or without a PHP-layer mode):
  --nginx <file>     Audit nginx request limits (client_max_body_size, buffers)
  --apache <file>    Audit Apache LimitRequest* directives
  --systemd <file>   Flag RLIMIT_AS/DATA; check cgroup MemoryMax
  --cgroup [path]    Read the cgroup memory bound (default /sys/fs/cgroup/memory.max)

Options: --uploads (32M body ceiling), --json, --html, --no-color,
         --strict (exit non-zero when action is required, for CI gating)

Verifies the Oct 2026 PHP RCE pair CVE-2026-109618 / CVE-2026-109619.
Generate matching config with Harden.ts. Neither tool exploits either CVE.`);
    process.exit(0);
  }

  // PHP-layer primary mode (optional).
  if (has("--version")) {
    verdict = evalVersion(val("--version")!, checks);
  } else if (has("--ini")) {
    const file = val("--ini")!;
    let text = "";
    try { text = readFileSync(file, "utf8"); }
    catch (e) { console.error(`Cannot read ${file}: ${(e as Error).message}`); process.exit(2); }
    const ini = parsePhpIni(text);
    const vm = text.match(/PHP\/?\s*(\d+\.\d+\.\d+)/);
    if (vm) verdict = evalVersion(vm[1], checks);
    const branch = vm ? parseVersion(vm[1])!.slice(0, 2).join(".") : undefined;
    auditConfig(ini, { uploads: opts.uploads, branch }, checks);
  } else if (has("--url")) {
    await runUrl(val("--url")!, checks);
    if (has("--probe")) {
      const sz = toBytes(val("--probe-size") || "9m") ?? 9 * 1024 * 1024;
      await runProbe(val("--url")!, sz, checks);
    }
    if (has("--fingerprint")) await runFingerprint(val("--url")!, checks);
  } else if (has("--local")) {
    verdict = runLocal(checks, opts);
  }

  // Server-layer audits (additive).
  if (has("--nginx")) auditNginx(val("--nginx")!, opts.uploads, checks);
  if (has("--apache")) auditApache(val("--apache")!, opts.uploads, checks);
  if (has("--systemd")) auditSystemd(val("--systemd")!, checks);
  if (has("--cgroup")) {
    const next = args[args.indexOf("--cgroup") + 1];
    auditCgroup(next && !next.startsWith("--") ? next : undefined, checks);
  }

  let subtitle = "host";
  if (has("--url")) subtitle = (val("--url") || "").replace(/^https?:\/\//, "").replace(/\/$/, "");
  else if (has("--local")) subtitle = "local host";
  else if (has("--ini")) subtitle = (val("--ini") || "config").split("/").pop()!;
  else if (has("--version")) subtitle = "PHP " + (val("--version") || "");
  else if (hasServer) subtitle = "server config";

  const color = !has("--no-color") && !process.env.NO_COLOR;
  const strict = has("--strict") || has("--ci");
  const sf = checks.some((ch) => ch.status === "FAIL") || verdict === "vulnerable";

  if (has("--html")) {
    console.log(buildHtml(checks, verdict, subtitle));
    process.exit(strict && sf ? 1 : 0);
  }

  render(checks, verdict, json, color, subtitle);
  // Default exit 0 so a normal run is not shown as an error. Use --strict
  // (or --ci) to make the exit non-zero when action is required, for gating.
  process.exit(strict && sf ? 1 : 0);
}

main();
