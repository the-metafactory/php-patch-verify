#!/usr/bin/env bun
/**
 * PHP Mitigation Config Generator (O1)
 *
 * Emits ready-to-review hardening config for the Oct 2026 PHP RCE pair
 * (CVE-2026-109618, CVE-2026-109619), tailored to the SAPI, version and
 * whether the app needs file uploads. It covers the PHP settings AND the
 * web-server / cgroup controls the advisory asks for.
 *
 * It GENERATES ONLY. It does not write to system paths, reload workers, or
 * touch a running service. The operator reviews the output and applies it.
 * Applying is a separate, confirmed step (see Workflows/MitigateHost.md).
 *
 * Usage:
 *   bun Harden.ts --sapi fpm      [--version 8.3.36] [--uploads] [--out DIR]
 *   bun Harden.ts --sapi apache   [--version 8.5.12] [--uploads]
 *   bun Harden.ts --sapi ini
 *
 * --uploads   app legitimately accepts uploads: post_max_size 32M, uploads on.
 *             Omitted: post_max_size 8M, file uploads disabled.
 * --version   used only to decide whether the 8.5-only fatal_error_backtraces
 *             line is emitted live or as a commented note.
 * --out DIR   also write the files into DIR (created if needed). Default: print.
 */

import { writeFileSync, mkdirSync } from "fs";
import { join } from "path";

const args = process.argv.slice(2);
const has = (f: string) => args.includes(f);
const val = (f: string) => { const i = args.indexOf(f); return i >= 0 ? args[i + 1] : undefined; };

const sapi = (val("--sapi") || "fpm").toLowerCase();
const uploads = has("--uploads");
const version = val("--version");
const outDir = val("--out");

const branch = version ? version.split(".").slice(0, 2).join(".") : undefined;
const is85 = branch === "8.5";

const postMax = uploads ? "32M" : "8M";
const postMaxBytes = uploads ? 32 * 1024 * 1024 : 8 * 1024 * 1024;
const uploadMax = uploads ? "8M" : "2M";

// ── PHP settings block (the heart of both CVEs' mitigations) ─────────
function phpAdminLines(prefix: string): string {
  const L: string[] = [];
  L.push(`${prefix}memory_limit = -1`);
  L.push(`${prefix}post_max_size = ${postMax}`);
  L.push(`${prefix}upload_max_filesize = ${uploadMax}`);
  if (!uploads) L.push(`${prefix}file_uploads = Off`);
  L.push(`${prefix}session.upload_progress.enabled = 0`);
  if (is85) {
    L.push(`${prefix}fatal_error_backtraces = 0`);
  } else {
    L.push(`; fatal_error_backtraces = 0   ; PHP 8.5 only — uncomment on 8.5 hosts`);
  }
  L.push(`${prefix}expose_php = Off`);
  return L.join("\n");
}

function banner(title: string): string {
  return `# ========================================================================\n` +
         `# ${title}\n` +
         `# CVE-2026-109618 / CVE-2026-109619 interim mitigation. Only the PHP\n` +
         `# update is a full fix; this reduces exposure. Restart workers after.\n` +
         `# ========================================================================`;
}

const files: { name: string; body: string }[] = [];

// 1 ── PHP config, by SAPI
if (sapi === "fpm") {
  files.push({
    name: "zz-cve-2026-php.conf",
    body: `${banner("FPM pool drop-in — php_admin_value locks these so apps cannot override")}\n` +
      `; Place in the pool's include dir, e.g. /etc/php/${branch ?? "8.x"}/fpm/pool.d/, then:\n` +
      `;   systemctl restart php${branch ?? "8.x"}-fpm\n` +
      `; php_admin_value cannot be overridden by ini_set(), .user.ini, or app code.\n\n` +
      phpAdminLines("php_admin_value[").replace(/php_admin_value\[(\S+) = (.*)$/gm, "php_admin_value[$1] = $2")
        .replace(/; php_admin_value\[fatal/, "; php_admin_value[fatal") + "\n",
  });
} else if (sapi === "apache") {
  files.push({
    name: "cve-2026-php-hardening.conf",
    body: `${banner("Apache mod_php hardening — php_admin_value locks these")}\n` +
      `# Place in conf-available/ and a2enconf, or inside the vhost. Then:\n` +
      `#   systemctl restart apache2   (mod_php shares the Apache process)\n` +
      `# mod_php is the PHP team's highest-risk SAPI for this pair — prioritise it.\n\n` +
      `<IfModule mod_php.c>\n` +
      phpAdminLines("    php_admin_value ").replace(/php_admin_value (\S+) = (.*)$/gm, "php_admin_value $1 $2")
        .replace(/^(\s*); fatal.*/m, "    # php_admin_value fatal_error_backtraces 0   # PHP 8.5 only") + "\n" +
      `</IfModule>\n`,
  });
} else {
  files.push({
    name: "cve-2026-php.ini",
    body: `${banner("php.ini fragment — weaker than php_admin_value (apps can still override)")}\n` +
      `; Prefer the FPM/Apache php_admin_value form so nothing can put a finite\n` +
      `; memory_limit back. Use this only where you control the single ini.\n\n` +
      phpAdminLines("") + "\n",
  });
}

// 2 ── Web-server / proxy request limits
files.push({
  name: "cve-2026-nginx-limits.conf",
  body: `${banner("nginx request limits — cap body size and header buffers")}\n` +
    `# Put in the server{} or location{} block in front of PHP, then: nginx -t && systemctl reload nginx\n\n` +
    `client_max_body_size ${postMax};            # match post_max_size\n` +
    `large_client_header_buffers 4 8k;    # cap header count/size\n` +
    `client_header_buffer_size 4k;\n` +
    `# Field count / multipart-part count are not native to nginx; enforce at a\n` +
    `# WAF or app gateway (Cloudflare WAF can). Ensure limits also apply to\n` +
    `# requests with no usable Content-Length (chunked).\n`,
});
files.push({
  name: "cve-2026-apache-limits.conf",
  body: `${banner("Apache request limits")}\n` +
    `# Place in the vhost or server config, then: apachectl configtest && systemctl reload apache2\n\n` +
    `LimitRequestBody ${postMaxBytes}      # = ${postMax}, match post_max_size\n` +
    `LimitRequestFields 100           # cap header count\n` +
    `LimitRequestFieldSize 8190       # cap header size\n` +
    `LimitRequestLine 8190            # cap request line\n`,
});

// 3 ── cgroup / container memory bound (availability boundary)
files.push({
  name: "cve-2026-cgroup-memory.conf",
  body: `${banner("Memory bound as an availability boundary — kill only the affected worker")}\n` +
    `# systemd drop-in: /etc/systemd/system/php${branch ?? "8.x"}-fpm.service.d/memory.conf\n` +
    `# Then: systemctl daemon-reload && systemctl restart php${branch ?? "8.x"}-fpm\n\n` +
    `[Service]\n` +
    `MemoryMax=1G            # tune to the host; OOM-kills the worker, not the box\n` +
    `MemorySwapMax=0\n\n` +
    `# Docker/compose equivalent:  mem_limit: 1g\n\n` +
    `# WARNING (advisory): do NOT use RLIMIT_AS / RLIMIT_DATA for this —\n` +
    `#   i.e. do NOT set LimitAS= or LimitDATA= in the unit. They can TRIGGER the\n` +
    `#   vulnerable allocation-failure path. Use the cgroup MemoryMax above instead.\n`,
});

// 4 ── Stop the PHP banner leaking (origin + edge)
files.push({
  name: "cve-2026-hide-php.conf",
  body: `${banner("Stop leaking that this is PHP")}\n` +
    `# Origin (real fix) — in the FPM pool / Apache / php.ini, then restart workers:\n` +
    (sapi === "fpm"
      ? `php_admin_value[expose_php] = Off\nphp_admin_value[session.name] = NPWSESS   ; rename the PHPSESSID cookie tell\n`
      : sapi === "apache"
      ? `php_admin_value expose_php Off\nphp_admin_value session.name NPWSESS\n`
      : `expose_php = Off\nsession.name = NPWSESS\n`) +
    `\n# expose_php=Off removes the X-Powered-By header and the PHP signature in\n` +
    `# error output. session.name hides the default PHPSESSID cookie, which also\n` +
    `# fingerprints PHP. Both need a worker restart.\n`,
});
files.push({
  name: "cve-2026-cloudflare-transform-rule.md",
  body: `# Cloudflare edge fix — strip the PHP banner for all hosts at once\n\n` +
    `Dashboard: Rules -> Transform Rules -> Modify Response Header -> Create.\n` +
    `Takes effect at the edge immediately, no origin change, covers app1/app2/app3 together.\n\n` +
    `- When incoming requests match:  (http.host in {"app1.example.com" "app2.example.com" "app3.example.com"})\n` +
    `- Then: Remove response header  X-Powered-By\n` +
    `- Then (optional): Set static response header  Server  to  your-org\n\n` +
    `This hides the header at the edge even if the origin still sets it. Still set\n` +
    `expose_php=Off at the origin so a direct-to-origin request does not leak.\n\n` +
    `Verify after:  bun CheckHost.ts --url https://app1.example.com/ --probe\n`,
});

// ── Emit ─────────────────────────────────────────────────────────────
const toolDir = import.meta.dir;
const checker = join(toolDir, "CheckHost.ts");

console.log(`\n# PHP mitigation config — generated, review before applying.`);
console.log(`# SAPI: ${sapi}   version: ${version ?? "(unspecified)"}   uploads: ${uploads ? "yes (32M)" : "no (8M, uploads off)"}\n`);

for (const f of files) {
  console.log(`\n# ---------- ${f.name} ----------`);
  console.log(f.body);
}

console.log(`\n# ---------- apply & verify (do NOT skip the re-check) ----------`);
console.log(`# 1. Back up the target config.`);
console.log(`# 2. Drop the file(s) in, test the web-server config, restart EVERY worker.`);
console.log(`# 3. Re-verify:  bun ${checker} --local`);
console.log(`#    and the server layer, e.g.:`);
console.log(`#      bun ${checker} --nginx /etc/nginx/nginx.conf --cgroup`);
console.log(`# 4. A mitigation is not a patch — still update PHP to a fixed release.\n`);

if (outDir) {
  mkdirSync(outDir, { recursive: true });
  for (const f of files) writeFileSync(join(outDir, f.name), f.body + "\n");
  console.log(`# Wrote ${files.length} file(s) to ${outDir}\n`);
}
