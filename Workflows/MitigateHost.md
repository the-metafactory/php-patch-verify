# Mitigate a host that cannot be patched yet

For a host where the PHP update genuinely cannot land immediately. Generates the
mitigation config, applies it under confirmation, and re-verifies. The only full
fix is still the update — this buys time, it is not a substitute.

## Step 1 — identify the host

Know the SAPI (FPM, mod_php, …), the PHP version, whether the app needs file
uploads, and the config paths (FPM pool / Apache conf, web server, systemd unit).

## Step 2 — generate the config (no changes yet)

```bash
cd ~/.soma/skills/php-patch-verify/Tools
bun Harden.ts --sapi fpm --version 8.3.36            # add --uploads if uploads are needed
```

Read every block. It emits: the PHP `php_admin_value` drop-in, nginx and Apache
request limits, and a systemd cgroup `MemoryMax` drop-in. The PHP block locks
`memory_limit=-1`, caps `post_max_size`, disables `session.upload_progress`, and
(on 8.5) `fatal_error_backtraces`.

Write them out when you are ready to stage: `--out ./hardening`.

## Step 3 — apply, with confirmation (human-in-the-loop)

This changes a live service. Confirm first; do not auto-apply.

1. Back up the current config.
2. Drop the file(s) into the right include dir.
3. Test the web-server config (`nginx -t`, `apachectl configtest`).
4. Restart EVERY worker (`systemctl restart php8.3-fpm`, reload nginx/Apache).
   Several mitigations only bite after a restart.

Do NOT set `LimitAS` / `LimitDATA` in the systemd unit — the advisory warns they
can trigger the vulnerable path. Bound memory with the cgroup `MemoryMax` instead.

## Step 4 — re-verify

```bash
bun CheckHost.ts --local \
  --nginx /etc/nginx/nginx.conf \
  --systemd /etc/systemd/system/php8.3-fpm.service.d/memory.conf \
  --cgroup
```

Every mitigation check should now be PASS. The version check stays FAIL until
the host is actually patched — that is expected, and it is the reminder that
mitigation is temporary.

## Step 5 — close the loop

Record the host as mitigated-not-patched, and schedule the real update. Re-run
`CheckHost.ts --local` after patching to flip the version check to PASS.
