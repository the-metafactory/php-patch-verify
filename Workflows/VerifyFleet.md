# Verify a fleet of PHP hosts

Produce a pass/fail record for each host (app1, app2, app3, and any other PHP
service) after a patch rollout, or to track interim mitigations.

## Step 1 — list the hosts and how to reach them

For each service, know: the hostname, the SAPI (PHP-FPM, mod_php, …), and the
path to its effective config (php.ini and/or the FPM pool file). mod_php hosts
go first — the PHP team rates them highest risk for this pair.

## Step 2 — verify each host on the box

The authoritative check runs where PHP runs. On each host:

```bash
cd ~/.soma/skills/php-patch-verify/Tools
bun CheckHost.ts --local --json > /var/tmp/phpcheck-$(hostname).json
echo "exit=$?"
```

`--local` runs `php -v` and `php -i`, so it reports the real running version and
the effective configuration. Add `--uploads` on hosts that legitimately accept
file uploads (app3 may; internal app1/app2 often do not).

If you cannot run on the box, point `--ini` at the pool/ini file you have:

```bash
bun CheckHost.ts --ini ./app3-fpm-pool.conf --uploads
```

## Step 3 — external sanity check (optional)

From outside, confirm the service is not leaking a stale version banner:

```bash
bun CheckHost.ts --url https://host.example.com/
```

A clean result here does not confirm the patch — `expose_php=Off` hides the
version. Always back it with a Step 2 run.

## Step 4 — confirm the things the tool cannot see

For every host the report marks PASS on config, still confirm by hand:

1. The mitigation settings are **locked** (`php_admin_value` in the FPM pool or
   Apache), not merely set, so no app or `.user.ini` can undo them.
2. Every worker was restarted after the config change (`systemctl restart
   php8.3-fpm`, Apache reload, container redeploy).
3. Request-size limits exist at the web server / proxy (nginx `client_max_body_size`,
   field/part/header caps) and a container/cgroup memory limit is set — not
   `RLIMIT_AS`/`RLIMIT_DATA`.

## Step 5 — record the outcome

Collect the per-host JSON. A host is cleared only when `overall` is `PATCHED`
(version at or above the fixed release and no FAIL checks). Anything else is
ACTION REQUIRED: patch if the version is behind, or fix the failing mitigation
if a patch genuinely cannot land yet.

Summary table to keep with the change record:

| Host | SAPI | Version | overall | Open items |
|------|------|---------|---------|-----------|
| app3  | php-fpm | 8.3.36 | PATCHED | — |
| app1  | mod_php | 8.3.20 | ACTION REQUIRED | update to 8.3.36 |

## Re-run as a gate

The non-zero exit on ACTION REQUIRED makes this a cron or CI gate:

```bash
bun CheckHost.ts --local --strict || notify "PHP host $(hostname) not patched"
```
