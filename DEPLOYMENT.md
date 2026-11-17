# Authy OIDC Server: Deployment Guide

Production runs as three containers from `docker-compose.yml`: the app (gunicorn
with WhiteNoise), Postgres and Redis. Traefik terminates TLS in front of it.

1. [What production needs](#what-production-needs)
2. [Signing key](#signing-key)
3. [Deploy](#deploy)
4. [First admin](#first-admin)
5. [Backups and restore](#backups-and-restore)
6. [Monitoring](#monitoring)
7. [Maintenance](#maintenance)
8. [Security checklist](#security-checklist)
9. [Troubleshooting](#troubleshooting)

## What production needs

With `DEBUG=False` the server refuses to start unless it has:

| Setting | Why |
|---|---|
| `DJANGO_SECRET_KEY` | Signs sessions, CSRF tokens, reset and verification links |
| `REDIS_URL` | Rate limits, lockouts, token blacklist and code-replay checks must be shared by every worker |
| A signing key | Signs every ID token (see below) |
| `DEFAULT_FROM_EMAIL` and SMTP settings | Verification and password-reset mail |

The compose file also requires `ALLOWED_HOSTS`, the `POSTGRES_*` credentials,
`ADMIN_URL`, `ADMIN_IP_WHITELIST`, `EMAIL_HOST` and `OIDC_KEY_FILE`, and fails
fast if any is missing. `.env.example` documents every setting.

Generate secrets with:

```bash
python -c 'import secrets; print(secrets.token_urlsafe(50))'   # DJANGO_SECRET_KEY
python -c 'import secrets; print(secrets.token_urlsafe(32))'   # POSTGRES_PASSWORD (URL-safe: it goes into DATABASE_URL)
```

## Signing key

The OIDC signing key is loaded from, in order: `OIDC_RSA_PRIVATE_KEY` (the PEM
itself), the file at `OIDC_RSA_PRIVATE_KEY_PATH`, or `oidc.key` at the repo root.
In compose, the file at `OIDC_KEY_FILE` on the host is mounted read-only at
`/run/secrets/oidc.key`.

```bash
openssl genrsa -out /srv/authy/oidc.key 4096
sudo chown 10001:10001 /srv/authy/oidc.key   # the container's appuser
sudo chmod 400 /srv/authy/oidc.key
```

Keep an offline copy (see [Backups](#backups-and-restore)). Losing the key
invalidates every issued ID token; leaking it lets anyone mint tokens your
relying parties will trust.

### Rotating the key

Relying parties fetch the public keys from `/o/.well-known/jwks.json` and match
tokens to keys by `kid`, so a rotation needs an overlap period:

1. Generate the new key next to the old one.
2. Point `OIDC_KEY_FILE` at the new key, mount the old one too, and list its
   in-container path in `OIDC_RSA_PRIVATE_KEYS_INACTIVE_PATHS`. JWKS then
   publishes both, and new tokens are signed with the new key.
3. Redeploy: `docker compose up -d`.
4. After the longest ID token lifetime plus your relying parties' JWKS cache
   time (a day is plenty for the defaults), remove the old key from
   `OIDC_RSA_PRIVATE_KEYS_INACTIVE_PATHS`, unmount it and redeploy.

## Deploy

Put the settings in an env file outside the repo, for example
`/srv/authy/authy.env`:

```bash
DJANGO_SECRET_KEY=...
ALLOWED_HOSTS=auth.example.com
POSTGRES_USER=authy
POSTGRES_PASSWORD=...
POSTGRES_DB=authy
OIDC_KEY_FILE=/srv/authy/oidc.key
ADMIN_URL=something-unguessable/
ADMIN_IP_WHITELIST=10.8.0.0/24          # your VPN or office range
METRICS_IP_WHITELIST=172.16.0.0/12      # where Prometheus scrapes from
DEFAULT_FROM_EMAIL=noreply@example.com
EMAIL_HOST=smtp.example.com
EMAIL_HOST_USER=...
EMAIL_HOST_PASSWORD=...
SENTRY_DSN=...
```

The app publishes no host port. Attach it to Traefik's network with a compose
override, adapting the network, entrypoint and certificate resolver names to
your Traefik setup:

```yaml
# docker-compose.override.yml
services:
  app:
    networks: [default, traefik]
    labels:
      - traefik.enable=true
      - traefik.docker.network=traefik
      - traefik.http.routers.authy.rule=Host(`auth.example.com`)
      - traefik.http.routers.authy.entrypoints=websecure
      - traefik.http.routers.authy.tls.certresolver=letsencrypt
      - traefik.http.services.authy.loadbalancer.server.port=8000

networks:
  traefik:
    external: true
```

`TRUSTED_PROXY_COUNT` defaults to 1 in compose (Traefik only). Set it to the
number of proxies in front of the app if there are more (for example 2 behind
Cloudflare), or client IPs, rate limits and the admin allowlist will be wrong.

Start it:

```bash
docker compose --env-file /srv/authy/authy.env up -d --build --wait
```

On start the entrypoint collects static files and runs migrations. With more
than one app replica, set `AUTO_MIGRATE=0` on all but one, or run
`docker compose run --rm app python src/manage.py migrate` as a release step.

Check it from outside:

```bash
curl -s https://auth.example.com/o/.well-known/openid-configuration | jq .issuer
# "https://auth.example.com/o"
docker compose exec app python src/manage.py check --deploy
```

## First admin

The admin needs a password and an OTP token. Bootstrap the first admin with a
single-use static token, then enrol an authenticator app:

```bash
docker compose exec app python src/manage.py createsuperuser
docker compose exec app python src/manage.py addstatictoken you@example.com
# prints a token, e.g. 7xk2mq3p
```

1. From an address in `ADMIN_IP_WHITELIST`, open `https://auth.example.com/<ADMIN_URL>`.
2. Sign in with the email, password and the static token.
3. Under **OTP_TOTP → TOTP devices**, add a device for yourself and scan the QR
   code with your authenticator app.
4. Use the authenticator from then on. Keep a couple of fresh static tokens
   somewhere safe for recovery (`addstatictoken` again).

## Backups and restore

What to back up:

| Data | Where | How |
|---|---|---|
| Accounts, OAuth applications, tokens, sessions | Postgres (`postgres_data` volume) | `pg_dump`, daily |
| Signing key | `OIDC_KEY_FILE` on the host | Offline copy at creation and after each rotation |
| Env file | `/srv/authy/authy.env` | With your other secrets |

Redis holds only short-lived data (rate-limit counters, lockouts, the token
blacklist). Sessions are written through to Postgres, so losing Redis signs
nobody out. It doesn't need backups.

Daily dump, kept for 14 days (for example from cron):

```bash
cd /path/to/authy-oidc-server
docker compose --env-file /srv/authy/authy.env exec -T db \
  sh -c 'pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" --format=custom' \
  > /srv/backups/authy-$(date +%F).dump
find /srv/backups -name 'authy-*.dump' -mtime +14 -delete
```

Copy the dumps off the host. A backup on the same disk isn't a backup.

Restore into a fresh stack:

```bash
docker compose --env-file /srv/authy/authy.env up -d db --wait
docker compose --env-file /srv/authy/authy.env exec -T db \
  sh -c 'pg_restore -U "$POSTGRES_USER" -d "$POSTGRES_DB" --clean --if-exists' \
  < /srv/backups/authy-YYYY-MM-DD.dump
docker compose --env-file /srv/authy/authy.env up -d --wait
```

Test a restore occasionally; an untested backup is a guess.

## Monitoring

- **Health:** `/healthz/` returns 200 when the database and Redis respond, 503
  otherwise. Docker's `HEALTHCHECK` uses it, and `docker compose ps` shows the
  result.
- **Metrics:** Prometheus can scrape `/metrics` from addresses in
  `METRICS_IP_WHITELIST`.
- **Errors:** set `SENTRY_DSN` to send exceptions to Sentry (no PII is sent).
- **Logs:** gunicorn access logs go to stdout (`docker compose logs app`).
  Django's error and security logs go to `LOG_DIR` (default `src/logs/` in the
  container). Tokens appear only as SHA-256 fingerprints.

## Maintenance

CI runs `pip-audit` against `uv.lock` on every push and PR. To update
dependencies:

```bash
uv lock --upgrade
uv run pytest
uvx pip-audit -r <(uv export --frozen --no-hashes --no-emit-project --format requirements-txt)
```

Django is held on the 5.2 LTS line (`<5.3`) in `pyproject.toml`.

## Security checklist

Before going live:

- [ ] `DEBUG=False` (compose sets it)
- [ ] `ALLOWED_HOSTS` is only your public host name
- [ ] `ADMIN_URL` changed, `ADMIN_IP_WHITELIST` set to a narrow range
- [ ] First admin enrolled a TOTP device
- [ ] `TRUSTED_PROXY_COUNT` matches the proxies in front of the app
- [ ] Signing key owned by 10001, mode 400, with an offline copy
- [ ] SMTP tested: register an account and receive the verification mail
- [ ] Daily backups scheduled, and one restore tested
- [ ] `manage.py check --deploy` is clean
- [ ] Relying parties that match accounts by email check `email_verified`

## Troubleshooting

**Redirect loop or `http://` URLs in discovery.** Traefik's
`X-Forwarded-Proto` isn't trusted: check `TRUSTED_PROXY_COUNT` is at least 1.

**Every client hits the same rate limit, or the admin allowlist blocks you.**
The app sees the proxy's address instead of the client's: `TRUSTED_PROXY_COUNT`
is too low. If it's too high, clients can spoof their address, so set it
exactly.

**An account is locked.** It unlocks after `LOGIN_LOCKOUT_SECONDS` (15 minutes
by default). To clear it now, `docker compose exec redis redis-cli --scan
--pattern '*login_failures*'` and delete the key.

**Startup fails with `ImproperlyConfigured`.** The message names the missing
setting: `REDIS_URL`, `DEFAULT_FROM_EMAIL`, or a signing key path that doesn't
exist or isn't readable by UID 10001.

**Verification mail doesn't arrive.** Failures are logged (`docker compose logs
app`) rather than shown to the user; users can resend from the account console.
