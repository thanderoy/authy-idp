# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A Django 5.2 LTS OAuth2 / OpenID Connect identity provider built on `django-oauth-toolkit` (DOT), working toward Keycloak-style IAM features. Python 3.13, managed with `uv`. Source lives in `src/` (a src layout, but not an installed package: `src/` itself is put on the path, so imports are `config.*` and `modules.*`). Production runs from `docker-compose.yml` (app, Postgres, Redis) behind Traefik; see `DEPLOYMENT.md`.

## Commands

```bash
uv sync                                   # install deps, dev group included
uv run python src/manage.py runserver     # dev server (reads .env at repo root; needs oidc.key, see README)
uv run python src/manage.py makemigrations / migrate

uv run pytest                             # full suite (xdist -n auto + coverage, from pytest.ini)
uv run pytest tests/entities/test_branding.py::test_name -n 0 --no-cov   # single test, serial, no coverage noise
uv run ruff check . && uv run ruff format src tests
uv run mypy src                           # the Django plugin imports settings: needs DJANGO_SECRET_KEY and a key
uv run pre-commit run --all-files         # ruff, ruff-format, mypy, conventional-commit msg hook
uvx pip-audit -r <(uv export --frozen --no-hashes --no-emit-project --format requirements-txt)
```

- `pytest.ini` is the config pytest uses; tox and `requirements/*.txt` are legacy and unused. pytest-env sets `DEBUG=False` so the suite runs **production-like regardless of the local `.env`** (module-level `if not DEBUG` branches like OTP admin and Prometheus are active in tests).
- Settings are evaluated at import, so environment-dependent behaviour is tested in a fresh interpreter through the `load_settings` fixture in `tests/conftest.py`. An autouse fixture there clears the cache between tests, since rate limits and lockouts live in it.
- Tests must not depend on local files: a clean clone has no `.env` or `oidc.key`. CI (`.github/workflows/gitflow-v1.yml`) runs from a clean checkout.
- The flows in `tests/authentication_flows/` drive the real `/o/authorize/` and `/o/token/` endpoints and are the best reference for how each grant, `prompt=none` and the claims behave. Prefer such tests over mocking validator internals: mocked attributes are how dead security code went unnoticed before.
- ruff's rule set is pinned in `pyproject.toml`. Don't run `ruff check --fix` across the tree; newer ruff versions rewrite unrelated files.

## Architecture

- **`src/config/settings.py`**: one environment-aware settings file using `python-decouple`. Branches on `DEBUG` and `TESTING`. `BASE_DIR` is `src/`, not the repo root. With `DEBUG=False` (outside tests) startup fails without `REDIS_URL`, `DEFAULT_FROM_EMAIL` or a signing key. The key comes from `OIDC_RSA_PRIVATE_KEY` (PEM), else `OIDC_RSA_PRIVATE_KEY_PATH`, else `oidc.key` at the repo root; `OIDC_RSA_PRIVATE_KEYS_INACTIVE_PATHS` keeps retired keys in JWKS. `TRUSTED_PROXY_COUNT` turns on trust of `X-Forwarded-*` headers. Sessions are `cached_db`. Logs go to `LOG_DIR` (default `src/logs/`, created on startup).
- **`src/config/urls.py`**: DOT is mounted at `/o/`, but `/o/authorize/` is shadowed by `modules.utils.authorization.SilentAwareAuthorizationView` (returns `consent_required` for `prompt=none` instead of rendering consent). Auth pages are thin `Branded*View` subclasses of Django's stock views; the password reset view also caps mails per address. The admin is at `settings.ADMIN_URL` and becomes django-otp's `OTPAdminSite` when `ADMIN_REQUIRE_OTP`. `/metrics` is mounted when `django_prometheus` is installed (non-DEBUG).
- **`modules/utils/oidc_validator.py`**: `EnhancedAuthyOAuth2Validator`. Claims come from `get_additional_claims` and are released per scope through `oidc_claim_scope`: a claim not in that map is never released, in either the ID token or userinfo. Refresh-token replay protection is DOT's `REFRESH_TOKEN_REUSE_PROTECTION`, not custom code. Never log raw tokens; use `fingerprint()`.
- **`modules/utils/middleware.py`**: `HealthCheckMiddleware` (`/healthz/`) runs first, before the SSL redirect and host check. The others: security headers/CSP (`script-src 'self'` only, so no inline scripts in templates), rate limiting (`RULES` per route, counters in `modules/utils/throttling.py` using atomic `cache.add`/`incr`), audit logging, the IP allowlist for the admin and `/metrics` (empty list denies when not DEBUG), request size and session security. Order in `MIDDLEWARE` matters.
- **`modules/utils/client_ip.py`**: `get_client_ip()` is the only way to read a client address; it takes `X-Forwarded-For` from the right per `TRUSTED_PROXY_COUNT`. Don't read `REMOTE_ADDR` directly.
- **`modules/entities`**: the only local app.
  - `Entity` is `AUTH_USER_MODEL`, logs in by email (lowercased on save, unique on `Lower(email)`, looked up with `iexact`), and `entity_type` makes it a Person (`PSN`) or Group (`GRP`). Group membership goes through `Relationship` (`child_entities` / `parent_entities`).
  - `email_verified` is set only by the signed link from `verification.py`, sent at registration and on email change. Mail failures are logged, not raised.
  - `backends.LockoutModelBackend` replaces `ModelBackend` and locks an account after repeated failures; it covers the login form, admin and the OAuth password grant. `login()` calls must name this backend.
  - `UserSession` (written by signal receivers in `sessions.py`) indexes sessions per user for the console's Active Devices page.
  - `EntityViewSet` (`/entities/entities/`) is staff-only. `EntityMeSerializer` needs `current_password` for email and password changes.
  - `ApplicationBranding` / `BrandedAuthMixin`: per-application logo and colour on the auth pages, keyed by `client_id` in GET or POST. Templates must carry `client_id` as a hidden field. Colours pass through the `safe_brand_color` filter.
- **`modules/common/models.py`**: `AuthyBaseModel` (adds `uuid`, `created`, `updated`).
- **Docker**: `docker/entrypoint.sh` runs `collectstatic` and, unless `AUTO_MIGRATE=0`, `migrate`. The container user is UID 10001; WhiteNoise serves static files. `.dockerignore` patterns need `**/` to match below the root.

## Conventions

- Conventional Commits, enforced by a pre-commit `commit-msg` hook.
- Branching in this repo: the integration branch is **`dev`** (not `develop`). PRs merge into `dev`, and `main` is for releases. CI runs on pushes and PRs to both.
- `PLAN.md` / `TASKS.md` (gitignored) hold the milestone roadmap and progress. `DEPLOYMENT.md` and `.env.example` must stay in step with settings changes.
