"""Enhanced Authy OIDC Settings with Security Improvements"""

import sys
from pathlib import Path

import dj_database_url
from django.core.exceptions import ImproperlyConfigured
from decouple import config, Csv

TESTING = "pytest" in sys.modules

# Build paths inside the project
BASE_DIR = Path(__file__).resolve().parent.parent

# Security Settings
SECRET_KEY = config("DJANGO_SECRET_KEY")
DEBUG = config("DEBUG", default=False, cast=bool)
ALLOWED_HOSTS = config("ALLOWED_HOSTS", default="", cast=Csv())

# Reverse proxy (Traefik): how many proxies sit in front of the app. When
# set, X-Forwarded-Proto/Host are trusted and client IPs come from
# X-Forwarded-For (see modules.utils.client_ip). Leave at 0 when the app is
# reached directly, or clients could spoof these headers.
TRUSTED_PROXY_COUNT = config("TRUSTED_PROXY_COUNT", default=0, cast=int)
if TRUSTED_PROXY_COUNT > 0:
    SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
    USE_X_FORWARDED_HOST = True

SECURE_SSL_REDIRECT = config("SECURE_SSL_REDIRECT", default=not DEBUG, cast=bool)
if TESTING:
    SECURE_SSL_REDIRECT = False
SESSION_COOKIE_SECURE = config("SESSION_COOKIE_SECURE", default=True, cast=bool)
CSRF_COOKIE_SECURE = config("CSRF_COOKIE_SECURE", default=True, cast=bool)
SECURE_HSTS_SECONDS = config("SECURE_HSTS_SECONDS", default=31536000, cast=int)
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_BROWSER_XSS_FILTER = True
X_FRAME_OPTIONS = "DENY"

# Application definition
INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "oauth2_provider",
    "corsheaders",
    "rest_framework",
    "drf_spectacular",
]

OTP_APPS = [
    "django_otp",
    "django_otp.plugins.otp_totp",
    "django_otp.plugins.otp_static",
]

LOCAL_APPS = [
    "modules.entities",
]

THIRD_PARTY_APPS = []

# Add apps based on environment
if DEBUG:
    # Dev tooling (shell_plus, runserver_plus) lives in the dev dependency
    # group, so it isn't installed in the production image.
    from importlib.util import find_spec

    if find_spec("django_extensions"):
        THIRD_PARTY_APPS += ["django_extensions"]
if not DEBUG:
    THIRD_PARTY_APPS += ["django_prometheus"]  # For production monitoring

INSTALLED_APPS += OTP_APPS + THIRD_PARTY_APPS + LOCAL_APPS

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "modules.utils.middleware.SecurityHeadersMiddleware",
    "corsheaders.middleware.CorsMiddleware",
    "modules.utils.middleware.RequestSizeMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django_otp.middleware.OTPMiddleware",
    "modules.utils.middleware.SessionSecurityMiddleware",
    "oauth2_provider.middleware.OAuth2TokenMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "modules.utils.middleware.AuditLoggingMiddleware",
    "modules.utils.middleware.RateLimitMiddleware",
    "modules.utils.middleware.IPWhitelistMiddleware",
]

# Add environment-specific middleware
if not DEBUG:
    MIDDLEWARE.insert(0, "django_prometheus.middleware.PrometheusBeforeMiddleware")
    MIDDLEWARE.append("django_prometheus.middleware.PrometheusAfterMiddleware")

# First of all, so container health checks over plain HTTP aren't redirected
# to HTTPS or rejected by the ALLOWED_HOSTS check.
MIDDLEWARE.insert(0, "modules.utils.middleware.HealthCheckMiddleware")

# CORS Configuration - More restrictive
CORS_ALLOWED_ORIGINS = config("CORS_ALLOWED_ORIGINS", default="", cast=Csv())
CORS_ALLOW_CREDENTIALS = True
CORS_ALLOW_HEADERS = [
    "accept",
    "accept-encoding",
    "authorization",
    "content-type",
    "dnt",
    "origin",
    "user-agent",
    "x-csrftoken",
    "x-requested-with",
]

ROOT_URLCONF = "config.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "config.wsgi.application"

# Database Configuration
DATABASES = {
    "default": dj_database_url.parse(
        config("DATABASE_URL", default=f"sqlite:///{BASE_DIR}/db.sqlite3")
    )
}

# Add database connection pooling for production
if not DEBUG:
    DATABASES["default"]["CONN_MAX_AGE"] = 600
    if "postgresql" in DATABASES["default"]["ENGINE"]:
        DATABASES["default"]["OPTIONS"] = {
            "connect_timeout": 10,
            "options": "-c statement_timeout=30000",  # 30 seconds
        }

# Password validation
AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
        "OPTIONS": {
            "min_length": 12,  # Increased from default 8
        },
    },
    {
        "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",
    },
]

# Internationalization
LANGUAGE_CODE = "en-us"
TIME_ZONE = config("TIME_ZONE", default="UTC")
USE_I18N = True
USE_TZ = True

# Static files
STATIC_URL = "/static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
STATICFILES_DIRS = [BASE_DIR / "static"] if (BASE_DIR / "static").exists() else []
# WhiteNoise serves collected static files when DEBUG is off. The manifest
# storage needs collectstatic to have run, so dev and tests use the plain one.
STORAGES = {
    "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
    "staticfiles": {
        "BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage"
        if DEBUG or TESTING
        else "whitenoise.storage.CompressedManifestStaticFilesStorage"
    },
}

# Media files
MEDIA_URL = "/media/"
MEDIA_ROOT = BASE_DIR / "media"

# Default primary key field type
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# API Documentation
SPECTACULAR_SETTINGS = {
    "TITLE": "Authy OIDC Server",
    "DESCRIPTION": "Authy OIDC Server - OAuth2 + OIDC Identity Provider.",
    "VERSION": "1.0.0",
    "SERVE_INCLUDE_SCHEMA": False,
    "COMPONENT_SPLIT_REQUEST": True,
    "EXAMPLES_INCLUDE_RESPONSE": True,
    "SWAGGER_UI_SETTINGS": {
        "deepLinking": True,
        "persistAuthorization": True,
        "displayOperationId": True,
    },
}

# Admin
# Served at ADMIN_URL instead of the well-known admin/. Outside DEBUG it is
# reachable only from ADMIN_IP_WHITELIST (addresses or CIDR ranges, "*" for
# any) and, with ADMIN_REQUIRE_OTP, only after an OTP token. Bootstrap the
# first admin with `manage.py addstatictoken <email>`, then add a TOTP device.
ADMIN_URL = config("ADMIN_URL", default="admin/").strip("/") + "/"
ADMIN_IP_WHITELIST = config("ADMIN_IP_WHITELIST", default="", cast=Csv())
# Prometheus scrapes /metrics (outside DEBUG); same rules as the admin list.
METRICS_IP_WHITELIST = config("METRICS_IP_WHITELIST", default="", cast=Csv())
ADMIN_REQUIRE_OTP = config("ADMIN_REQUIRE_OTP", default=not DEBUG, cast=bool)
OTP_TOTP_ISSUER = "Authy"

# Authentication
AUTH_USER_MODEL = "entities.Entity"
LOGIN_URL = "/login/"
LOGIN_REDIRECT_URL = "/entities/console/profile/"
LOGOUT_REDIRECT_URL = "/"

AUTHENTICATION_BACKENDS = [
    "oauth2_provider.backends.OAuth2Backend",
    "modules.entities.backends.LockoutModelBackend",
]

# Failed logins per account before it is locked, and for how long.
LOGIN_LOCKOUT_ATTEMPTS = config("LOGIN_LOCKOUT_ATTEMPTS", default=5, cast=int)
LOGIN_LOCKOUT_SECONDS = config("LOGIN_LOCKOUT_SECONDS", default=900, cast=int)
# Reset emails a single address can receive per hour, whoever asks.
PASSWORD_RESET_EMAILS_PER_HOUR = config(
    "PASSWORD_RESET_EMAILS_PER_HOUR", default=3, cast=int
)

# REST Framework Configuration
REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": (
        "oauth2_provider.contrib.rest_framework.OAuth2Authentication",
        "rest_framework.authentication.SessionAuthentication",
    ),
    "DEFAULT_PERMISSION_CLASSES": ("rest_framework.permissions.IsAuthenticated",),
    "DEFAULT_SCHEMA_CLASS": "drf_spectacular.openapi.AutoSchema",
    "DEFAULT_PAGINATION_CLASS": "rest_framework.pagination.PageNumberPagination",
    "PAGE_SIZE": 100,
    "DEFAULT_THROTTLE_CLASSES": [
        "rest_framework.throttling.AnonRateThrottle",
        "rest_framework.throttling.UserRateThrottle",
    ],
    "DEFAULT_THROTTLE_RATES": {
        "anon": "100/hour",
        "user": "1000/hour",
        "token": "10/minute",  # For token endpoints
    },
}


# OAuth2 Provider Configuration
# The OIDC signing key comes from, in order: OIDC_RSA_PRIVATE_KEY (the PEM
# itself), the file at OIDC_RSA_PRIVATE_KEY_PATH, or oidc.key at the repo
# root. Without one the server refuses to start; tests get a throwaway key.
# Retired keys listed in OIDC_RSA_PRIVATE_KEYS_INACTIVE_PATHS stay in JWKS
# so tokens they signed still verify during a rotation.
def _read_key(path: Path) -> str:
    if not path.is_file():
        raise ImproperlyConfigured(f"OIDC signing key not found at {path}.")
    return path.read_text()


oidc_key_val = config("OIDC_RSA_PRIVATE_KEY", default="")
if not oidc_key_val.startswith("-----BEGIN"):
    if TESTING:
        from jwcrypto import jwk

        key = jwk.JWK.generate(kty="RSA", size=2048)
        oidc_key_val = key.export_to_pem(private_key=True, password=None).decode(
            "utf-8"
        )
    else:
        oidc_key_val = _read_key(
            Path(
                config(
                    "OIDC_RSA_PRIVATE_KEY_PATH",
                    default=str(BASE_DIR.parent / "oidc.key"),
                )
            )
        )

OIDC_INACTIVE_KEYS = [
    _read_key(Path(path))
    for path in config("OIDC_RSA_PRIVATE_KEYS_INACTIVE_PATHS", default="", cast=Csv())
]

OAUTH2_PROVIDER = {
    "OIDC_ENABLED": True,
    "OIDC_RSA_PRIVATE_KEY": oidc_key_val,
    "OIDC_RSA_PRIVATE_KEYS_INACTIVE": OIDC_INACTIVE_KEYS,
    "OAUTH2_VALIDATOR_CLASS": "modules.utils.oidc_validator.EnhancedAuthyOAuth2Validator",
    "SCOPES": {
        "openid": "OpenID Connect scope",
        "profile": "User profile information",
        "email": "User email address",
        "groups": "User group memberships",
        "offline_access": "Offline access for refresh tokens",
    },
    "DEFAULT_SCOPES": ["openid", "profile", "email"],
    "REQUEST_APPROVAL_PROMPT": "auto",
    "ACCESS_TOKEN_EXPIRE_SECONDS": config(
        "ACCESS_TOKEN_EXPIRE_SECONDS", default=3600, cast=int
    ),
    "REFRESH_TOKEN_EXPIRE_SECONDS": config(
        "REFRESH_TOKEN_EXPIRE_SECONDS", default=1209600, cast=int
    ),  # 14 days
    "AUTHORIZATION_CODE_EXPIRE_SECONDS": config(
        "AUTHORIZATION_CODE_EXPIRE_SECONDS", default=600, cast=int
    ),
    "ROTATE_REFRESH_TOKEN": True,  # Security best practice
    # Replaying a rotated refresh token revokes its whole family.
    "REFRESH_TOKEN_REUSE_PROTECTION": True,
    "PKCE_REQUIRED": True,  # Enforce PKCE for public clients
    "APPLICATION_MODEL": "oauth2_provider.Application",
}

OAUTH2_PROVIDER_APPLICATION_MODEL = "oauth2_provider.Application"


# Caching Configuration
# Rate limits, lockouts, the token blacklist and code-replay protection all
# live in the cache, so every worker must share it. The in-memory fallback is
# per process and is only allowed for development and tests.
REDIS_URL = config("REDIS_URL", default=None)
if not REDIS_URL and not DEBUG and not TESTING:
    raise ImproperlyConfigured("REDIS_URL is required when DEBUG is False.")

CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.redis.RedisCache"
        if REDIS_URL
        else "django.core.cache.backends.locmem.LocMemCache",
        "LOCATION": REDIS_URL or "",
        "KEY_PREFIX": "authy_oidc",
        "TIMEOUT": 300,
    }
}

# Session Configuration
# cached_db writes through to the database, so a Redis restart doesn't sign
# everyone out.
SESSION_ENGINE = "django.contrib.sessions.backends.cached_db"
SESSION_CACHE_ALIAS = "default"
SESSION_COOKIE_AGE = 86400  # 24 hours
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"

# Logging Configuration
# Log files go to LOG_DIR (default src/logs/), created on startup so a fresh
# checkout or container doesn't fail with "Unable to configure handler".
LOG_DIR = Path(config("LOG_DIR", default="") or BASE_DIR / "logs")
LOG_DIR.mkdir(parents=True, exist_ok=True)

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "verbose": {
            "format": "{levelname} {asctime} {module} {process:d} {thread:d} {message}",
            "style": "{",
        },
        "simple": {
            "format": "{levelname} {message}",
            "style": "{",
        },
    },
    "filters": {
        "require_debug_false": {"()": "django.utils.log.RequireDebugFalse"},
        "require_debug_true": {"()": "django.utils.log.RequireDebugTrue"},
    },
    "handlers": {
        "console": {
            "level": "INFO",
            "class": "logging.StreamHandler",
            "formatter": "simple",
        },
        "file": {
            "level": "ERROR",
            "class": "logging.handlers.RotatingFileHandler",
            "filename": LOG_DIR / "django.log",
            "maxBytes": 1024 * 1024 * 10,  # 10 MB
            "backupCount": 10,
            "formatter": "verbose",
        },
        "security": {
            "level": "WARNING",
            "class": "logging.handlers.RotatingFileHandler",
            "filename": LOG_DIR / "security.log",
            "maxBytes": 1024 * 1024 * 10,  # 10 MB
            "backupCount": 10,
            "formatter": "verbose",
        },
    },
    "loggers": {
        "django": {
            "handlers": ["console", "file"],
            "level": "INFO",
            "propagate": False,
        },
        "django.security": {
            "handlers": ["security"],
            "level": "WARNING",
            "propagate": False,
        },
        "oauth2_provider": {
            "handlers": ["console", "file"],
            "level": "DEBUG" if DEBUG else "INFO",
            "propagate": False,
        },
        "modules": {
            "handlers": ["console", "file"],
            "level": "DEBUG" if DEBUG else "INFO",
            "propagate": False,
        },
    },
}

# Email Configuration
# Verification and password-reset mail must really go out in production:
# SMTP by default, and the sender address has to be set explicitly.
EMAIL_BACKEND = config(
    "EMAIL_BACKEND",
    default="django.core.mail.backends.console.EmailBackend"
    if DEBUG or TESTING
    else "django.core.mail.backends.smtp.EmailBackend",
)
EMAIL_HOST = config("EMAIL_HOST", default="localhost")
EMAIL_PORT = config("EMAIL_PORT", default=587, cast=int)
EMAIL_USE_TLS = config("EMAIL_USE_TLS", default=True, cast=bool)
EMAIL_HOST_USER = config("EMAIL_HOST_USER", default="")
EMAIL_HOST_PASSWORD = config("EMAIL_HOST_PASSWORD", default="")
DEFAULT_FROM_EMAIL = config("DEFAULT_FROM_EMAIL", default="")
if not DEFAULT_FROM_EMAIL:
    if not DEBUG and not TESTING:
        raise ImproperlyConfigured(
            "DEFAULT_FROM_EMAIL is required when DEBUG is False."
        )
    DEFAULT_FROM_EMAIL = "webmaster@localhost"

# Sentry Configuration (for production error tracking)
if not DEBUG:
    import sentry_sdk
    from sentry_sdk.integrations.django import DjangoIntegration

    SENTRY_DSN = config("SENTRY_DSN", default=None)
    if SENTRY_DSN:
        sentry_sdk.init(
            dsn=SENTRY_DSN,
            integrations=[DjangoIntegration()],
            traces_sample_rate=0.1,
            send_default_pii=False,
        )

# Celery Configuration (for async tasks)
CELERY_BROKER_URL = REDIS_URL or "redis://localhost:6379/0"
CELERY_RESULT_BACKEND = REDIS_URL or "redis://localhost:6379/0"
CELERY_ACCEPT_CONTENT = ["json"]
CELERY_TASK_SERIALIZER = "json"
CELERY_RESULT_SERIALIZER = "json"
CELERY_TIMEZONE = TIME_ZONE
