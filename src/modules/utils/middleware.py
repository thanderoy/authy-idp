"""Security middleware for Authy OIDC Server"""

import ipaddress
import logging
import time
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.utils.deprecation import MiddlewareMixin
from django.conf import settings
from django.core.cache import cache
from django.db import connection

from modules.utils import throttling
from modules.utils.client_ip import get_client_ip

logger = logging.getLogger(__name__)


class HealthCheckMiddleware:
    """Answers /healthz/ with 200 when the database and cache respond.

    Runs before everything else so it isn't redirected, host-checked,
    rate-limited or logged.
    """

    PATH = "/healthz/"

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        if request.path != self.PATH:
            return self.get_response(request)
        try:
            connection.ensure_connection()
            cache.set("healthz", 1, timeout=5)
        except Exception:
            logger.exception("Health check failed")
            return JsonResponse({"status": "unavailable"}, status=503)
        return JsonResponse({"status": "ok"})


class RateLimitMiddleware(MiddlewareMixin):
    """Rate limiting middleware for API endpoints"""

    DEFAULT_RATE_LIMIT = 100  # requests per minute
    TOKEN_ENDPOINT_LIMIT = 10  # requests per minute for token endpoints

    # (path prefix, methods or None for any, limit, window seconds). The
    # first match wins; anything unmatched gets DEFAULT_RATE_LIMIT a minute.
    RULES = [
        ("/login/", {"POST"}, 10, 60),
        ("/password_reset/", {"POST"}, 5, 3600),
        ("/register/", {"POST"}, 5, 3600),
    ]

    def process_request(self, request: HttpRequest) -> HttpResponse | None:
        """Process incoming request and check rate limits"""

        # Skip rate limiting for internal IPs in debug mode
        if settings.DEBUG and get_client_ip(request) in [
            "127.0.0.1",
            "localhost",
        ]:
            return None

        # Get client identifier (IP address or authenticated user)
        client_id = self._get_client_identifier(request)

        rate_limit, window = self._get_rate_limit_for_request(request)

        cache_key = f"rate_limit:{client_id}:{request.path}"
        if throttling.hit(cache_key, window) > rate_limit:
            logger.warning(f"Rate limit exceeded for {client_id} on {request.path}")
            return JsonResponse(
                {
                    "error": "rate_limit_exceeded",
                    "message": "Too many requests. Please try again later.",
                },
                status=429,
            )

        return None

    def _get_client_identifier(self, request: HttpRequest) -> str:
        """Get unique identifier for the client"""
        if request.user and request.user.is_authenticated:
            return f"user:{request.user.id}"
        return f"ip:{get_client_ip(request)}"

    def _get_rate_limit_for_request(self, request: HttpRequest) -> tuple[int, int]:
        """Get (limit, window seconds) for this request"""
        for prefix, methods, limit, window in self.RULES:
            if request.path.startswith(prefix) and (
                methods is None or request.method in methods
            ):
                return limit, window
        if "/token" in request.path or "/authorize" in request.path:
            return self.TOKEN_ENDPOINT_LIMIT, 60
        return self.DEFAULT_RATE_LIMIT, 60


class SecurityHeadersMiddleware(MiddlewareMixin):
    """Add security headers to responses"""

    def process_response(
        self, request: HttpRequest, response: HttpResponse
    ) -> HttpResponse:
        """Add security headers to the response"""

        # Content Security Policy
        # No inline or third-party scripts: every page (ours, the admin, the
        # consent page) only loads same-origin script files. Inline styles
        # stay allowed for style attributes and the hex-validated brand
        # color; Google Fonts serves the Inter font; logos may be any https.
        response["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "img-src 'self' data: https:; "
            "font-src 'self' https://fonts.gstatic.com; "
            "connect-src 'self'; "
            "object-src 'none'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self';"
        )

        # Additional security headers
        response["X-Content-Type-Options"] = "nosniff"
        response["X-Frame-Options"] = "DENY"
        response["X-XSS-Protection"] = "1; mode=block"
        response["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response["Permissions-Policy"] = (
            "accelerometer=(), camera=(), geolocation=(), "
            "gyroscope=(), magnetometer=(), microphone=(), "
            "payment=(), usb=()"
        )

        # Strict Transport Security (only for HTTPS)
        if request.is_secure():
            response["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains; preload"
            )

        return response


class AuditLoggingMiddleware(MiddlewareMixin):
    """Audit logging for sensitive operations"""

    SENSITIVE_ENDPOINTS = [
        "/o/token/",
        "/o/authorize/",
        "/o/revoke/",
        "/o/introspect/",
        "/entities/",
    ]

    def _is_sensitive(self, path: str) -> bool:
        return path.startswith(admin_path()) or any(
            endpoint in path for endpoint in self.SENSITIVE_ENDPOINTS
        )

    def process_request(self, request: HttpRequest) -> None:
        """Log incoming requests to sensitive endpoints"""
        request._start_time = time.time()  # type: ignore

        if self._is_sensitive(request.path):
            logger.info(
                f"Audit: {request.method} {request.path} from "
                f"{get_client_ip(request)} "
                f"User: {request.user.id if request.user.is_authenticated else 'Anonymous'}"
            )

    def process_response(
        self, request: HttpRequest, response: HttpResponse
    ) -> HttpResponse:
        """Log response for sensitive endpoints"""

        if hasattr(request, "_start_time"):
            duration = time.time() - request._start_time

            if self._is_sensitive(request.path):
                logger.info(
                    f"Audit Response: {request.method} {request.path} "
                    f"Status: {response.status_code} "
                    f"Duration: {duration:.3f}s"
                )

        return response

    def process_exception(self, request: HttpRequest, exception: Exception) -> None:
        """Log exceptions in sensitive endpoints"""

        if self._is_sensitive(request.path):
            logger.error(
                f"Audit Exception: {request.method} {request.path} "
                f"Exception: {type(exception).__name__} "
                f"User: {request.user.id if request.user.is_authenticated else 'Anonymous'}"
            )


def admin_path() -> str:
    return f"/{settings.ADMIN_URL}"


class IPWhitelistMiddleware(MiddlewareMixin):
    """IP whitelist middleware for admin and sensitive endpoints

    ADMIN_IP_WHITELIST holds addresses or CIDR ranges. Outside DEBUG an empty
    list denies everyone; "*" allows all addresses explicitly (the admin
    still needs a password and an OTP token).
    """

    def process_request(self, request: HttpRequest) -> HttpResponse | None:
        """Check if IP is whitelisted for sensitive endpoints"""

        # Only apply to admin endpoints
        if not request.path.startswith(admin_path()):
            return None

        # Skip in debug mode
        if settings.DEBUG:
            return None

        whitelist = getattr(settings, "ADMIN_IP_WHITELIST", [])
        client_ip = get_client_ip(request)

        if "*" in whitelist or self._is_whitelisted(client_ip, whitelist):
            return None

        if not whitelist:
            logger.warning("Admin access refused: ADMIN_IP_WHITELIST is empty")
        else:
            logger.warning(f"Unauthorized admin access attempt from {client_ip}")
        return JsonResponse(
            {"error": "forbidden", "message": "Access denied"}, status=403
        )

    @staticmethod
    def _is_whitelisted(client_ip: str, whitelist: list[str]) -> bool:
        try:
            address = ipaddress.ip_address(client_ip)
        except ValueError:
            return False
        for entry in whitelist:
            try:
                if address in ipaddress.ip_network(entry, strict=False):
                    return True
            except ValueError:
                logger.error(f"Ignoring invalid ADMIN_IP_WHITELIST entry: {entry}")
        return False


class RequestSizeMiddleware(MiddlewareMixin):
    """Limit request body size to prevent DoS attacks"""

    MAX_REQUEST_SIZE = 10 * 1024 * 1024  # 10 MB

    def process_request(self, request: HttpRequest) -> HttpResponse | None:
        """Check request body size"""

        if request.method in ["POST", "PUT", "PATCH"]:
            content_length = request.META.get("CONTENT_LENGTH")

            if content_length:
                try:
                    size = int(content_length)
                    if size > self.MAX_REQUEST_SIZE:
                        logger.warning(
                            f"Request too large: {size} bytes from "
                            f"{get_client_ip(request)}"
                        )
                        return JsonResponse(
                            {
                                "error": "request_too_large",
                                "message": "Request body too large",
                            },
                            status=413,
                        )
                except (ValueError, TypeError):
                    pass

        return None


class SessionSecurityMiddleware(MiddlewareMixin):
    """Enhanced session security"""

    def process_request(self, request: HttpRequest) -> None:
        """Process request and check session security"""

        if request.user.is_authenticated:
            # Check for session hijacking by comparing IP
            session_ip = request.session.get("ip_address")
            current_ip = get_client_ip(request)

            if session_ip and session_ip != current_ip:
                logger.warning(
                    f"Possible session hijacking detected. "
                    f"User: {request.user.id}, "
                    f"Session IP: {session_ip}, Current IP: {current_ip}"
                )
                # Optionally invalidate the session
                # request.session.flush()

            # Store/update session IP
            if not session_ip:
                request.session["ip_address"] = current_ip

            # Update last activity timestamp
            request.session["last_activity"] = time.time()
