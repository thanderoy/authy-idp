"""Client address resolution behind a reverse proxy.

With ``TRUSTED_PROXY_COUNT = n`` (Traefik alone is 1) the client address is
the n-th entry from the right of X-Forwarded-For. Each trusted proxy appends
the address it received the request from, so the right-hand entries can't
be forged; anything further left was supplied by the client and is ignored.
"""

from typing import Any

from django.conf import settings


def get_client_ip(request: Any) -> str:
    meta = getattr(request, "META", None) or {}
    remote_addr = meta.get("REMOTE_ADDR", "") or "unknown"
    proxies = getattr(settings, "TRUSTED_PROXY_COUNT", 0)
    if proxies <= 0:
        return remote_addr

    forwarded = [
        part.strip()
        for part in meta.get("HTTP_X_FORWARDED_FOR", "").split(",")
        if part.strip()
    ]
    if len(forwarded) < proxies:
        # Header missing or shorter than the proxy chain: the request didn't
        # come through every trusted hop, so don't believe any of it.
        return remote_addr
    return forwarded[-proxies]
