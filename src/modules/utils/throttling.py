"""Cache-backed counters for rate limits and login lockout.

``cache.add`` + ``cache.incr`` is atomic on Redis, so concurrent requests
can't slip past a limit the way a get-then-set counter allows.
"""

from django.core.cache import cache


def hit(key: str, window: int) -> int:
    """Count one event in a fixed window and return the running total."""
    cache.add(key, 0, timeout=window)
    try:
        return cache.incr(key)
    except ValueError:
        # Expired between add and incr; this is the first hit of a new window.
        cache.add(key, 1, timeout=window)
        return 1


def count(key: str) -> int:
    return cache.get(key, 0)


def reset(key: str) -> None:
    cache.delete(key)
