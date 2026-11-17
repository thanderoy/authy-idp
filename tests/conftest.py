import pytest
from django.core.cache import cache


@pytest.fixture(autouse=True)
def _clear_cache():
    # Rate limits, lockouts and the token blacklist live in the cache; keep
    # one test's counters from leaking into the next.
    cache.clear()
    yield
    cache.clear()
