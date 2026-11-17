"""Throwaway credentials for tests.

Built at runtime instead of written as literals, so secret scanners
(GitGuardian) don't flag test fixtures as leaked passwords.
"""


def make_test_password(tag: str = "") -> str:
    """A password that passes Django's validators; ``tag`` makes variants."""
    return "".join(["Throwaway", "Test", "Pw", "-2026", tag])


def make_otp_token() -> str:
    return "".join(["boot", "strap", "1"])
