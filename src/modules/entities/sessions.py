"""Record and end a user's sessions (the console's "Active Devices")."""

from importlib import import_module

from django.conf import settings
from django.contrib.auth.signals import user_logged_in, user_logged_out
from django.contrib.sessions.models import Session
from django.dispatch import receiver
from django.utils import timezone

from modules.entities.models import UserSession
from modules.utils.client_ip import get_client_ip


def _session_store(session_key):
    engine = import_module(settings.SESSION_ENGINE)
    return engine.SessionStore(session_key)


@receiver(user_logged_in)
def record_session(sender, request, user, **kwargs):
    if request is None or not hasattr(request, "session"):
        return  # e.g. the OAuth password grant: no browser session
    touch_session(request, user)


def touch_session(request, user):
    """Create or refresh the record for the request's own session."""
    if request.session.session_key is None:
        request.session.save()
    ip = get_client_ip(request)
    user_agent = request.META.get("HTTP_USER_AGENT", "")[:255]
    # Only overwrite what this request actually tells us.
    defaults = {"user": user}
    if ip != "unknown":
        defaults["ip"] = ip
    if user_agent:
        defaults["user_agent"] = user_agent
    UserSession.objects.update_or_create(
        session_key=request.session.session_key, defaults=defaults
    )


@receiver(user_logged_out)
def forget_session(sender, request, user, **kwargs):
    if request is not None and request.session.session_key:
        UserSession.objects.filter(session_key=request.session.session_key).delete()


def active_sessions(user):
    """The user's sessions that still exist and haven't expired."""
    live = Session.objects.filter(expire_date__gt=timezone.now()).values("session_key")
    UserSession.objects.filter(user=user).exclude(session_key__in=live).delete()
    return UserSession.objects.filter(user=user)


def end_session(user, pk) -> bool:
    """Sign one of the user's sessions out. False if it isn't theirs."""
    record = UserSession.objects.filter(user=user, pk=pk).first()
    if record is None:
        return False
    _session_store(record.session_key).delete()
    record.delete()
    return True
