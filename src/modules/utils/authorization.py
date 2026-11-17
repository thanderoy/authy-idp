"""OIDC authorization endpoint with prompt=none support."""

from django.template.response import TemplateResponse
from oauth2_provider.views import AuthorizationView
from oauthlib.openid.connect.core.exceptions import ConsentRequired


class SilentAwareAuthorizationView(AuthorizationView):
    """DOT's AuthorizationView, plus the consent half of prompt=none.

    DOT already answers an unauthenticated prompt=none with login_required
    and skips the consent page for skip_authorization apps or prior
    approval. What's left is the case where it would show the consent
    page; OIDC Core 3.1.2.1 forbids any UI for prompt=none, so redirect
    back with consent_required instead.
    """

    def get(self, request, *args, **kwargs):
        response = super().get(request, *args, **kwargs)
        prompt = set(request.GET.get("prompt", "").split())
        if "none" not in prompt or not isinstance(response, TemplateResponse):
            return response

        context = response.context_data or {}
        form = context.get("form")
        if form is None or "redirect_uri" not in form.initial:
            # Not the consent page (e.g. an error page); leave it alone.
            return response

        error = ConsentRequired(state=request.GET.get("state"))
        return self.redirect(
            error.in_uri(form.initial["redirect_uri"]), context.get("application")
        )
