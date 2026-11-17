from rest_framework import permissions, viewsets, generics
from rest_framework.response import Response
from modules.entities.models import Entity
from modules.entities.serializers import EntitySerializer, EntityMeSerializer

from django.views.generic.edit import CreateView, UpdateView
from django.views.generic import TemplateView, View
from django.views.decorators.http import require_POST
from django.utils.decorators import method_decorator
from django.utils.http import urlsafe_base64_decode
from django.shortcuts import redirect, render
from django.urls import reverse_lazy
from django.contrib.auth import login
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.views import PasswordChangeView
from django.contrib import messages
from django.conf import settings

from modules.utils.client_ip import get_client_ip
from modules.entities.forms import CustomUserCreationForm, UserUpdateForm
from modules.entities.verification import (
    email_verification_token,
    send_verification_email,
)


class RegisterView(CreateView):
    template_name = "registration/register.html"
    form_class = CustomUserCreationForm

    def get_success_url(self):
        return settings.LOGIN_REDIRECT_URL

    def form_valid(self, form):
        response = super().form_valid(form)
        user = self.object
        user.is_active = True
        user.save(update_fields=["is_active"])
        login(
            self.request,
            user,
            backend="modules.entities.backends.LockoutModelBackend",
        )
        send_verification_email(self.request, user)
        return response


class VerifyEmailView(View):
    """Marks the address verified when the signed link checks out."""

    def get(self, request, uidb64, token):
        try:
            user = Entity.objects.get(pk=urlsafe_base64_decode(uidb64).decode())
        except (TypeError, ValueError, OverflowError, Entity.DoesNotExist):
            user = None

        verified = user is not None and email_verification_token.check_token(
            user, token
        )
        if verified:
            user.email_verified = True
            user.save(update_fields=["email_verified"])
        return render(
            request,
            "registration/verify_email_done.html",
            {"verified": verified},
            status=200 if verified else 400,
        )


@method_decorator(require_POST, name="dispatch")
class ResendVerificationView(LoginRequiredMixin, View):
    def post(self, request):
        if not request.user.email_verified:
            send_verification_email(request, request.user)
            messages.success(request, "We've sent a new verification link.")
        return redirect("entities:console_profile")


class EntityViewSet(viewsets.ModelViewSet):
    """Directory-wide entity management. Staff only: it can read and rewrite
    any account. Users manage their own account through the console."""

    queryset = Entity.objects.all()
    serializer_class = EntitySerializer
    permission_classes = [permissions.IsAdminUser]


class EntityMeViewset(generics.RetrieveUpdateAPIView):
    queryset = None
    serializer_class = EntityMeSerializer
    permission_classes = (permissions.IsAuthenticated,)

    def get_object(self):
        return self.request.user

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        data = serializer.data

        return Response(data)


class ConsoleProfileView(LoginRequiredMixin, UpdateView):
    template_name = "console/profile.html"
    form_class = UserUpdateForm
    success_url = reverse_lazy("entities:console_profile")

    def get_object(self, queryset=None):
        return self.request.user

    def form_valid(self, form):
        messages.success(self.request, "Your profile has been updated successfully.")
        return super().form_valid(form)


class ConsoleSecurityView(LoginRequiredMixin, PasswordChangeView):
    template_name = "console/security.html"
    success_url = reverse_lazy("entities:console_security")

    def form_valid(self, form):
        messages.success(self.request, "Your password has been changed successfully.")
        return super().form_valid(form)


class ConsoleSessionsView(LoginRequiredMixin, TemplateView):
    template_name = "console/sessions.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        # TODO: Replace this simulated session list with a real session
        # query once the project supports a database-backed session engine.
        # Currently Django's cache-backed sessions are not indexed by user,
        # so we only surface the current request's session metadata.
        context["current_session"] = self.request.session.session_key
        context["active_sessions"] = self._get_active_sessions()
        return context

    def _get_active_sessions(self):
        """Return a list of session dicts for the authenticated user.

        This is an abstraction point: when the project migrates to
        database-backed sessions, this method should query all sessions
        belonging to ``self.request.user`` without changing the template
        contract (each dict must contain ``session_key``, ``ip``, and
        ``user_agent``).
        """
        return [
            {
                "session_key": self.request.session.session_key,
                "ip": get_client_ip(self.request),
                "user_agent": self.request.META.get("HTTP_USER_AGENT", "Unknown"),
            }
        ]
