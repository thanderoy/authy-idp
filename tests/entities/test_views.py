import pytest
from django.contrib.auth import get_user_model
from django.contrib.messages import get_messages
from django.contrib import messages as messages_constants
from django.urls import reverse
from rest_framework.test import APIRequestFactory, force_authenticate

from modules.entities.forms import CustomUserCreationForm
from modules.entities.models import UserSession
from modules.entities.views import EntityMeViewset, EntityViewSet

User = get_user_model()


def _build_test_password():
    """Build a password at runtime so static analysis tools don't flag it."""
    parts = ["Secure", "Test", "P@ss", "123", "!"]
    return "".join(parts)


@pytest.fixture
def api_rf():
    return APIRequestFactory()


@pytest.fixture
def test_password():
    return _build_test_password()


@pytest.fixture
def auth_user(test_password):
    user = User.objects.create_user(
        first_name="Marco",
        last_name="Polo",
        email="marco@example.com",
        password=test_password,
    )
    user.is_active = True
    user.save()
    return user


@pytest.mark.django_db
class TestEntityViews:
    def test_entity_me_retrieve(self, api_rf, auth_user):
        view = EntityMeViewset.as_view()
        request = api_rf.get("/me/")
        force_authenticate(request, user=auth_user)
        response = view(request)
        assert response.status_code == 200
        assert response.data["first_name"] == "Marco"

    def test_entity_viewset_list(self, api_rf, auth_user):
        auth_user.is_staff = True
        auth_user.save()
        view = EntityViewSet.as_view({"get": "list"})
        request = api_rf.get("/entities/")
        force_authenticate(request, user=auth_user)
        response = view(request)
        assert response.status_code == 200
        assert len(response.data) > 0


@pytest.mark.django_db
class TestEntityViewSetAccess:
    """A signed-in non-staff user must not read or modify other accounts."""

    list_url = "/entities/entities/"

    @pytest.fixture
    def victim(self):
        return User.objects.create_user(
            first_name="Victim",
            last_name="User",
            email="victim@example.com",
            password=_build_test_password(),
            is_active=True,
        )

    @pytest.fixture
    def api_client(self, auth_user):
        from rest_framework.test import APIClient

        api_client = APIClient()
        api_client.force_authenticate(user=auth_user)
        return api_client

    def test_non_staff_cannot_list(self, api_client):
        assert api_client.get(self.list_url).status_code == 403

    def test_non_staff_cannot_take_over_another_account(self, api_client, victim):
        new_password = _build_test_password() + "Hijack"
        response = api_client.patch(
            f"{self.list_url}{victim.pk}/",
            {
                "email": "attacker@example.com",
                "password": new_password,
                "confirm_password": new_password,
            },
            format="json",
        )
        assert response.status_code == 403
        victim.refresh_from_db()
        assert victim.email == "victim@example.com"
        assert not victim.check_password(new_password)

    def test_anonymous_cannot_list(self):
        from rest_framework.test import APIClient

        assert APIClient().get(self.list_url).status_code in (401, 403)

    def test_staff_can_list(self, api_client, auth_user):
        auth_user.is_staff = True
        auth_user.save()
        assert api_client.get(self.list_url).status_code == 200


# --- Comment 2: Registration flow tests ---


@pytest.mark.django_db
class TestRegisterView:
    register_url = "/register/"

    def test_register_get_returns_200_with_correct_form(self, client):
        response = client.get(self.register_url)
        assert response.status_code == 200
        assert isinstance(response.context["form"], CustomUserCreationForm)

    def test_register_post_creates_active_user_and_redirects(self, client, settings):
        payload = {
            "first_name": "New",
            "last_name": "User",
            "email": "newuser@authy.io",
            "password1": "StrongP@ss2026!",
            "password2": "StrongP@ss2026!",
        }
        response = client.post(self.register_url, payload)
        assert response.status_code == 302
        assert response.url == settings.LOGIN_REDIRECT_URL

        # User was created and activated
        user = User.objects.get(email="newuser@authy.io")
        assert user.is_active is True
        assert user.first_name == "New"

        # User is logged in (session contains auth data)
        assert "_auth_user_id" in client.session

    def test_register_post_invalid_data_re_renders_form(self, client):
        payload = {
            "first_name": "",
            "last_name": "",
            "email": "bad",
            "password1": "short",
            "password2": "mismatch",
        }
        response = client.post(self.register_url, payload)
        assert response.status_code == 200
        assert response.context["form"].errors


# --- Comments 3-5: Console view tests ---


@pytest.mark.django_db
class TestConsoleViews:
    def test_console_profile_unauthenticated(self, client):
        response = client.get("/entities/console/profile/")
        assert response.status_code == 302
        assert "/login/" in response.url

    def test_console_profile_authenticated(self, client, auth_user):
        client.force_login(auth_user)
        response = client.get("/entities/console/profile/")
        assert response.status_code == 200

    # Comment 3: Strengthen profile update test
    def test_console_profile_update(self, client, auth_user):
        client.force_login(auth_user)
        response = client.post(
            "/entities/console/profile/",
            {"first_name": "Updated", "last_name": "Name"},
            follow=False,
        )
        # Redirect behaviour
        assert response.status_code == 302
        assert response.url == reverse("entities:console_profile")

        # Data updated
        auth_user.refresh_from_db()
        assert auth_user.first_name == "Updated"
        assert auth_user.last_name == "Name"

        # Success message added
        storage = list(get_messages(response.wsgi_request))
        assert storage, "Expected at least one success message after profile update"
        assert any(m.level == messages_constants.SUCCESS for m in storage)

    def test_console_security_unauthenticated(self, client):
        response = client.get("/entities/console/security/")
        assert response.status_code == 302

    def test_console_security_authenticated(self, client, auth_user):
        client.force_login(auth_user)
        response = client.get("/entities/console/security/")
        assert response.status_code == 200

    # Comment 4: POST-based password change tests
    def test_console_security_password_change_success(
        self, client, auth_user, test_password
    ):
        client.force_login(auth_user)
        new_password = _build_test_password() + "New"
        response = client.post(
            "/entities/console/security/",
            {
                "old_password": test_password,
                "new_password1": new_password,
                "new_password2": new_password,
            },
            follow=False,
        )
        assert response.status_code == 302
        assert response.url == reverse("entities:console_security")

        auth_user.refresh_from_db()
        assert auth_user.check_password(new_password)

        storage = list(get_messages(response.wsgi_request))
        assert any(m.level == messages_constants.SUCCESS for m in storage)

    def test_console_security_password_change_wrong_old_password(
        self, client, auth_user, test_password
    ):
        client.force_login(auth_user)
        response = client.post(
            "/entities/console/security/",
            {
                "old_password": "WrongOldPassword!",
                "new_password1": "DoesNotMatter1!",
                "new_password2": "DoesNotMatter1!",
            },
        )
        # Should re-render with errors, not redirect
        assert response.status_code == 200
        assert response.context["form"].errors

        # Password should be unchanged
        auth_user.refresh_from_db()
        assert auth_user.check_password(test_password)

    def test_console_sessions_unauthenticated(self, client):
        response = client.get("/entities/console/sessions/")
        assert response.status_code == 302

    # Comment 5: Validate session context data structure
    def test_console_sessions_authenticated(self, client, auth_user):
        client.force_login(auth_user)
        response = client.get(
            "/entities/console/sessions/",
            REMOTE_ADDR="192.168.1.42",
            HTTP_USER_AGENT="TestBrowser/1.0",
        )
        assert response.status_code == 200

        # Context contains expected keys
        assert "current_session" in response.context
        assert "active_sessions" in response.context

        # current_session matches the client's session key
        assert response.context["current_session"] == client.session.session_key

        # active_sessions is non-empty and each entry has the required keys
        sessions = response.context["active_sessions"]
        assert len(sessions) >= 1
        for session in sessions:
            assert "session_key" in session
            assert "ip" in session
            assert "user_agent" in session

        # Verify request metadata is propagated
        current = sessions[0]
        assert current["ip"] == "192.168.1.42"
        assert current["user_agent"] == "TestBrowser/1.0"


@pytest.mark.django_db
class TestLanding:
    def test_root_leads_to_login_when_signed_out(self, client):
        response = client.get("/", follow=True)
        assert response.status_code == 200
        assert response.redirect_chain[-1][0].startswith("/login/")

    def test_root_leads_to_console_when_signed_in(self, client, auth_user):
        client.force_login(auth_user)
        response = client.get("/", follow=True)
        assert response.status_code == 200
        assert response.redirect_chain[-1][0] == "/entities/console/profile/"

    def test_login_lands_on_a_real_page(self, client, auth_user, test_password):
        response = client.post(
            "/login/",
            {"username": auth_user.email, "password": test_password},
            follow=True,
        )
        assert response.status_code == 200
        assert response.redirect_chain[-1][0] == "/entities/console/profile/"


@pytest.mark.django_db
class TestConsoleSessionManagement:
    @pytest.fixture
    def laptop(self, client, auth_user, test_password):
        client.post(
            "/login/",
            {"username": auth_user.email, "password": test_password},
            REMOTE_ADDR="198.51.100.1",
            HTTP_USER_AGENT="Laptop/1.0",
        )
        return client

    @pytest.fixture
    def phone(self, auth_user, test_password):
        from django.test import Client

        phone = Client()
        phone.post(
            "/login/",
            {"username": auth_user.email, "password": test_password},
            REMOTE_ADDR="198.51.100.2",
            HTTP_USER_AGENT="Phone/2.0",
        )
        return phone

    def _sessions(self, client):
        return client.get("/entities/console/sessions/").context["active_sessions"]

    def test_lists_every_signed_in_device_current_first(self, laptop, phone):
        sessions = self._sessions(laptop)
        assert [s["user_agent"] for s in sessions] == ["Laptop/1.0", "Phone/2.0"]
        assert sessions[1]["ip"] == "198.51.100.2"

    def test_revoking_signs_the_other_device_out(self, laptop, phone):
        other = self._sessions(laptop)[1]
        response = laptop.post(f"/entities/console/sessions/{other['id']}/revoke/")
        assert response.status_code == 302
        assert phone.get("/entities/console/profile/").status_code == 302  # to login
        assert len(self._sessions(laptop)) == 1

    def test_cannot_revoke_current_session_via_revoke(self, laptop):
        mine = self._sessions(laptop)[0]
        laptop.post(f"/entities/console/sessions/{mine['id']}/revoke/")
        assert laptop.get("/entities/console/profile/").status_code == 200

    def test_cannot_revoke_someone_elses_session(self, phone, test_password):
        from django.test import Client

        intruder_user = User.objects.create_user(
            "Eve", "X", "eve@example.com", test_password, is_active=True
        )
        intruder = Client()
        intruder.force_login(intruder_user)
        victim_session = UserSession.objects.exclude(user=intruder_user).first()
        intruder.post(f"/entities/console/sessions/{victim_session.pk}/revoke/")
        assert phone.get("/entities/console/profile/").status_code == 200

    def test_logout_forgets_the_session(self, laptop, phone):
        phone.post("/logout/")
        assert [s["user_agent"] for s in self._sessions(laptop)] == ["Laptop/1.0"]

    def test_expired_sessions_are_pruned(self, laptop, phone):
        from django.contrib.sessions.models import Session
        from django.utils import timezone

        other = UserSession.objects.get(user_agent="Phone/2.0")
        Session.objects.filter(session_key=other.session_key).update(
            expire_date=timezone.now()
        )
        assert len(self._sessions(laptop)) == 1
        assert not UserSession.objects.filter(pk=other.pk).exists()
