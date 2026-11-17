import pytest
from django.contrib.auth import get_user_model
from modules.entities.serializers import EntitySerializer

User = get_user_model()


@pytest.mark.django_db
class TestEntitySerializer:
    def test_validate_passwords_match(self):
        serializer = EntitySerializer(
            data={
                "first_name": "Test",
                "last_name": "User",
                "email": "testuser@example.com",
                "password": "strongpassword123",
                "confirm_password": "strongpassword123",
            }
        )
        assert serializer.is_valid(), serializer.errors

    def test_validate_passwords_mismatch(self):
        serializer = EntitySerializer(
            data={
                "first_name": "Test",
                "last_name": "User",
                "email": "testuser@example.com",
                "password": "strongpassword123",
                "confirm_password": "wrongpassword123",
            }
        )
        assert not serializer.is_valid()
        assert "non_field_errors" in serializer.errors

    def test_create_with_password(self):
        serializer = EntitySerializer(
            data={
                "first_name": "Test",
                "last_name": "User",
                "email": "testuser2@example.com",
                "password": "strongpassword123",
                "confirm_password": "strongpassword123",
            }
        )
        assert serializer.is_valid()
        user = serializer.save()
        assert user.check_password("strongpassword123")

    def test_update_without_password(self):
        user = User.objects.create_user(
            first_name="Marco",
            last_name="Polo",
            email="marco@example.com",
            password="testpass123",
        )
        serializer = EntitySerializer(
            instance=user,
            data={
                "first_name": "Marco Updated",
                "last_name": "Polo",
            },
            partial=True,
        )
        assert serializer.is_valid()
        updated_user = serializer.save()
        assert updated_user.first_name == "Marco Updated"

    def test_update_with_password(self):
        user = User.objects.create_user(
            first_name="Marco",
            last_name="Polo",
            email="marco@example.com",
            password="testpass123",
        )
        serializer = EntitySerializer(
            instance=user,
            data={"password": "newpassword123", "confirm_password": "newpassword123"},
            partial=True,
        )
        assert serializer.is_valid(), serializer.errors
        updated_user = serializer.save()
        assert updated_user.check_password("newpassword123")


@pytest.mark.django_db
class TestEntityMeSerializer:
    PASSWORD = "Current-P@ss-2026"

    @pytest.fixture
    def user(self):
        return User.objects.create_user(
            "Marco", "Polo", "marco@example.com", self.PASSWORD, email_verified=True
        )

    def _update(self, user, data):
        from modules.entities.serializers import EntityMeSerializer

        return EntityMeSerializer(instance=user, data=data, partial=True)

    def test_email_change_requires_current_password(self, user):
        serializer = self._update(user, {"email": "new@example.com"})
        assert not serializer.is_valid()
        assert "current_password" in serializer.errors

    def test_email_change_with_wrong_password_rejected(self, user):
        serializer = self._update(
            user, {"email": "new@example.com", "current_password": "wrong"}
        )
        assert not serializer.is_valid()

    def test_password_change_requires_current_password(self, user):
        serializer = self._update(
            user, {"password": "N3w-P@ss-2026!", "confirm_password": "N3w-P@ss-2026!"}
        )
        assert not serializer.is_valid()
        assert "current_password" in serializer.errors

    def test_email_change_resets_verification_and_sends_link(self, user, rf):
        from django.core import mail
        from modules.entities.serializers import EntityMeSerializer

        serializer = EntityMeSerializer(
            instance=user,
            data={"email": "New@example.com", "current_password": self.PASSWORD},
            partial=True,
            context={"request": rf.get("/")},
        )
        assert serializer.is_valid(), serializer.errors
        serializer.save()
        user.refresh_from_db()
        assert user.email == "new@example.com"
        assert user.email_verified is False
        assert mail.outbox[0].to == ["new@example.com"]

    def test_name_change_needs_no_password(self, user):
        serializer = self._update(user, {"first_name": "Marcus"})
        assert serializer.is_valid(), serializer.errors

    def test_cannot_change_entity_type_or_groups(self, user):
        group = User.objects.create_user(
            "Admins", "Group", "admins@example.com", "x", entity_type="GRP"
        )
        serializer = self._update(
            user, {"entity_type": "GRP", "organizations": [group.pk]}
        )
        assert serializer.is_valid()
        serializer.save()
        user.refresh_from_db()
        assert user.entity_type == "PSN"
        assert not user.parent_entities.exists()
