import pytest
from django.contrib.auth import get_user_model
from modules.entities.models import Entity

User = get_user_model()


@pytest.mark.django_db
class TestEntityModels:
    def test_person_manager(self):
        person = User.objects.create_user(
            first_name="Marco",
            last_name="Polo",
            email="marco@example.com",
            password="sys",
        )
        group = User.objects.create_user(
            first_name="Admin",
            last_name="Group",
            email="admin@example.com",
            password="sys",
            entity_type=Entity.EntityType.GROUP,
        )

        persons = Entity.persons.all()
        assert person in persons
        assert group not in persons

    def test_group_manager(self):
        person = User.objects.create_user(
            first_name="Marco",
            last_name="Polo",
            email="marco@example.com",
            password="sys",
        )
        group = User.objects.create_user(
            first_name="Admin",
            last_name="Group",
            email="admin@example.com",
            password="sys",
            entity_type=Entity.EntityType.GROUP,
        )

        groups = Entity.groups.all()
        assert group in groups
        assert person not in groups

    def test_entity_names_property(self):
        person = User.objects.create_user(
            first_name="Marco",
            last_name="Polo",
            email="marco@example.com",
            password="sys",
        )
        assert person.names == "Marco Polo"


@pytest.mark.django_db
class TestEmailCaseInsensitivity:
    def test_manager_lowercases_whole_address(self):
        user = User.objects.create_user("A", "B", "Victim@Example.COM", "x")
        assert user.email == "victim@example.com"

    def test_cannot_create_case_variant_duplicate(self):
        from django.db import IntegrityError

        User.objects.create_user("A", "B", "victim@example.com", "x")
        with pytest.raises(IntegrityError):
            User.objects.create(
                first_name="C", last_name="D", email="Victim@example.com"
            )

    def test_login_lookup_is_case_insensitive(self):
        user = User.objects.create_user("A", "B", "victim@example.com", "x")
        assert User.objects.get_by_natural_key("VICTIM@example.com") == user


@pytest.mark.django_db
class TestRegistrationRejectsCaseVariant:
    def test_register_form_rejects_case_variant(self, client):
        User.objects.create_user("A", "B", "victim@example.com", "x")
        response = client.post(
            "/register/",
            {
                "first_name": "Eve",
                "last_name": "Attacker",
                "email": "Victim@example.com",
                "password1": "StrongP@ss2026!",
                "password2": "StrongP@ss2026!",
            },
        )
        assert response.status_code == 200
        assert "email" in response.context["form"].errors
        assert User.objects.filter(email__iexact="victim@example.com").count() == 1

    def test_serializer_rejects_case_variant(self):
        from modules.entities.serializers import EntitySerializer

        User.objects.create_user("A", "B", "victim@example.com", "x")
        serializer = EntitySerializer(
            data={
                "first_name": "Eve",
                "last_name": "Attacker",
                "email": "Victim@example.com",
                "password": "StrongP@ss2026!",
                "confirm_password": "StrongP@ss2026!",
            }
        )
        assert not serializer.is_valid()
        assert "email" in serializer.errors
