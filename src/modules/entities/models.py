import re

from django.conf import settings
from django.contrib.auth.models import (
    AbstractBaseUser,
    BaseUserManager,
    PermissionsMixin,
)
from django.core.exceptions import ValidationError
from django.db import models
from django.db.models.functions import Lower

from modules.common.models import AuthyBaseModel

HEX_COLOR_RE = re.compile(r"^#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6})$")


def validate_hex_color(value: str) -> None:
    """Ensure ``value`` is a strict 3‑ or 6‑digit hex color."""
    if not HEX_COLOR_RE.match(value):
        raise ValidationError(
            "%(value)s is not a valid hex color (expected #RGB or #RRGGBB).",
            params={"value": value},
        )


class EntityManager(BaseUserManager):
    use_in_migrations = True

    @classmethod
    def normalize_email(cls, email):
        # The whole address is lowercased, not just the domain, so that
        # "Victim@x.com" and "victim@x.com" can't be two accounts.
        return (email or "").strip().lower()

    def get_by_natural_key(self, username):
        return self.get(**{f"{self.model.USERNAME_FIELD}__iexact": username})

    def _create_user(
        self, first_name, last_name, email, password, entity_type="PSN", **extra_fields
    ):  # noqa
        if not first_name:
            raise ValueError("First Name is required.")
        if not last_name:
            raise ValueError("Last Name is required.")
        if not email:
            raise ValueError("Email is required.")
        # Non-Person enitities are not allowed to login only used
        #    for communication and entity management. No pass expiry
        if entity_type != self.model.EntityType.PERSON:
            extra_fields["is_system_entity"] = True

        email = self.normalize_email(email)
        user = self.model(
            first_name=first_name,
            last_name=last_name,
            email=email,
            entity_type=entity_type,
            **extra_fields,
        )
        user.set_password(password)
        user.save()
        return user

    def create_user(
        self, first_name, last_name, email, password, entity_type="PSN", **extra_fields
    ):  # noqa
        extra_fields.setdefault("is_staff", False)
        extra_fields.setdefault("is_superuser", False)

        return self._create_user(
            first_name, last_name, email, password, entity_type, **extra_fields
        )  # noqa

    def create_superuser(
        self, first_name, last_name, email, password, entity_type="PSN", **extra_fields
    ):  # noqa
        extra_fields.setdefault("is_active", True)
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)

        if extra_fields.get("is_staff") is not True:
            raise ValueError("Superuser must have is_staff=True.")
        if extra_fields.get("is_superuser") is not True:
            raise ValueError("Superuser must have is_superuser=True.")

        return self._create_user(
            first_name, last_name, email, password, entity_type, **extra_fields
        )  # noqa


class PersonManager(EntityManager):
    def get_queryset(self):
        return super().get_queryset().filter(entity_type=self.model.EntityType.PERSON)


class GroupManager(EntityManager):
    def get_queryset(self):
        return super().get_queryset().filter(entity_type=self.model.EntityType.GROUP)


class Entity(AuthyBaseModel, AbstractBaseUser, PermissionsMixin):
    class EntityType(models.TextChoices):
        PERSON = "PSN", "Person"
        GROUP = "GRP", "Group"

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = [
        "first_name",
        "last_name",
    ]

    # Entity details
    first_name = models.CharField(max_length=50, blank=False, null=False)
    last_name = models.CharField(max_length=50, blank=False, null=False)
    entity_type = models.CharField(
        choices=EntityType.choices, max_length=3, default=EntityType.PERSON
    )
    email = models.EmailField(max_length=255, unique=True, blank=False, null=False)  # noqa
    email_verified = models.BooleanField(default=False)

    # Access + Priviledges
    is_active = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)
    is_system_entity = models.BooleanField(default=False)

    # Relationships
    child_entities = models.ManyToManyField(
        "self",
        through="Relationship",
        symmetrical=False,
        related_name="parent_entities",
    )  # noqa: E501

    # Managers
    objects = EntityManager()
    persons = PersonManager()
    groups = GroupManager()  # type: ignore

    class Meta(object):
        ordering = (
            "first_name",
            "last_name",
        )
        constraints = [
            models.UniqueConstraint(Lower("email"), name="entity_email_ci_unique"),
        ]

    def save(self, *args, **kwargs):
        self.email = self.__class__.objects.normalize_email(self.email)
        super().save(*args, **kwargs)

    @property
    def names(self):
        return f"{self.first_name} {self.last_name}"

    def __str__(self) -> str:
        return f"{self.entity_type} ({self.id})- {self.names}"


class Relationship(AuthyBaseModel):
    class RelationshipType(models.TextChoices):
        UNDEFINED = "UND", "Undefined"
        MEMBER = "MEM", "Member"

    parent = models.ForeignKey(
        Entity, on_delete=models.CASCADE, related_name="parent_relations"
    )
    child = models.ForeignKey(
        Entity, on_delete=models.CASCADE, related_name="child_relations"
    )
    relationship_type = models.CharField(
        choices=RelationshipType.choices,
        max_length=50,
        default=RelationshipType.UNDEFINED,
    )  # noqa: E501

    def __str__(self) -> str:
        return f"{self.relationship_type} - ({self.parent} -> {self.child})"


class ApplicationBranding(AuthyBaseModel):
    """Stores UI branding configuration for an OAuth2 Application.

    When a user arrives at the login page via an OIDC flow, the ``client_id``
    query parameter is used to look up the matching branding record. The
    template then renders the application's custom logo, colors, and name
    instead of the default Authy branding.
    """

    application = models.OneToOneField(
        settings.OAUTH2_PROVIDER_APPLICATION_MODEL,
        on_delete=models.CASCADE,
        related_name="branding",
    )
    logo_url = models.URLField(
        max_length=500,
        blank=True,
        help_text="URL to the application's logo image (displayed on login/register screens).",
    )
    brand_color = models.CharField(
        max_length=7,
        blank=True,
        validators=[validate_hex_color],
        help_text="Primary brand hex color (e.g. #1C352D) used for buttons and accents.",
    )

    class Meta:
        verbose_name = "Application Branding"
        verbose_name_plural = "Application Brandings"

    def __str__(self) -> str:
        return f"Branding for {self.application.name}"


class UserSession(models.Model):
    """One signed-in browser session, so a user can see and end their
    sessions from the console. Sessions themselves live in Django's
    session store, which can't be queried by user; this table indexes them.
    """

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="sessions"
    )
    session_key = models.CharField(max_length=40, unique=True)
    ip = models.CharField(max_length=45, blank=True)  # IPv4 or IPv6
    user_agent = models.CharField(max_length=255, blank=True)
    created = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("-last_seen",)

    def __str__(self) -> str:
        return f"Session for {self.user_id} from {self.ip}"
