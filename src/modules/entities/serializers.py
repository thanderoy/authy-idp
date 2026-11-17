from rest_framework import serializers
from django.contrib.auth import get_user_model, password_validation
from rest_framework.exceptions import ValidationError
from modules.entities.models import Entity

USER_MODEL = get_user_model()


class EntitySerializer(serializers.ModelSerializer):
    confirm_password = serializers.CharField(write_only=True, required=True)
    # Read-only: membership is managed through Relationship, not this API.
    organizations = serializers.ManyRelatedField(
        child_relation=serializers.PrimaryKeyRelatedField(read_only=True),
        source="parent_entities",
        read_only=True,
    )
    # parent_entities = serializers.StringRelatedField(many=True)

    class Meta:
        model = USER_MODEL
        fields: tuple[str, ...] = (
            "uuid",
            "first_name",
            "last_name",
            "email",
            "entity_type",
            "password",
            "confirm_password",
            "is_active",
            "is_system_entity",
            "organizations",
        )
        read_only_fields: tuple[str, ...] = ("uuid", "is_active", "is_system_entity")
        extra_kwargs = {"password": {"write_only": True}}

    def validate_email(self, value):
        value = Entity.objects.normalize_email(value)
        existing = Entity.objects.filter(email__iexact=value)
        if self.instance is not None:
            existing = existing.exclude(pk=self.instance.pk)
        if existing.exists():
            raise ValidationError("An account with this email already exists.")
        return value

    def validate(self, attrs):
        attrs = super(EntitySerializer, self).validate(attrs)
        if "confirm_password" in attrs or "password" in attrs:
            confirm_password = attrs.get("confirm_password", None)
            password = attrs.get("password", None)
            if password != confirm_password:
                raise ValidationError("Passwords do not match.")
            if self.instance:
                password_validation.validate_password(password, self.instance)
        return attrs

    def create(self, validated_data):
        password = validated_data.pop("password", None)
        validated_data.pop("confirm_password", None)
        instance = super().create(validated_data)
        if password is not None:
            instance.set_password(password)
            instance.save()
        return instance

    def update(self, instance, validated_data):
        validated_data.pop("confirm_password", None)
        password = validated_data.pop("password", None)
        if password is not None:
            instance.set_password(password)
        return super(EntitySerializer, self).update(instance, validated_data)


class EntityMeSerializer(EntitySerializer):
    """
    Serializer for the user data endpoint. Currently logged in user.

    Allows for updating:
        - First name
        - Last name
        - Email (needs current_password; the new address starts unverified)
        - Password (needs current_password)
    """

    current_password = serializers.CharField(write_only=True, required=False)

    class Meta(EntitySerializer.Meta):
        fields = (
            "uuid",
            "first_name",
            "last_name",
            "email",
            "email_verified",
            "entity_type",
            "password",
            "confirm_password",
            "current_password",
            "is_active",
            "is_system_entity",
            "organizations",
        )
        read_only_fields = (
            "uuid",
            "email_verified",
            "entity_type",
            "is_active",
            "is_system_entity",
        )

    def validate(self, attrs):
        attrs = super().validate(attrs)
        current_password = attrs.pop("current_password", None)
        email_changed = "email" in attrs and attrs["email"] != self.instance.email
        if email_changed or "password" in attrs:
            if not current_password or not self.instance.check_password(
                current_password
            ):
                raise ValidationError(
                    {"current_password": "Your current password is required."}
                )
        return attrs

    def update(self, instance, validated_data):
        email_changed = (
            "email" in validated_data and validated_data["email"] != instance.email
        )
        if email_changed:
            instance.email_verified = False
        instance = super().update(instance, validated_data)
        request = self.context.get("request")
        if email_changed and request is not None:
            from modules.entities.verification import send_verification_email

            send_verification_email(request, instance)
        return instance
