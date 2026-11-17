from django.apps import AppConfig


class EntitiesConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "modules.entities"

    def ready(self):
        from modules.entities import sessions  # noqa: F401  (signal receivers)
