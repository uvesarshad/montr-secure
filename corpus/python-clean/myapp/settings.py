"""Django settings (corpus: python-clean) — secured counterpart."""
import os

# A07:2021 fixed — secret read from the environment, never hard-coded.
SECRET_KEY = os.environ["DJANGO_SECRET_KEY"]

# A05:2021 fixed — debug off, explicit host allow-list.
DEBUG = False
ALLOWED_HOSTS = ["app.example.com"]

INSTALLED_APPS = ["myapp"]

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": os.environ.get("DB_NAME", "app"),
        "HOST": os.environ.get("DB_HOST", "localhost"),
    }
}
