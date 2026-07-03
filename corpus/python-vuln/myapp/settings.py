"""Django settings (corpus: python-vuln) — INTENTIONALLY INSECURE. DO NOT DEPLOY."""
import os

# A07:2021 — hard-coded secret. Should be os.environ["DJANGO_SECRET_KEY"].
SECRET_KEY = "django-insecure-hardcoded-abc123def456ghi789jkl"

# A05:2021 — debug + wildcard hosts left on in "production".
DEBUG = True
ALLOWED_HOSTS = ["*"]

INSTALLED_APPS = ["myapp"]

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": "app",
        "HOST": os.environ.get("DB_HOST", "localhost"),
    }
}
