from seed_message_sender.settings import *  # flake8: noqa

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = "TESTSEKRET"

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

TEMPLATE_DEBUG = True

CELERY_TASK_EAGER_PROPAGATES = True
CELERY_TASK_ALWAYS_EAGER = True

METRICS_URL = "http://metrics-url"
METRICS_AUTH_TOKEN = "REPLACEME"

PASSWORD_HASHERS = ("django.contrib.auth.hashers.MD5PasswordHasher",)

# REST Framework conf defaults
REST_FRAMEWORK["PAGE_SIZE"] = 2
