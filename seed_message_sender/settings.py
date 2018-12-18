"""
Django settings for seed_message_sender project.

For more information on this file, see
https://docs.djangoproject.com/en/1.9/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/1.9/ref/settings/
"""

import os

import dj_database_url

from kombu import Exchange, Queue
from getenv import env

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
BASE_DIR = os.path.dirname(os.path.dirname(__file__))

# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/1.9/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = env("SECRET_KEY", "REPLACEME")

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = env("DEBUG", False)

ALLOWED_HOSTS = ["*"]


# Application definition

INSTALLED_APPS = (
    # admin
    "django.contrib.admin",
    # core
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "django.contrib.sites",
    # 3rd party
    "raven.contrib.django.raven_compat",
    "rest_framework",
    "rest_framework.authtoken",
    "django_filters",
    "rest_hooks",
    "storages",
    "django_prometheus",
    # us
    "message_sender",
)

SITE_ID = 1
USE_SSL = os.environ.get("USE_SSL", "false").lower() == "true"
USE_SSL = env("USE_SSL", False)

MIDDLEWARE = (
    "django_prometheus.middleware.PrometheusBeforeMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "django_prometheus.middleware.PrometheusAfterMiddleware",
)

ROOT_URLCONF = "seed_message_sender.urls"

WSGI_APPLICATION = "seed_message_sender.wsgi.application"


# Database
# https://docs.djangoproject.com/en/1.9/ref/settings/#databases

DATABASES = {
    "default": dj_database_url.config(
        default=env(
            "MESSAGE_SENDER_DATABASE",
            "postgres://postgres:@localhost/seed_message_sender",
        ),
        engine="django_prometheus.db.backends.postgresql",
    )
}

PROMETHEUS_EXPORT_MIGRATIONS = False


# Internationalization
# https://docs.djangoproject.com/en/1.9/topics/i18n/

LANGUAGE_CODE = "en-gb"

TIME_ZONE = "UTC"

USE_I18N = True

USE_L10N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/1.9/howto/static-files/

STATICFILES_FINDERS = (
    "django.contrib.staticfiles.finders.AppDirectoriesFinder",
    "django.contrib.staticfiles.finders.FileSystemFinder",
)

STATIC_ROOT = "static"
STATIC_URL = "/static/"

MEDIA_ROOT = "media"
MEDIA_URL = "/media/"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [os.path.join(BASE_DIR, "templates")],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ]
        },
    }
]

# Sentry configuration
RAVEN_CONFIG = {
    # DevOps will supply you with this.
    "dsn": env("MESSAGE_SENDER_SENTRY_DSN", None)
}

# REST Framework conf defaults
REST_FRAMEWORK = {
    "PAGE_SIZE": 1000,
    "DEFAULT_PAGINATION_CLASS": "rest_framework.pagination.CursorPagination",
    "DEFAULT_AUTHENTICATION_CLASSES": (
        "rest_framework.authentication.BasicAuthentication",
        "rest_framework.authentication.TokenAuthentication",
    ),
    "DEFAULT_PERMISSION_CLASSES": ("rest_framework.permissions.IsAuthenticated",),
    "DEFAULT_FILTER_BACKENDS": ("django_filters.rest_framework.DjangoFilterBackend",),
}

# Webhook event definition
HOOK_EVENTS = {
    # 'any.event.name': 'App.Model.Action' (created/updated/deleted)
    # 'dummymodel.added': 'message_sender.DummyModel.created+'
    "outbound.delivery_report": None,
    "whatsapp.failed_contact_check": None,
}

HOOK_DELIVERER = "message_sender.tasks.deliver_hook_wrapper"

HOOK_AUTH_TOKEN = env("HOOK_AUTH_TOKEN", "REPLACEME")

CELERY_BROKER_URL = env("BROKER_URL", "redis://localhost:6379/0")

CELERY_TASK_DEFAULT_QUEUE = "seed_message_sender"
CELERY_TASK_QUEUES = (
    Queue(
        "seed_message_sender",
        Exchange("seed_message_sender"),
        routing_key="seed_message_sender",
    ),
)

CELERY_TASK_ALWAYS_EAGER = False

# Tell Celery where to find the tasks
CELERY_IMPORTS = ("message_sender.tasks",)

CELERY_TASK_CREATE_MISSING_QUEUES = True
CELERY_TASK_ROUTES = {
    "celery.backend_cleanup": {"queue": "mediumpriority"},
    "message_sender.tasks.deliver_hook_wrapper": {"queue": "priority"},
    "message_sender.tasks.send_message": {"queue": "lowpriority"},
    "message_sender.tasks.fire_metric": {"queue": "metrics"},
    "message_sender.tasks.requeue_failed_tasks": {"queue": "mediumpriority"},
}

METRICS_REALTIME = [
    "vumimessage.tries.sum",
    "vumimessage.maxretries.sum",
    "vumimessage.obd.tries.sum",
    "message.failures.sum",
    "message.sent.sum",
    "sender.send_message.connection_error.sum",
    "sender.send_message.http_error.400.sum",
    "sender.send_message.http_error.401.sum",
    "sender.send_message.http_error.403.sum",
    "sender.send_message.http_error.404.sum",
    "sender.send_message.http_error.500.sum",
    "sender.send_message.timeout.sum",
]
METRICS_SCHEDULED = []
METRICS_SCHEDULED_TASKS = []

CELERY_TASK_SERIALIZER = "json"
CELERY_RESULT_SERIALIZER = "json"
CELERY_ACCEPT_CONTENT = ["json"]
CELERY_TASK_IGNORE_RESULT = True
CELERY_WORKER_MAX_TASKS_PER_CHILD = 50

MESSAGE_BACKEND_VOICE = env("MESSAGE_SENDER_MESSAGE_BACKEND_VOICE", "vumi")
MESSAGE_BACKEND_TEXT = env("MESSAGE_SENDER_MESSAGE_BACKEND_TEXT", "vumi")

VUMI_API_URL_VOICE = env(
    "MESSAGE_SENDER_VUMI_API_URL_VOICE",
    "http://example.com/api/v1/go/http_api_nostream",
)
VUMI_ACCOUNT_KEY_VOICE = env("MESSAGE_SENDER_VUMI_ACCOUNT_KEY_VOICE", "acc-key")
VUMI_CONVERSATION_KEY_VOICE = env(
    "MESSAGE_SENDER_VUMI_CONVERSATION_KEY_VOICE", "conv-key"
)
VUMI_ACCOUNT_TOKEN_VOICE = env("MESSAGE_SENDER_VUMI_ACCOUNT_TOKEN_VOICE", "conv-token")

VOICE_TO_ADDR_FORMATTER = env(
    "VOICE_TO_ADDR_FORMATTER", "message_sender.formatters.noop"
)
TEXT_TO_ADDR_FORMATTER = env("TEXT_TO_ADDR_FORMATTER", "message_sender.formatters.noop")

VUMI_API_URL_TEXT = env(
    "MESSAGE_SENDER_VUMI_API_URL_TEXT", "http://example.com/api/v1/go/http_api_nostream"
)
VUMI_ACCOUNT_KEY_TEXT = env("MESSAGE_SENDER_VUMI_ACCOUNT_KEY_TEXT", "acc-key")
VUMI_CONVERSATION_KEY_TEXT = env(
    "MESSAGE_SENDER_VUMI_CONVERSATION_KEY_TEXT", "conv-key"
)
VUMI_ACCOUNT_TOKEN_TEXT = env("MESSAGE_SENDER_VUMI_ACCOUNT_TOKEN_TEXT", "conv-token")

JUNEBUG_API_URL_VOICE = env(
    "MESSAGE_SENDER_JUNEBUG_API_URL_VOICE",
    "http://example.com/jb/channels/abc-def/messages",
)
JUNEBUG_API_AUTH_VOICE = env("MESSAGE_SENDER_JUNEBUG_API_AUTH_VOICE", None)
JUNEBUG_API_FROM_VOICE = env("MESSAGE_SENDER_JUNEBUG_API_FROM_VOICE", None)

JUNEBUG_API_URL_TEXT = env(
    "MESSAGE_SENDER_JUNEBUG_API_URL_TEXT",
    "http://example.com/jb/channels/def-abc/messages",
)
JUNEBUG_API_AUTH_TEXT = env("MESSAGE_SENDER_JUNEBUG_API_AUTH_TEXT", None)
JUNEBUG_API_FROM_TEXT = env("MESSAGE_SENDER_JUNEBUG_API_FROM_TEXT", None)

MESSAGE_SENDER_MAX_RETRIES = env("MESSAGE_SENDER_MAX_RETRIES", 3)
MESSAGE_SENDER_MAX_FAILURES = env("MESSAGE_SENDER_MAX_FAILURES", 5)

METRICS_URL = env("METRICS_URL", None)
METRICS_AUTH = (
    env("METRICS_AUTH_USER", "REPLACEME"),
    env("METRICS_AUTH_PASSWORD", "REPLACEME"),
)

REDIS_HOST = env("REDIS_HOST", "localhost")
REDIS_PORT = env("REDIS_PORT", 6379)
REDIS_DB = env("REDIS_DB", 0)

# A value of 0 disables cuncurrency limiter
CONCURRENT_VOICE_LIMIT = env("CONCURRENT_VOICE_LIMIT", 0)
# Seconds to wait before retrying a waiting message
VOICE_MESSAGE_DELAY = env("VOICE_MESSAGE_DELAY", 0)
# Seconds until we assume a message has finished
VOICE_MESSAGE_TIMEOUT = env("VOICE_MESSAGE_TIMEOUT", 0)
# A value of 0 disables cuncurrency limiter
CONCURRENT_TEXT_LIMIT = env("CONCURRENT_TEXT_LIMIT", 0)
# Seconds to wait before retrying a waiting message
TEXT_MESSAGE_DELAY = env("TEXT_MESSAGE_DELAY", 0)
# Seconds until we assume a message has finished
TEXT_MESSAGE_TIMEOUT = env("TEXT_MESSAGE_TIMEOUT", 0)

CACHES = {
    "default": {
        "BACKEND": "django_prometheus.cache.backends.redis.RedisCache",
        "LOCATION": ["%s:%s" % (REDIS_HOST, REDIS_PORT)],
        "OPTIONS": {"DB": REDIS_DB},
    }
}
REDIS_PASSWORD = env("REDIS_PASSWORD", None)
if REDIS_PASSWORD:
    CACHES["default"]["OPTIONS"]["PASSWORD"] = REDIS_PASSWORD

DEFAULT_REQUEST_TIMEOUT = env("DEFAULT_REQUEST_TIMEOUT", 30)

IDENTITY_STORE_URL = env("IDENTITY_STORE_URL", "http://is/api/v1")
IDENTITY_STORE_TOKEN = env("IDENTITY_STORE_TOKEN", "REPLACEME")

AGGREGATE_OUTBOUND_BACKTRACK = env("AGGREGATE_OUTBOUND_BACKTRACK", 30)


AWS_ACCESS_KEY_ID = env("AWS_ACCESS_KEY_ID", None)
AWS_SECRET_ACCESS_KEY = env("AWS_SECRET_ACCESS_KEY", None)
AWS_STORAGE_BUCKET_NAME = env("AWS_STORAGE_BUCKET_NAME", None)
AWS_S3_ENCRYPTION = True

if AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY and AWS_STORAGE_BUCKET_NAME:
    DEFAULT_FILE_STORAGE = "storages.backends.s3boto3.S3Boto3Storage"
