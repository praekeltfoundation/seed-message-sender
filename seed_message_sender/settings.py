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
import djcelery

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
BASE_DIR = os.path.dirname(os.path.dirname(__file__))

# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/1.9/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = os.environ.get('SECRET_KEY', 'REPLACEME')

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = os.environ.get('DEBUG', False)

ALLOWED_HOSTS = ['*']


# Application definition

INSTALLED_APPS = (
    # admin
    'django.contrib.admin',
    # core
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'django.contrib.sites',
    # documentation
    'rest_framework_docs',
    # 3rd party
    'raven.contrib.django.raven_compat',
    'rest_framework',
    'rest_framework.authtoken',
    'django_filters',
    'rest_hooks',
    'djcelery',
    # us
    'message_sender',

)

SITE_ID = 1
USE_SSL = os.environ.get('USE_SSL', 'false').lower() == 'true'

MIDDLEWARE_CLASSES = (
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.auth.middleware.SessionAuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
)

ROOT_URLCONF = 'seed_message_sender.urls'

WSGI_APPLICATION = 'seed_message_sender.wsgi.application'


# Database
# https://docs.djangoproject.com/en/1.9/ref/settings/#databases

DATABASES = {
    'default': dj_database_url.config(
        default=os.environ.get(
            'MESSAGE_SENDER_DATABASE',
            'postgres://postgres:@localhost/seed_message_sender')),
}


# Internationalization
# https://docs.djangoproject.com/en/1.9/topics/i18n/

LANGUAGE_CODE = 'en-gb'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_L10N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/1.9/howto/static-files/

STATICFILES_FINDERS = (
    'django.contrib.staticfiles.finders.AppDirectoriesFinder',
    'django.contrib.staticfiles.finders.FileSystemFinder',
)

STATIC_ROOT = 'static'
STATIC_URL = '/static/'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [
            os.path.join(BASE_DIR, 'templates')
        ],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

PAPERTRAIL = os.environ.get('PAPERTRAIL')
if PAPERTRAIL:
    import seed_papertrail  # noqa
    PAPERTRAIL_HOST, _, PAPERTRAIL_PORT = PAPERTRAIL.partition(':')
    LOGGING = seed_papertrail.auto_configure(
        host=PAPERTRAIL_HOST,
        port=int(PAPERTRAIL_PORT),
        system=os.environ.get('MARATHON_APP_DOCKER_IMAGE', 'seed'),
        program=os.environ.get('MESOS_TASK_ID', 'message_sender'))
    LOGGING['loggers']['celery.app'] = {
        'handlers': ['papertrail'],
        'level': 'DEBUG',
        'propagate': True,
    }


# Sentry configuration
RAVEN_CONFIG = {
    # DevOps will supply you with this.
    'dsn': os.environ.get('MESSAGE_SENDER_SENTRY_DSN', None),
}

# REST Framework conf defaults
REST_FRAMEWORK = {
    'PAGE_SIZE': 1000,
    'DEFAULT_PAGINATION_CLASS':
        'rest_framework.pagination.LimitOffsetPagination',
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'rest_framework.authentication.BasicAuthentication',
        'rest_framework.authentication.TokenAuthentication',
    ),
    'DEFAULT_PERMISSION_CLASSES': (
        'rest_framework.permissions.IsAuthenticated',
    ),
    'DEFAULT_FILTER_BACKENDS': ('rest_framework.filters.DjangoFilterBackend',)
}

# Webhook event definition
HOOK_EVENTS = {
    # 'any.event.name': 'App.Model.Action' (created/updated/deleted)
    # 'dummymodel.added': 'message_sender.DummyModel.created+'
    'outbound.delivery_report': None,
}

HOOK_DELIVERER = 'message_sender.tasks.deliver_hook_wrapper'

HOOK_AUTH_TOKEN = os.environ.get('HOOK_AUTH_TOKEN', 'REPLACEME')

# Celery configuration options
CELERY_RESULT_BACKEND = 'djcelery.backends.database:DatabaseBackend'
CELERYBEAT_SCHEDULER = 'djcelery.schedulers.DatabaseScheduler'

BROKER_URL = os.environ.get('BROKER_URL', 'redis://localhost:6379/0')

CELERY_DEFAULT_QUEUE = 'seed_message_sender'
CELERY_QUEUES = (
    Queue('seed_message_sender',
          Exchange('seed_message_sender'),
          routing_key='seed_message_sender'),
)

CELERY_ALWAYS_EAGER = False

# Tell Celery where to find the tasks
CELERY_IMPORTS = (
    'message_sender.tasks',
)

CELERY_CREATE_MISSING_QUEUES = True
CELERY_ROUTES = {
    'celery.backend_cleanup': {
        'queue': 'mediumpriority',
    },
    'message_sender.tasks.deliver_hook_wrapper': {
        'queue': 'priority',
    },
    'message_sender.tasks.send_message': {
        'queue': 'lowpriority',
    },
    'message_sender.tasks.fire_metric': {
        'queue': 'metrics',
    },
    'message_sender.tasks.requeue_failed_tasks': {
        'queue': 'mediumpriority',
    },
}

METRICS_REALTIME = [
    'inbounds.created.sum',
    'vumimessage.tries.sum',
    'vumimessage.maxretries.sum',
    'vumimessage.obd.tries.sum',
    'vumimessage.obd.successful.sum',
    'vumimessage.obd.unsuccessful.sum',
    'message.failures.sum',
    'message.sent.sum',
    'sender.send_message.connection_error.sum',
    'sender.send_message.http_error.400.sum',
    'sender.send_message.http_error.401.sum',
    'sender.send_message.http_error.403.sum',
    'sender.send_message.http_error.404.sum',
    'sender.send_message.http_error.500.sum',
    'sender.send_message.timeout.sum',
]
METRICS_SCHEDULED = [
]
METRICS_SCHEDULED_TASKS = [
]

CELERY_TASK_SERIALIZER = 'json'
CELERY_RESULT_SERIALIZER = 'json'
CELERY_ACCEPT_CONTENT = ['json']
CELERY_IGNORE_RESULT = True
CELERYD_MAX_TASKS_PER_CHILD = 50

djcelery.setup_loader()

MESSAGE_BACKEND_VOICE = os.environ.get(
    'MESSAGE_SENDER_MESSAGE_BACKEND_VOICE', 'vumi')
MESSAGE_BACKEND_TEXT = os.environ.get(
    'MESSAGE_SENDER_MESSAGE_BACKEND_TEXT', 'vumi')

VUMI_API_URL_VOICE = \
    os.environ.get('MESSAGE_SENDER_VUMI_API_URL_VOICE',
                   'http://example.com/api/v1/go/http_api_nostream')
VUMI_ACCOUNT_KEY_VOICE = \
    os.environ.get('MESSAGE_SENDER_VUMI_ACCOUNT_KEY_VOICE', 'acc-key')
VUMI_CONVERSATION_KEY_VOICE = \
    os.environ.get('MESSAGE_SENDER_VUMI_CONVERSATION_KEY_VOICE', 'conv-key')
VUMI_ACCOUNT_TOKEN_VOICE = \
    os.environ.get('MESSAGE_SENDER_VUMI_ACCOUNT_TOKEN_VOICE', 'conv-token')

VOICE_TO_ADDR_FORMATTER = os.environ.get(
    'VOICE_TO_ADDR_FORMATTER', 'message_sender.formatters.noop')
TEXT_TO_ADDR_FORMATTER = os.environ.get(
    'TEXT_TO_ADDR_FORMATTER', 'message_sender.formatters.noop')

VUMI_API_URL_TEXT = \
    os.environ.get('MESSAGE_SENDER_VUMI_API_URL_TEXT',
                   'http://example.com/api/v1/go/http_api_nostream')
VUMI_ACCOUNT_KEY_TEXT = \
    os.environ.get('MESSAGE_SENDER_VUMI_ACCOUNT_KEY_TEXT', 'acc-key')
VUMI_CONVERSATION_KEY_TEXT = \
    os.environ.get('MESSAGE_SENDER_VUMI_CONVERSATION_KEY_TEXT', 'conv-key')
VUMI_ACCOUNT_TOKEN_TEXT = \
    os.environ.get('MESSAGE_SENDER_VUMI_ACCOUNT_TOKEN_TEXT', 'conv-token')

JUNEBUG_API_URL_VOICE = \
    os.environ.get('MESSAGE_SENDER_JUNEBUG_API_URL_VOICE',
                   'http://example.com/jb/channels/abc-def/messages')
JUNEBUG_API_AUTH_VOICE = \
    os.environ.get('MESSAGE_SENDER_JUNEBUG_API_AUTH_VOICE', None)
JUNEBUG_API_FROM_VOICE = \
    os.environ.get('MESSAGE_SENDER_JUNEBUG_API_FROM_VOICE', None)

JUNEBUG_API_URL_TEXT = \
    os.environ.get('MESSAGE_SENDER_JUNEBUG_API_URL_TEXT',
                   'http://example.com/jb/channels/def-abc/messages')
JUNEBUG_API_AUTH_TEXT = \
    os.environ.get('MESSAGE_SENDER_JUNEBUG_API_AUTH_TEXT', None)
JUNEBUG_API_FROM_TEXT = \
    os.environ.get('MESSAGE_SENDER_JUNEBUG_API_FROM_TEXT', None)

MESSAGE_SENDER_MAX_RETRIES = \
    int(os.environ.get('MESSAGE_SENDER_MAX_RETRIES', 3))
MESSAGE_SENDER_MAX_FAILURES = \
    int(os.environ.get('MESSAGE_SENDER_MAX_FAILURES', 5))

METRICS_URL = os.environ.get("METRICS_URL", None)
METRICS_AUTH_TOKEN = os.environ.get("METRICS_AUTH_TOKEN", "REPLACEME")

REDIS_HOST = os.environ.get("REDIS_HOST", "localhost")
REDIS_PORT = os.environ.get("REDIS_PORT", 6379)
REDIS_DB = os.environ.get("REDIS_DB", 0)

# A value of 0 disables cuncurrency limiter
CONCURRENT_VOICE_LIMIT = os.environ.get("CONCURRENT_VOICE_LIMIT", 0)
# Seconds to wait before retrying a waiting message
VOICE_MESSAGE_DELAY = os.environ.get("VOICE_MESSAGE_DELAY", 0)
# Seconds until we assume a message has finished
VOICE_MESSAGE_TIMEOUT = os.environ.get("VOICE_MESSAGE_TIMEOUT", 0)
# A value of 0 disables cuncurrency limiter
CONCURRENT_TEXT_LIMIT = os.environ.get("CONCURRENT_TEXT_LIMIT", 0)
# Seconds to wait before retrying a waiting message
TEXT_MESSAGE_DELAY = os.environ.get("TEXT_MESSAGE_DELAY", 0)
# Seconds until we assume a message has finished
TEXT_MESSAGE_TIMEOUT = os.environ.get("TEXT_MESSAGE_TIMEOUT", 0)

CACHES = {
    'default': {
        'BACKEND': 'redis_cache.RedisCache',
        'LOCATION': ['%s:%s' % (os.environ.get("REDIS_HOST", "localhost"),
                                os.environ.get("REDIS_PORT", 6379))],
        'OPTIONS': {
            'DB': os.environ.get("REDIS_DB", 0),
        }
    },
}
REDIS_PASSWORD = os.environ.get("REDIS_PASSWORD", None)
if REDIS_PASSWORD:
    CACHES['default']['OPTIONS']['PASSWORD'] = REDIS_PASSWORD

DEFAULT_REQUEST_TIMEOUT = float(os.environ.get("DEFAULT_REQUEST_TIMEOUT", 30))

IDENTITY_STORE_URL = os.environ.get('IDENTITY_STORE_URL',
                                    'http://is/api/v1')
IDENTITY_STORE_TOKEN = os.environ.get('IDENTITY_STORE_TOKEN',
                                      'REPLACEME')
