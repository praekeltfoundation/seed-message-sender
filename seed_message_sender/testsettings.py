from seed_message_sender.settings import *  # flake8: noqa

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'TESTSEKRET'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

TEMPLATE_DEBUG = True

CELERY_EAGER_PROPAGATES_EXCEPTIONS = True
CELERY_ALWAYS_EAGER = True
BROKER_BACKEND = 'memory'
CELERY_RESULT_BACKEND = 'djcelery.backends.database:DatabaseBackend'

METRICS_URL = "http://metrics-url"
METRICS_AUTH_TOKEN = "REPLACEME"

PASSWORD_HASHERS = ('django.contrib.auth.hashers.MD5PasswordHasher',)
