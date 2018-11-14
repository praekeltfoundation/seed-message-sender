0.10.5
------
 - Only call Whatsapp contact check when necessary
 - Use secure comparison for hmac signature

0.10.4
------
 - Increase inbound message content limit to 4096

0.10.3
------
 - Downgrade to ptyhon 3.6, celery doesn't support 3.7

0.10.2
------
 - Fix celery config from django settings, ensure that namespace is CELERY

0.10.1
------
 - Fix celery env var regression: CELERY_BROKER_URL -> BROKER_URL

0.10.0
------
 - Upgrade to Django 2.1
 - Upgrade all dependancies
 - Upgrade to python 3.7
 - Add python black automatic formatting for entire codebase
 - Add WhatsApp channel type with outbound, inbound, and event support
