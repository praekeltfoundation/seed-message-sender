from .celery import app as celery_app

__version__ = "0.10.11"
VERSION = __version__
__all__ = ("celery_app",)
