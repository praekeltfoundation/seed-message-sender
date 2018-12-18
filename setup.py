import codecs
import os
import re

from setuptools import setup, find_packages


HERE = os.path.abspath(os.path.dirname(__file__))


def read(*parts):  # Stolen from txacme
    with codecs.open(os.path.join(HERE, *parts), "rb", "utf-8") as f:
        return f.read()


def get_version(package):
    """
    Return package version as listed in `__version__` in `init.py`.
    """
    init_py = open(os.path.join(package, "__init__.py")).read()
    return re.search("__version__ = ['\"]([^'\"]+)['\"]", init_py).group(1)


version = get_version("seed_message_sender")


setup(
    name="seed-message-sender",
    version=version,
    url="http://github.com/praekelt/seed-message-sender",
    license="BSD",
    description="Seed Message Sender mircoservice",
    long_description=read("README.rst"),
    author="Praekelt.org",
    author_email="dev@praekelt.org",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        "Django==2.1.2",
        "djangorestframework==3.8.2",
        "dj-database-url==0.5.0",
        "psycopg2==2.7.5",
        "raven==6.9.0",
        "django-filter==2.0.0",
        "celery==4.2.1",
        "pytz==2018.5",
        "django-rest-hooks==1.5.0",
        "go_http==0.3.2",
        "django-redis==4.10.0",
        "seed-services-client==0.37.0",
        "django-getenv==1.3.2",
        "django-storages==1.7.1",
        "boto3==1.9.4",
        "coreapi==2.3.3",
        "phonenumberslite==8.9.14",
        "django_prometheus==1.0.15",
    ],
    classifiers=[
        "Development Status :: 4 - Beta",
        "Framework :: Django",
        "License :: OSI Approved :: BSD License",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3.6",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
)
