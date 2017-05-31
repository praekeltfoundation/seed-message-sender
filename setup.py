import codecs
import os
import re

from setuptools import setup, find_packages


HERE = os.path.abspath(os.path.dirname(__file__))


def read(*parts):  # Stolen from txacme
    with codecs.open(os.path.join(HERE, *parts), 'rb', 'utf-8') as f:
        return f.read()


def get_version(package):
    """
    Return package version as listed in `__version__` in `init.py`.
    """
    init_py = open(os.path.join(package, '__init__.py')).read()
    return re.search("__version__ = ['\"]([^'\"]+)['\"]", init_py).group(1)


version = get_version('seed_message_sender')


setup(
    name="seed-message-sender",
    version=version,
    url='http://github.com/praekelt/seed-message-sender',
    license='BSD',
    description='Seed Message Sender mircoservice',
    long_description=read('README.rst'),
    author='Praekelt.org',
    author_email='dev@praekelt.org',
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        'Django==1.9.12',
        'djangorestframework==3.3.2',
        'dj-database-url==0.3.0',
        'psycopg2==2.7.1',
        'raven==5.32.0',
        'django-filter==0.12.0',
        'whitenoise==2.0.6',
        'celery==3.1.24',
        'django-celery==3.1.17',
        'redis==2.10.5',
        'pytz==2015.7',
        'django-rest-hooks==1.3.1',
        'go_http==0.3.0',
        'drfdocs==0.0.11',
        'django-redis-cache==1.7.1',
        'seed-papertrail>=1.5.1',
    ],
    classifiers=[
        'Development Status :: 4 - Beta',
        'Framework :: Django',
        'License :: OSI Approved :: BSD License',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.7',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ],
)
