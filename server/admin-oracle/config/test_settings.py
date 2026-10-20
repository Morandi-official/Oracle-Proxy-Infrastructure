import os
import tempfile

os.environ.setdefault('ADMIN_SECRET_KEY', 'synthetic-unit-test-key-not-for-deployment-' * 2)
os.environ.setdefault('ADMIN_MFA_ENCRYPTION_KEY', 'MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA=')
os.environ.setdefault('ADMIN_GITHUB_CLIENT_ID', 'synthetic-test-client')
os.environ.setdefault('ADMIN_GITHUB_CLIENT_SECRET', 'synthetic-test-secret')
os.environ.setdefault('ADMIN_STATE_DIR', tempfile.mkdtemp(prefix='oracle-admin-test-'))

from .settings import *  # noqa: E402,F403

DATABASES = {'default': {'ENGINE': 'django.db.backends.sqlite3', 'NAME': ':memory:'}}
PASSWORD_HASHERS = ['django.contrib.auth.hashers.MD5PasswordHasher']
STORAGES = {'staticfiles': {'BACKEND': 'django.contrib.staticfiles.storage.StaticFilesStorage'}}
