import os
from pathlib import Path

from cryptography.fernet import Fernet
from django.core.exceptions import ImproperlyConfigured

BASE_DIR = Path(__file__).resolve().parent.parent


def required(name, minimum=1):
    value = os.environ.get(name, '')
    if len(value) < minimum:
        raise ImproperlyConfigured(f'{name} is required')
    return value


SECRET_KEY = required('ADMIN_SECRET_KEY', 50)
MFA_ENCRYPTION_KEY = required('ADMIN_MFA_ENCRYPTION_KEY')
try:
    Fernet(MFA_ENCRYPTION_KEY.encode())
except (ValueError, TypeError):
    raise ImproperlyConfigured('ADMIN_MFA_ENCRYPTION_KEY must be a Fernet key') from None
DEBUG = False
ADMIN_HOST = os.environ.get('ADMIN_HOST', 'vpn-admin.morandi.dpdns.org')
import re
if not re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?', ADMIN_HOST):
    raise ImproperlyConfigured('Invalid ADMIN_HOST')
ALLOWED_HOSTS = [ADMIN_HOST]
CSRF_TRUSTED_ORIGINS = [f'https://{ADMIN_HOST}']
ADMIN_GITHUB_IDS = frozenset(os.environ.get('ADMIN_GITHUB_IDS', '204281968').split(','))
if not ADMIN_GITHUB_IDS or any(not uid.isdigit() for uid in ADMIN_GITHUB_IDS):
    raise ImproperlyConfigured('Explicit numeric GitHub user IDs are required')
NODE_ID = 'oracle-primary'
SOURCE_REVISION = os.environ.get('ADMIN_SOURCE_REVISION', 'unversioned')
STATE_DIR = Path(os.environ.get('ADMIN_STATE_DIR', '/var/lib/oracle-proxy-admin'))
DATABASES = {'default': {'ENGINE': 'django.db.backends.sqlite3',
                         'NAME': STATE_DIR / 'admin.sqlite3', 'OPTIONS': {'timeout': 15}}}
CACHES = {'default': {'BACKEND': 'django.core.cache.backends.db.DatabaseCache',
                       'LOCATION': 'console_ratelimit'}}
INSTALLED_APPS = [
    'django.contrib.auth', 'django.contrib.contenttypes', 'django.contrib.sessions',
    'django.contrib.messages', 'django.contrib.staticfiles',
    'allauth', 'allauth.account', 'allauth.socialaccount',
    'allauth.socialaccount.providers.github', 'allauth.mfa', 'console.apps.ConsoleConfig',
]
MIDDLEWARE = [
    'console.middleware.SecurityHeadersMiddleware',
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'allauth.account.middleware.AccountMiddleware',
    'console.middleware.AuthSurfaceMiddleware',
]
ROOT_URLCONF = 'config.urls'
WSGI_APPLICATION = 'config.wsgi.application'
TEMPLATES = [{'BACKEND': 'django.template.backends.django.DjangoTemplates',
              'DIRS': [BASE_DIR / 'templates'], 'APP_DIRS': True,
              'OPTIONS': {'context_processors': [
                  'django.template.context_processors.request',
                  'django.contrib.auth.context_processors.auth',
                  'django.contrib.messages.context_processors.messages']}}]
AUTHENTICATION_BACKENDS = ['console.adapters.GitHubSessionBackend']
SOCIALACCOUNT_ADAPTER = 'console.adapters.GitHubAllowlistAdapter'
ACCOUNT_ADAPTER = 'console.adapters.ClosedAccountAdapter'
SOCIALACCOUNT_AUTO_SIGNUP = True
SOCIALACCOUNT_QUERY_EMAIL = False
SOCIALACCOUNT_EMAIL_AUTHENTICATION = False
SOCIALACCOUNT_STORE_TOKENS = False
SOCIALACCOUNT_LOGIN_ON_GET = False
SOCIALACCOUNT_PROVIDERS = {'github': {
    'APP': {'client_id': required('ADMIN_GITHUB_CLIENT_ID'),
            'secret': required('ADMIN_GITHUB_CLIENT_SECRET'), 'key': ''},
    'SCOPE': ['read:user'], 'OAUTH_PKCE_ENABLED': True,
}}
SOCIALACCOUNT_REQUESTS_TIMEOUT = 10
ACCOUNT_SIGNUP_FIELDS = ['username*']
ACCOUNT_EMAIL_VERIFICATION = 'none'
ACCOUNT_LOGIN_METHODS = {'username'}
ACCOUNT_SESSION_REMEMBER = False
ACCOUNT_LOGIN_BY_CODE_ENABLED = False
ACCOUNT_EMAIL_NOTIFICATIONS = False
ACCOUNT_REAUTHENTICATION_TIMEOUT = 300
LOGIN_URL = '/login/'
LOGIN_REDIRECT_URL = '/'
ACCOUNT_LOGOUT_REDIRECT_URL = '/login/'
MFA_ADAPTER = 'console.adapters.EncryptedMFAAdapter'
MFA_SUPPORTED_TYPES = ['totp', 'recovery_codes']
MFA_TRUST_ENABLED = False
MFA_ALLOW_UNVERIFIED_EMAIL = True  # Authorization uses verified GitHub numeric ID, never email.
MFA_TOTP_ISSUER = 'Oracle Proxy Admin'
SESSION_ENGINE = 'django.contrib.sessions.backends.db'
SESSION_COOKIE_NAME = '__Host-oracle_admin'
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Lax'
SESSION_COOKIE_AGE = 3600
SESSION_EXPIRE_AT_BROWSER_CLOSE = True
CSRF_COOKIE_NAME = '__Host-oracle_csrf'
CSRF_COOKIE_SECURE = True
CSRF_COOKIE_HTTPONLY = True
CSRF_COOKIE_SAMESITE = 'Lax'
SECURE_SSL_REDIRECT = True
# Only Caddy on the loopback interface may reach Gunicorn and supply this header.
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = 'DENY'
DATA_UPLOAD_MAX_MEMORY_SIZE = 16384
DATA_UPLOAD_MAX_NUMBER_FIELDS = 30
FILE_UPLOAD_MAX_MEMORY_SIZE = 0
STATIC_URL = '/static/'
STATIC_ROOT = BASE_DIR / 'staticfiles'
STATICFILES_DIRS = [BASE_DIR / 'static']
STORAGES = {'staticfiles': {'BACKEND': 'whitenoise.storage.CompressedManifestStaticFilesStorage'}}
LANGUAGE_CODE = 'zh-hans'
TIME_ZONE = 'Asia/Shanghai'
USE_TZ = True
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'
# Do not send secrets, callback codes, MFA QR contents or tokens to email/log output.
EMAIL_BACKEND = 'django.core.mail.backends.dummy.EmailBackend'
LOGGING = {'version': 1, 'disable_existing_loggers': False,
           'handlers': {'console': {'class': 'logging.StreamHandler'}},
           'loggers': {'django.request': {'handlers': ['console'], 'level': 'ERROR', 'propagate': False}}}
