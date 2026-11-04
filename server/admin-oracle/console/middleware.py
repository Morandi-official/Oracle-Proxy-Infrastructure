import logging
import re
from django.http import HttpResponseNotFound
from django.conf import settings


class AuthSurfaceMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if settings.ADMIN_AUTH_MODE == 'local' and request.path.startswith('/accounts/'):
            return HttpResponseNotFound()
        if request.path.startswith(('/accounts/password/', '/accounts/signup/',
                                    '/accounts/email/', '/accounts/social/connections/',
                                    '/accounts/login/code/')):
            return HttpResponseNotFound()
        return self.get_response(request)


class SecurityHeadersMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        response['Cache-Control'] = 'no-store'
        # HTTPS CSRF fallback needs Referer when the browser omits Origin.
        # Keep same-origin form submissions verifiable without leaking OAuth URLs externally.
        response.setdefault('Referrer-Policy', 'same-origin')
        response['X-Content-Type-Options'] = 'nosniff'
        response['X-Frame-Options'] = 'DENY'
        response['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
        response['Content-Security-Policy'] = (
            "default-src 'none'; script-src 'self'; style-src 'self'; "
            "img-src 'self' data:; connect-src 'self'; font-src 'self'; "
            # Chromium also checks the redirect following the local OAuth POST.
            "base-uri 'none'; frame-ancestors 'none'; form-action 'self' https://github.com")
        return response


class SecretImportUrlFilter(logging.Filter):
    def filter(self, record):
        def redact(value):
            return re.sub(r"(/api/flclash/import/[a-fA-F0-9-]+/)[A-Za-z0-9_-]+", r"\1[REDACTED]", value) if isinstance(value,str) else value
        record.msg=redact(record.msg)
        if isinstance(record.args,tuple):record.args=tuple(redact(v) for v in record.args)
        elif isinstance(record.args,dict):record.args={k:redact(v) for k,v in record.args.items()}
        return True
