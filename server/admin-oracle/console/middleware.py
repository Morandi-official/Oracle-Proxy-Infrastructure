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
        response['Referrer-Policy'] = 'same-origin'
        response['X-Content-Type-Options'] = 'nosniff'
        response['X-Frame-Options'] = 'DENY'
        response['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
        response['Content-Security-Policy'] = (
            "default-src 'none'; script-src 'self'; style-src 'self'; "
            "img-src 'self' data:; connect-src 'self'; font-src 'self'; "
            # Chromium also checks the redirect following the local OAuth POST.
            "base-uri 'none'; frame-ancestors 'none'; form-action 'self' https://github.com")
        return response
