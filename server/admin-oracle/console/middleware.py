from django.http import HttpResponseNotFound


class AuthSurfaceMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
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
        response['Referrer-Policy'] = 'no-referrer'
        response['X-Content-Type-Options'] = 'nosniff'
        response['X-Frame-Options'] = 'DENY'
        response['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
        response['Content-Security-Policy'] = (
            "default-src 'none'; script-src 'self'; style-src 'self'; "
            "img-src 'self' data:; connect-src 'self'; font-src 'self'; "
            # Chromium also checks the redirect following the local OAuth POST.
            "base-uri 'none'; frame-ancestors 'none'; form-action 'self' https://github.com")
        return response
