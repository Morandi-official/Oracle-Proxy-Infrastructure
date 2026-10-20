"""Read-only public HTTPS acceptance. No credentials, TLS bypass, or login sessions."""
import urllib.error
import urllib.parse
import urllib.request
import http.cookiejar
import re

BASE = 'https://vpn-admin.morandi.dpdns.org'


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl): return None


def main():
    opener = urllib.request.build_opener(NoRedirect, urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    csrf = None
    for path, expected in (('/login/', 200), ('/static/console/style.css', 200),
                           ('/static/console/app.js', 200), ('/style.css', 401), ('/app.js', 401),
                           ('/', 302), ('/api/status', 401), ('/api/audit', 401),
                           ('/api/health', 404), ('/accounts/login/', 200),
                           ('/accounts/password/reset/', 404), ('/accounts/password/set/', 404),
                           ('/accounts/signup/', 404)):
        try:
            response = opener.open(BASE + path, timeout=10)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            if response.code != expected:
                raise ValueError(f'PUBLIC_CHECK_FAILED {path} expected={expected} actual={response.code}')
            if path == '/login/':
                assert response.headers.get('Strict-Transport-Security')
                assert response.headers.get('X-Frame-Options') == 'DENY'
                assert response.headers.get('X-Content-Type-Options') == 'nosniff'
                assert response.headers.get('Referrer-Policy') == 'same-origin'
                assert "form-action 'self' https://github.com" in response.headers.get('Content-Security-Policy', '')
            if path in ('/login/', '/accounts/login/'):
                body = response.read(65536)
                assert b'github/login/' in body
                assert b'type="password"' not in body
                csrf = re.search(rb'name="csrfmiddlewaretoken" value="([^"]+)"', body).group(1).decode()
        print(f'PUBLIC_CHECK={path} HTTP_{expected}_PASS')
    request = urllib.request.Request(BASE + '/accounts/github/login/',
        data=urllib.parse.urlencode({'csrfmiddlewaretoken': csrf}).encode(),
        # Exercise Django's HTTPS Referer fallback rather than always supplying Origin.
        headers={'Referer': BASE + '/login/'})
    try: response = opener.open(request, timeout=10)
    except urllib.error.HTTPError as error: response = error
    with response:
        assert response.code == 302
        target = urllib.parse.urlsplit(response.headers['Location'])
        values = urllib.parse.parse_qs(target.query)
        assert (target.scheme, target.netloc, target.path) == ('https', 'github.com', '/login/oauth/authorize')
        assert values['client_id'] == ['Ov23liYD7HIQdS5nDjpS']
        assert values['redirect_uri'] == [BASE + '/accounts/github/login/callback/']
        assert values['code_challenge_method'] == ['S256'] and values['code_challenge'] and values['state']
    print('PUBLIC_GITHUB_OAUTH_INITIATION_CSRF_CALLBACK_AND_PKCE=PASS')
    print('PUBLIC_HTTPS_AND_UNAUTHENTICATED_BOUNDARIES=PASS')


if __name__ == '__main__': main()
