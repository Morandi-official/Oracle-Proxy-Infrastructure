"""Read-only public HTTPS acceptance. No credentials, TLS bypass, or login sessions."""
import urllib.error
import urllib.request

BASE = 'https://vpn-admin.morandi.dpdns.org'


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl): return None


def main():
    opener = urllib.request.build_opener(NoRedirect)
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
            if path in ('/login/', '/accounts/login/'):
                body = response.read(65536)
                assert b'github/login/' in body
                assert b'type="password"' not in body
        print(f'PUBLIC_CHECK={path} HTTP_{expected}_PASS')
    print('PUBLIC_HTTPS_AND_UNAUTHENTICATED_BOUNDARIES=PASS')


if __name__ == '__main__': main()
