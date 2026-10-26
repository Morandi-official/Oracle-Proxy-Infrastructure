"""Read-only public HTTPS acceptance. No credentials, TLS bypass, or login sessions."""
import urllib.error
import urllib.parse
import urllib.request
import http.cookiejar
import re
import hashlib
from pathlib import Path

BASE = 'https://vpn-admin.morandi.dpdns.org'


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl): return None


def main():
    opener = urllib.request.build_opener(NoRedirect, urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    csrf = None
    expected=(Path(__file__).resolve().parents[2]/'server/admin-oracle/static/console/privacy.js').read_bytes()
    digest=hashlib.sha256(expected).hexdigest()
    with opener.open(BASE+'/privacy-check.js?verify='+digest,timeout=10) as probe:
        if probe.code!=200 or probe.read(len(expected)+1)!=expected:raise ValueError('PUBLIC_PRIVACY_CLASSIFIER_SOURCE_MISMATCH')
    print('PUBLIC_WEBRTC_CLASSIFIER_EXACT_SOURCE=PASS; SHA256='+digest)
    with opener.open(BASE+'/login/',timeout=10) as probe:
        local_login=b'name="password"' in probe.read(65536)
    for path, expected in (('/login/', 200), ('/static/console/style.css', 200),
                           ('/static/console/app.js', 200), ('/style.css', 401), ('/app.js', 401),
                           ('/', 302), ('/api/status', 401), ('/api/audit', 401), ('/api/control',401),
                           ('/api/health', 404), ('/accounts/login/', 404 if local_login else 200),
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
                assert "form-action 'self'" in response.headers.get('Content-Security-Policy', '')
            if path in ('/login/', '/accounts/login/') and expected==200:
                body = response.read(65536)
                if local_login:
                    assert b'name="username"' in body and b'type="password"' in body and b'github/login/' not in body
                else:
                    assert b'github/login/' in body
                    assert b'type="password"' not in body
                csrf = re.search(rb'name="csrfmiddlewaretoken" value="([^"]+)"', body).group(1).decode()
        print(f'PUBLIC_CHECK={path} HTTP_{expected}_PASS')
    if local_login:
        for path in ('/accounts/github/login/','/accounts/2fa/'):
            try: opener.open(BASE+path,timeout=10)
            except urllib.error.HTTPError as error: assert error.code==404
            else: raise ValueError('EXTERNAL_AUTH_SURFACE_OPEN')
        print('PUBLIC_LOCAL_ADMIN_ONLY_LOGIN_SURFACE=PASS')
        print('PUBLIC_HTTPS_AND_UNAUTHENTICATED_BOUNDARIES=PASS')
        return
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
