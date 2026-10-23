"""Anonymous browser acceptance only; never authenticate or export browser state."""
from urllib.parse import urlsplit

from playwright.sync_api import sync_playwright, TimeoutError as BrowserTimeout

BASE = 'https://vpn-admin.morandi.dpdns.org'


def main():
    with sync_playwright() as playwright:
        for name in ('chromium', 'firefox'):
            browser = getattr(playwright, name).launch(headless=True)
            context = browser.new_context(service_workers='block')
            page = context.new_page()
            statuses = []
            # Stop at the external authorization navigation. Never log OAuth state/URLs.
            page.route('https://github.com/**', lambda route: route.fulfill(
                status=200, content_type='text/html', body='<p>OAuth navigation verified</p>'))
            page.on('response', lambda response: statuses.append(response.status)
                    if response.url == BASE + '/accounts/github/login/' else None)
            try:
                response = page.goto(BASE + '/login/', wait_until='networkidle')
                assert response.status == 200
                assert response.headers['referrer-policy'] == 'same-origin'
                assert any(cookie['name'] == '__Host-oracle_csrf' and cookie['secure']
                           for cookie in context.cookies())
                with page.expect_request(lambda request:
                        (urlsplit(request.url).netloc, urlsplit(request.url).path) ==
                        ('github.com', '/login/oauth/authorize'), timeout=15000):
                    page.get_by_role('button', name='使用 GitHub 登录', exact=True).click()
                assert 302 in statuses and 403 not in statuses
                print(f'BROWSER_{name.upper()}_REAL_FORM_COOKIE_CSRF_OAUTH_REDIRECT=PASS', flush=True)
            except BrowserTimeout:
                print(f'BROWSER_{name.upper()}_LOCAL_POST_STATUSES={statuses}', flush=True)
                raise RuntimeError('Anonymous browser OAuth navigation failed') from None
            finally:
                context.close()
                browser.close()


if __name__ == '__main__': main()
