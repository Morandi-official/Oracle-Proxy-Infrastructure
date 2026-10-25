"""Anonymous browser acceptance only; never authenticate or export browser state."""
from urllib.parse import urlsplit
import time
import os

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
                if page.locator('input[name="password"]').count():
                    username=os.environ.get('ADMIN_LOCAL_ACCEPTANCE_USERNAME','')
                    password=os.environ.get('ADMIN_LOCAL_ACCEPTANCE_PASSWORD','')
                    if not username or not password:raise RuntimeError('LOCAL_ADMIN_ACCEPTANCE_CREDENTIALS_REQUIRED')
                    try:
                        page.locator('input[name="username"]').fill(username)
                        page.locator('input[name="password"]').fill(password)
                        page.get_by_role('button',name='登录',exact=True).click()
                        page.wait_for_url(BASE+'/',timeout=15000)
                        status=context.request.get(BASE+'/api/status')
                        control=context.request.get(BASE+'/api/control')
                        assert status.status==200 and control.status==200
                        assert status.json()['actor']==username and 'users' in control.json()
                        cookies=context.cookies()
                        session=next(c for c in cookies if c['name']=='__Host-oracle_admin')
                        assert session['secure'] and session['httpOnly'] and session['sameSite']=='Lax'
                        assert 30*86400-60 <= session['expires']-time.time() <= 30*86400
                        restored=browser.new_context(service_workers='block')
                        fresh=browser.new_context(service_workers='block')
                        try:
                            restored.add_cookies(cookies)
                            assert restored.request.get(BASE+'/api/status').status==200
                            assert fresh.request.get(BASE+'/api/status').status==401
                        finally:
                            fresh.close()
                        assert control.json().get('administrator',{}).get('username')==username
                        assert page.locator('#unconfirmed').count()==1
                        assert not page.locator('#user-form').is_visible()
                        help_icon=page.locator('#users .help-icon').first
                        help_icon.click()
                        assert page.locator('#help-users').is_visible()
                        page.keyboard.press('Escape')
                        assert not page.locator('#help-users').is_visible()
                        if control.json()['users']:
                            from playwright.sync_api import expect
                            page.locator('#user-rows .user-toggle').first.click()
                            chart=page.locator('#user-rows .user-history:not([hidden])').first
                            for choice,count in [('day',24),('week',7)]:
                                chart.get_by_label('流量统计范围').select_option(choice)
                                expect(chart.locator('svg rect')).to_have_count(count)
                            chart.get_by_label('流量统计范围').select_option('month')
                        print(f'BROWSER_{name.upper()}_REAL_COMPACT_HELP_AND_USER_USAGE_CHART_READ_ONLY=PASS',flush=True)
                        page.get_by_role('button',name='退出登录',exact=True).click()
                        page.wait_for_url(BASE+'/login/',timeout=15000)
                        assert context.request.get(BASE+'/api/control').status==401
                        assert restored.request.get(BASE+'/api/status').status==401
                        restored.close()
                    except Exception:
                        raise RuntimeError('LOCAL_ADMIN_BROWSER_ACCEPTANCE_FAILED') from None
                    print(f'BROWSER_{name.upper()}_REAL_LOCAL_PASSWORD_30_DAY_COOKIE_RESTORE_FRESH_CONTEXT_AND_LOGOUT=PASS',flush=True)
                    continue
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
