"""Check the deployed admin UI without exporting credentials or browser state."""
from urllib.parse import urlsplit
import time
import os

from playwright.sync_api import sync_playwright, expect, TimeoutError as BrowserTimeout

BASE = 'https://vpn-admin.morandi.dpdns.org'


def verify_readability(page, critical_selector):
    page.evaluate("document.documentElement.style.fontSize = '200%'")
    try:
        assert page.evaluate(r"""selector => {
            const root = document.documentElement;
            const bodyStyle = getComputedStyle(document.body);
            const elements = [...document.querySelectorAll(selector)];
            const channels = value => value.match(/\d+(?:\.\d+)?/g).slice(0, 3).map(Number);
            const luminance = value => channels(value).map(channel => {
                const s = channel / 255;
                return s <= 0.04045 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4;
            }).reduce((total, channel, index) => total + channel * [0.2126, 0.7152, 0.0722][index], 0);
            const ink = luminance(bodyStyle.color);
            const canvas = luminance(bodyStyle.backgroundColor);
            if ((Math.max(ink, canvas) + 0.05) / (Math.min(ink, canvas) + 0.05) < 4.5)
                return false;
            if (root.scrollWidth > root.clientWidth + 1 || !elements.length)
                return false;
            return elements.every(element => {
                const box = element.getBoundingClientRect();
                return box.width > 0 && box.left >= -1 && box.right <= root.clientWidth + 1 &&
                    element.scrollHeight <= element.clientHeight + 1 &&
                    element.scrollWidth <= element.clientWidth + 1;
            });
        }""", critical_selector)
    finally:
        page.evaluate("document.documentElement.style.removeProperty('font-size')")


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
                page.set_viewport_size({'width': 390, 'height': 844})
                verify_readability(page, 'main h1')
                page.set_viewport_size({'width': 1280, 'height': 900})
                print(f'BROWSER_{name.upper()}_LIVE_NARROW_LARGE_TEXT_LOGIN=PASS', flush=True)
                assert any(cookie['name'] == '__Host-oracle_csrf' and cookie['secure']
                           for cookie in context.cookies())
                if page.locator('input[name="password"]').count():
                    if os.environ.get('ADMIN_BOOTSTRAP_BROWSER_STATE')=='CHANGED':
                        expect(page.locator('input[name="username"]')).to_be_visible()
                        expect(page.locator('input[name="password"]')).to_be_visible()
                        print(f'BROWSER_{name.upper()}_LOCAL_LOGIN_FORM_AND_SECURE_CSRF_COOKIE=PASS',flush=True)
                        print(f'BROWSER_{name.upper()}_AUTHENTICATED_LOGIN=NOT_TESTED_WEBSITE_PASSWORD_PRESERVED',flush=True)
                        continue
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
                            assert fresh.request.get(BASE+'/api/flclash').status==401
                        finally:
                            fresh.close()
                        assert control.json().get('administrator',{}).get('username')==username
                        page.set_viewport_size({'width': 390, 'height': 844})
                        verify_readability(page, 'main h1, #overview h2')
                        page.set_viewport_size({'width': 1280, 'height': 900})
                        print(f'BROWSER_{name.upper()}_LIVE_NARROW_LARGE_TEXT_DASHBOARD=PASS', flush=True)
                        profiles=context.request.get(BASE+'/api/flclash')
                        assert profiles.status==200 and isinstance(profiles.json().get('profiles'),list)
                        assert page.locator('#flclash').count()==1
                        expect(page.locator('#flclash-status')).to_contain_text('WireGuard UDP 443')
                        assert page.locator('#flclash-form [name=confirm]').count()==0
                        telemetry=context.request.get(BASE+'/api/host-status')
                        assert telemetry.status==200
                        health=telemetry.json();assert health['sample'] and not health['stale'] and '_raw' not in health['sample']
                        assert page.locator('#host-health').count()==1
                        expect(page.locator('#overview #connections')).to_be_visible()
                        expect(page.locator('nav a[href="#connections"]')).to_have_count(0)
                        connection_details=page.locator('#connection-details')
                        assert not connection_details.evaluate('(element) => element.open')
                        connection_details.locator('summary').click()
                        assert connection_details.evaluate('(element) => element.open')
                        connection_details.locator('summary').click()
                        print(f'BROWSER_{name.upper()}_LIVE_OVERVIEW_CONNECTION_DISCLOSURE=PASS',flush=True)
                        assert page.locator('#available').count()==0
                        for window in ('hour','day','week','month'):
                            historical=context.request.get(BASE+'/api/host-status?window='+window)
                            assert historical.status==200 and historical.json()['window']==window and len(historical.json()['history'])>=60
                        expect(page.locator('#host-trends figure')).to_have_count(6)
                        print('LIVE_HOST_HEALTH_FRESH=PASS',flush=True)
                        print(f'BROWSER_{name.upper()}_REAL_FLCLASH_UDP_EXPORT_MODULE_READ_ONLY=PASS',flush=True)
                        assert page.locator('#unconfirmed').count()==1
                        assert not page.locator('#user-form').is_visible()
                        help_icon=page.locator('#users .help-icon').first
                        help_icon.click()
                        assert page.locator('#help-users').is_visible()
                        page.keyboard.press('Escape')
                        assert not page.locator('#help-users').is_visible()
                        if control.json()['users']:
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
