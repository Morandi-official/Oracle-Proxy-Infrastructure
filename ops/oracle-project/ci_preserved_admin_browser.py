"""Actual browsers must not submit the obsolete bootstrap secret after a web password change."""
import importlib.util
import os
from pathlib import Path
from unittest.mock import patch
from playwright.sync_api import sync_playwright

spec=importlib.util.spec_from_file_location('live_admin_browser',Path(__file__).with_name('browser_acceptance.py'))
acceptance=importlib.util.module_from_spec(spec);spec.loader.exec_module(acceptance)

def main():
    requests=[]
    with sync_playwright() as actual:
        def serve(route):
            requests.append(route.request.method)
            assert route.request.method=='GET','Obsolete credentials were submitted'
            route.fulfill(status=200,content_type='text/html',headers={'referrer-policy':'same-origin',
                'set-cookie':'__Host-oracle_csrf=synthetic-only; Path=/; Secure; SameSite=Lax'},
                body='<form><input name="username"><input name="password" type="password"><button>登录</button></form>')
        class Browser:
            def __init__(self,browser):self.browser=browser
            def new_context(self,**options):
                context=self.browser.new_context(**options);context.route('https://vpn-admin.morandi.dpdns.org/**',serve);return context
            def close(self):self.browser.close()
        class Kind:
            def __init__(self,kind):self.kind=kind
            def launch(self,**options):return Browser(self.kind.launch(**options))
        class Context:
            def __enter__(self):return type('Browsers',(),{'chromium':Kind(actual.chromium),'firefox':Kind(actual.firefox)})()
            def __exit__(self,*args):pass
        with patch.object(acceptance,'sync_playwright',return_value=Context()),patch.dict(os.environ,{
                'ADMIN_BOOTSTRAP_BROWSER_STATE':'CHANGED','ADMIN_LOCAL_ACCEPTANCE_USERNAME':'','ADMIN_LOCAL_ACCEPTANCE_PASSWORD':''}):
            acceptance.main()
    assert len(requests)>=2 and all(method=='GET' for method in requests)
    print('ACTUAL_CHROMIUM_FIREFOX_WEB_PASSWORD_PRESERVED_NO_BOOTSTRAP_POST=PASS')

if __name__=='__main__':main()
