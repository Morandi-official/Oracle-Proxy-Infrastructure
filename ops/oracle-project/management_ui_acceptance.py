"""Browser UI tests with local synthetic RPC/ledger. No production login or user fixtures."""
import importlib.util
import json
import tempfile
from pathlib import Path
from urllib.parse import urlsplit
from playwright.sync_api import sync_playwright, expect

ROOT=Path(__file__).resolve().parents[2]
SERVER=ROOT/'server/admin-oracle'
spec=importlib.util.spec_from_file_location('synthetic_policy',SERVER/'control/test_agent.py')
fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture)


def main():
 with sync_playwright() as playwright:
  for name in ('chromium','firefox'):
   with tempfile.TemporaryDirectory() as temporary:
    driver=fixture.FakeDriver();engine=fixture.agent.Engine(Path(temporary)/'fixture.sqlite3',driver);engine.tick()
    browser=getattr(playwright,name).launch(headless=True);context=browser.new_context(timezone_id='UTC');page=context.new_page()
    errors=[];page.on('pageerror',lambda error:errors.append(str(error)))
    def serve(route):
     path=urlsplit(route.request.url).path
     if path=='/':
      body=(SERVER/'templates/dashboard.html').read_text().replace('{% csrf_token %}','<input type="hidden" name="csrfmiddlewaretoken" value="synthetic-browser-only-token">')
      route.fulfill(status=200,content_type='text/html',body=body)
     elif path in ('/app.js','/style.css'):
      route.fulfill(status=200,content_type='text/javascript' if path.endswith('.js') else 'text/css',body=(SERVER/'static/console'/path[1:]).read_text())
     else:
      if path=='/api/control':
       if route.request.method=='POST':
        assert route.request.headers['x-csrftoken']=='synthetic-browser-only-token'
        value=route.request.post_data_json
        data=engine.dispatch({'actor':'github:204281968',**value})
       else:data=engine.snapshot()
      elif path=='/api/status':data={'actor':'Synthetic CI administrator','snapshot':None}
      elif path=='/api/audit':data={'entries':[]}
      else:route.fulfill(status=404);return
      route.fulfill(status=200,content_type='application/json',body=json.dumps(data))
    page.route('**/*',serve)
    try:
     page.goto('https://management-fixture.invalid/',wait_until='networkidle')
     expect(page.locator('#remaining')).to_have_text('未知')
     label='CI browser user <b>literal</b>'
     page.locator('#user-form [name=name]').fill(label);page.locator('#user-form [name=quota]').fill('1')
     page.get_by_role('button',name='保存用户策略',exact=True).click()
     row=page.locator('#user-rows tr').filter(has_text=label);expect(row).to_contain_text('可用')
     assert page.locator('#user-rows b').count()==0
     user=engine.snapshot()['users'][0]
     page.locator('#peer-form [name=name]').fill('CI Windows PC');page.locator('#peer-form [name=user_id]').select_option(user['id'])
     page.locator('#peer-form [name=public_key]').fill(fixture.KEY1)
     page.get_by_role('button',name='绑定 / 调整已有 Peer',exact=True).click()
     expect(page.locator('#peer-rows tr').filter(has_text='CI Windows PC')).to_contain_text(label)
     assert driver.allowed=={'10.250.0.2'}
     page.locator('#peer-form [name=name]').fill('CI New Windows PC');page.locator('#peer-form [name=public_key]').fill(fixture.KEY3)
     page.get_by_role('button',name='新增 Peer',exact=True).click()
     expect(page.locator('#peer-rows tr').filter(has_text='CI New Windows PC')).to_contain_text('10.250.0.4/32')
     row.get_by_role('button',name='禁用',exact=True).click();expect(row).to_contain_text('已禁用');assert not driver.allowed
     row.get_by_role('button',name='启用',exact=True).click();expect(row).to_contain_text('可用')
     row.get_by_role('button',name='编辑',exact=True).click();page.locator('#user-form [name=expires]').fill('2020-01-01T00:00')
     page.get_by_role('button',name='保存用户策略',exact=True).click();expect(row).to_contain_text('已到期');assert not driver.allowed
     page.locator('#budget-form [name=prior]').fill('10');page.locator('#budget-form [name=confirm]').check();page.locator('#budget-form [name=guard]').check()
     page.get_by_role('button',name='保存出站保护策略',exact=True).click()
     expect(page.locator('#balance-basis')).to_have_text('手工核对基线 + 本机增量估算')
     assert engine.budget_state()['estimated_used_bytes']==10_000_000_000
     assert not errors, 'Synthetic management UI raised JavaScript errors'
     print(f'SYNTHETIC_{name.upper()}_UI_USER_PEER_QUOTA_EXPIRY_BUDGET_CSRF_HEADER_AND_TEXT_ESCAPE=PASS',flush=True)
    finally:context.close();browser.close();engine.db.close()


if __name__=='__main__':main()
