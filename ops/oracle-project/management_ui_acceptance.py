"""Browser UI tests with local synthetic RPC/ledger. No production login or user fixtures."""
import importlib.util
import json
import tempfile
import time
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
    accounts={};official_fixture=[None];pending_fixture=[[]];presence_fixture=[False]
    engine.official_usage=lambda:official_fixture[0] or {'status':'NOT_QUERIED'}
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
        if value['operation']=='account.save':
         account=value['data']; policy={k:account[k] for k in ('id','name','quota_bytes','expires_at','enabled','device_limit')}
         data=engine.dispatch({'actor':'github:204281968','operation':'user.save','data':policy})
         accounts[data['saved_user_id']]=account['username']
        elif value['operation']=='account.delete':
         data=engine.dispatch({'actor':'github:204281968','operation':'user.delete','data':value['data']})
         accounts.pop(value['data']['user_id'],None)
        else:data=engine.dispatch({'actor':'github:204281968',**value})
       else:data=engine.snapshot()
       for u in data['users']:u['username']=accounts.get(u['id'])
       data['pending_devices']=pending_fixture[0]
       for p in data['peers']:
        if presence_fixture[0] and p['public_key']==fixture.KEY3:p['client_status']={'online':True,'reported_mode':'connected','transport':'wireguard-udp','last_seen_at':int(time.time())}
       if official_fixture[0] is not None:data['official_usage']=official_fixture[0]
      elif path=='/api/status':data={'actor':'Synthetic CI administrator','snapshot':None}
      elif path=='/api/audit':data={'entries':[{'occurred_at':int(time.time())-i,'actor':'fixture','action':'test','resource':'fixture'} for i in range(20)],'activity':[{'username':'ci-user01','count':7}]}
      else:route.fulfill(status=404);return
      route.fulfill(status=200,content_type='application/json',body=json.dumps(data))
    page.route('**/*',serve)
    try:
     page.goto('https://management-fixture.invalid/',wait_until='networkidle')
     expect(page.locator('#remaining')).to_have_text('未知')
     label='CI browser user <b>literal</b>'
     page.locator('#user-form [name=username]').fill('ci-user01');page.locator('#user-form [name=password]').fill('synthetic-password-only-123')
     page.locator('#user-form [name=name]').fill(label);page.locator('#user-form [name=quota]').fill('1')
     page.get_by_role('button',name='保存用户',exact=True).click()
     row=page.locator('#user-rows tr').filter(has_text=label);expect(row).to_contain_text('可用')
     assert page.locator('#user-rows b').count()==0
     user=engine.snapshot()['users'][0]
     expect(row).to_contain_text('ci-user01');expect(page.locator('#user-form [name=password]')).to_have_value('')
     assert page.locator('#account-form').count()==0
     assert 'synthetic-password-only-123' not in page.locator('body').inner_text()
     page.locator('#device-editor').evaluate('(el)=>el.open=true')
     page.locator('#peer-form [name=name]').fill('CI Windows PC');page.locator('#peer-form [name=user_id]').select_option(user['id'])
     page.locator('#peer-form [name=public_key]').fill(fixture.KEY1)
     page.get_by_role('button',name='保存设备',exact=True).click()
     expect(page.locator('#peer-rows tr').filter(has_text='CI Windows PC')).to_contain_text(label)
     assert driver.allowed=={'10.250.0.2'}
     page.locator('#peer-form [name=name]').fill('CI New Windows PC');page.locator('#peer-form [name=public_key]').fill(fixture.KEY3)
     page.get_by_role('button',name='保存设备',exact=True).click()
     expect(page.locator('#peer-rows tr').filter(has_text='CI New Windows PC')).to_contain_text('10.250.0.4/32')
     engine.dispatch({'operation':'peer.enroll','actor':'system:client-api','data':{'public_key':fixture.KEY3,'user_id':user['id'],'name':'CI New Windows PC','machine_name':'CI-DESKTOP','client_version':'0.3.0-rc18','confirm':True}})
     pending_fixture[0]=[{'id':'a'*12,'name':'CI pending <b>literal</b>','user_id':user['id'],'created_at':int(time.time()),'last_seen_at':int(time.time())}];presence_fixture[0]=True
     page.get_by_role('button',name='↻ 刷新',exact=True).click()
     confirmed=page.locator('#peer-rows tr').filter(has_text='CI New Windows PC')
     expect(confirmed).to_contain_text('用户已确认');expect(confirmed).to_contain_text('CI-DESKTOP');expect(confirmed).to_contain_text('自报已连接')
     expect(page.locator('#pending-device-rows')).to_contain_text('CI pending <b>literal</b>')
     assert page.locator('#pending-device-rows b').count()==0
     assert engine.device_count(user['id'])==2
     confirmed.get_by_role('button',name='管理',exact=True).click()
     expect(page.locator('#device-profile')).to_be_visible()
     expect(page.locator('#device-profile')).to_contain_text('设备识别码')
     pending_fixture[0]=[]
     print(f'SYNTHETIC_{name.upper()}_PENDING_CONFIRMED_DEVICE_PRESENCE_AND_TEXT_ESCAPE=PASS',flush=True)
     row.get_by_role('button',name='编辑',exact=True).click();page.locator('#user-form [name=enabled]').uncheck()
     page.get_by_role('button',name='保存用户',exact=True).click();expect(row).to_contain_text('已禁用');assert not driver.allowed
     row.get_by_role('button',name='编辑',exact=True).click();page.locator('#user-form [name=enabled]').check()
     page.get_by_role('button',name='保存用户',exact=True).click();expect(row).to_contain_text('可用')
     row.get_by_role('button',name='编辑',exact=True).click();page.locator('#user-form [name=expires]').fill('2020-01-01T00:00')
     page.get_by_role('button',name='保存用户',exact=True).click();expect(row).to_contain_text('已到期');assert not driver.allowed
     page.locator('#budget-form [name=source]').select_option('manual')
     page.locator('#budget-form [name=prior]').fill('10');page.locator('#budget-form [name=confirm]').check();page.locator('#budget-form [name=guard]').check()
     page.get_by_role('button',name='保存出站保护策略',exact=True).click()
     expect(page.locator('#balance-basis')).to_have_text('手工核对基线 + 本机增量估算')
     assert engine.budget_state()['estimated_used_bytes']==10_000_000_000
     page.on('dialog',lambda dialog:dialog.accept())
     row.get_by_role('button',name='删除',exact=True).click();expect(page.locator('#user-rows')).to_contain_text('尚无用户')
     assert not engine.snapshot()['users'] and not driver.allowed
     assert all(p['revoked'] for p in engine.snapshot()['peers'] if p['managed'])
     official_fixture[0]={'status':'INSTANCE_PRINCIPAL_READY','free_tier_status':'VERIFIED_USAGE_AND_PRICE_TIER','free_tier_limit_gb':10240,'free_tier_used_gb':1.25,'free_tier_remaining_gb':10238.75,'period':engine.snapshot()['period'],'checked_at':int(time.time()),'billing_through':int(time.time())-86400,'free_tier_policy_checked':'2026-10-23'}
     page.get_by_role('button',name='↻ 刷新',exact=True).click()
     expect(page.locator('#official-remaining')).to_have_text('10,238.75 GB')
     expect(page.locator('#remaining')).to_have_text('10,238.75 GB')
     assert page.locator('#official-progress').evaluate('(el)=>el.max===10240 && el.value===1.25')
     page.locator('#budget-form [name=source]').select_option('official')
     page.locator('#budget-form [name=confirm]').check()
     page.get_by_role('button',name='保存出站保护策略',exact=True).click()
     assert engine.budget_state()['estimated_used_bytes']>=int(1.25*2**30)
     expect(page.locator('#available')).not_to_have_text('未知')
     official_fixture[0]['free_tier_status']='PAGINATED_INCOMPLETE'
     page.get_by_role('button',name='↻ 刷新',exact=True).click()
     expect(page.locator('#official-remaining')).to_have_text('未知')
     expect(page.locator('#audit-rows tr')).to_have_count(10)
     expect(page.locator('#activity-chart')).to_contain_text('7 次')
     assert not errors, 'Synthetic management UI raised JavaScript errors'
     print(f'SYNTHETIC_{name.upper()}_UI_USER_PEER_QUOTA_EXPIRY_BUDGET_CSRF_HEADER_AND_TEXT_ESCAPE=PASS',flush=True)
    finally:context.close();browser.close();engine.db.close()


if __name__=='__main__':main()
