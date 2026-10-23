import json
import re
import time
from datetime import timedelta
from unittest.mock import Mock, patch
from urllib.parse import parse_qs, urlsplit

import requests
from allauth.core.exceptions import ImmediateHttpResponse
from allauth.mfa.models import Authenticator
from allauth.mfa.totp.internal.auth import TOTP, hotp_value, format_hotp_value
from allauth.socialaccount.models import SocialAccount, SocialLogin, SocialToken
from django.conf import settings
from django.contrib.auth import authenticate, get_user_model
from django.core.cache import cache
from django.test import Client, TestCase
from django.utils import timezone

from .adapters import EncryptedMFAAdapter, GitHubAllowlistAdapter
from .collector import collect
from .models import Audit, Snapshot

HOST = 'vpn-admin.morandi.dpdns.org'
SECRET = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP'  # synthetic unit-test seed


class AdminTests(TestCase):
    def setUp(self):
        cache.clear()
        self.client = Client(HTTP_HOST=HOST)

    def get(self, path, data=None, **kwargs):
        return self.client.get(path, data=data, secure=True, **kwargs)

    def post(self, path, data=None, **kwargs):
        return self.client.post(path, data=data or {}, secure=True, **kwargs)

    def signed_in(self, *, mfa=True, social=True, uid='204281968', expired=False):
        user = get_user_model().objects.create_user('testadmin')
        SocialAccount.objects.create(user=user, provider='github', uid=uid)
        self.client.force_login(user, backend='console.adapters.GitHubSessionBackend')
        if mfa:
            TOTP.activate(user, SECRET)
        session = self.client.session
        at = time.time() - (7200 if expired else 0)
        records = []
        if social:
            records.append({'method': 'socialaccount', 'provider': 'github', 'uid': uid, 'at': at})
        if mfa:
            records.append({'method': 'mfa', 'type': 'totp', 'at': at})
        session['account_authentication_methods'] = records
        session.save()
        return user

    def test_anonymous_requests_cannot_read_data_assets_or_mutate(self):
        for path in ['/api/status', '/api/audit', '/api/control', '/app.js', '/style.css']:
            self.assertEqual(self.get(path).status_code, 401)
        self.assertRedirects(self.get('/'), '/login/', fetch_redirect_response=False)
        self.assertEqual(self.post('/api/status').status_code, 405)
        self.assertEqual(self.post('/api/peers').status_code, 404)
        self.assertEqual(self.post('/api/ingest').status_code, 404)

    def test_control_requires_full_mfa_and_web_sets_actor(self):
        with patch('console.views.control.call') as rpc:
            self.assertEqual(self.get('/api/control').status_code,401);rpc.assert_not_called()
            self.signed_in(mfa=False)
            self.assertEqual(self.get('/api/control').status_code,403);rpc.assert_not_called()

    def test_authenticated_control_uses_fixed_schema_and_never_accepts_actor_or_commands(self):
        self.signed_in()
        with patch('console.views.control.call',return_value={'users':[]}) as rpc:
            self.assertEqual(self.get('/api/control').status_code,200)
            rpc.assert_called_with('state','github:204281968',{})
            for value in ({'operation':'sh','data':{}},{'operation':'user.put','data':{},'actor':'github:999'}):
                self.assertEqual(self.post('/api/control',json.dumps(value),content_type='application/json').status_code,400)
            self.assertEqual(rpc.call_count,1)
            self.assertEqual(self.post('/api/control',json.dumps({'operation':'peer.revoke','data':{'public_key':'synthetic'}}),content_type='application/json').status_code,200)
            rpc.assert_called_with('peer.revoke','github:204281968',{'public_key':'synthetic'})
        with patch('console.views.control.call',side_effect=OSError()):
            self.assertEqual(self.get('/api/control').status_code,503)

    def test_control_mutations_keep_csrf_protection(self):
        self.signed_in()
        client=Client(HTTP_HOST=HOST,enforce_csrf_checks=True);client.cookies=self.client.cookies
        page=client.get('/',secure=True)
        token=re.search(rb'name="csrfmiddlewaretoken" value="([^"]+)"',page.content).group(1).decode()
        body=json.dumps({'operation':'peer.revoke','data':{'public_key':'synthetic'}})
        with patch('console.views.control.call',return_value={'users':[]}) as rpc:
            self.assertEqual(client.post('/api/control',body,content_type='application/json',secure=True,HTTP_REFERER=f'https://{HOST}/').status_code,403)
            rpc.assert_not_called()
            self.assertEqual(client.post('/api/control',body,content_type='application/json',secure=True,HTTP_REFERER=f'https://{HOST}/',HTTP_X_CSRFTOKEN=token).status_code,200)

    def test_login_requires_post_and_csrf_for_github(self):
        secure_client = Client(HTTP_HOST=HOST, enforce_csrf_checks=True)
        login = secure_client.get('/login/', secure=True)
        self.assertContains(login, 'GitHub')
        self.assertEqual(secure_client.post('/accounts/github/login/', secure=True).status_code, 403)
        page = self.get('/accounts/github/login/')
        self.assertEqual(page.status_code, 200)  # confirmation, never OAuth side effect on GET

    def test_browser_referrer_policy_allows_valid_same_origin_form_without_origin_header(self):
        client = Client(HTTP_HOST=HOST, enforce_csrf_checks=True)
        page = client.get('/login/', secure=True)
        token = re.search(rb'name="csrfmiddlewaretoken" value="([^"]+)"', page.content).group(1).decode()
        # Emulate a browser that omits Origin and applies the page's Referrer-Policy.
        headers = {} if page['Referrer-Policy'] == 'no-referrer' else {'HTTP_REFERER': f'https://{HOST}/login/'}
        response = client.post('/accounts/github/login/', {'csrfmiddlewaretoken': token}, secure=True, **headers)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(urlsplit(response['Location']).netloc, 'github.com')
        self.assertEqual(client.post('/accounts/github/login/', {'csrfmiddlewaretoken': token},
                         secure=True, HTTP_REFERER='https://untrusted.invalid/').status_code, 403)
        self.assertEqual(client.post('/accounts/github/login/', secure=True,
                         HTTP_REFERER=f'https://{HOST}/login/').status_code, 403)

    def test_wrong_github_numeric_id_is_rejected_even_with_matching_email(self):
        adapter = GitHubAllowlistAdapter()
        social = SocialLogin(account=SocialAccount(provider='github', uid='999'),
                            user=get_user_model()(email='morandi@nuaa.edu.cn'))
        self.assertFalse(adapter.is_open_for_signup(None, social))
        with self.assertRaises(ImmediateHttpResponse):
            adapter.pre_social_login(None, social)
        self.signed_in(uid='999')
        self.assertEqual(self.get('/api/status').status_code, 401)

    def test_mfa_enrollment_is_required(self):
        self.signed_in(mfa=False)
        self.assertEqual(self.get('/api/status').json()['error'], 'MFA_ENROLLMENT_REQUIRED')
        self.assertRedirects(self.get('/'), '/accounts/2fa/totp/activate/', fetch_redirect_response=False)

    def test_linked_github_account_or_expired_records_are_insufficient(self):
        self.signed_in(social=False)
        self.assertEqual(self.get('/api/status').json()['error'], 'MFA_LOGIN_REQUIRED')
        session = self.client.session
        session['account_authentication_methods'] = [
            {'method': 'socialaccount', 'provider': 'github', 'uid': '204281968', 'at': time.time()-7200},
            {'method': 'mfa', 'type': 'totp', 'at': time.time()-7200}]
        session.save()
        self.assertEqual(self.get('/api/audit').status_code, 403)

    def test_authenticated_empty_status_is_unknown_and_audited(self):
        self.signed_in()
        response = self.get('/api/status')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['freshness'], 'unknown')
        self.assertIsNone(response.json()['snapshot'])
        self.assertFalse(response.json()['capabilities']['configuration'])
        self.assertEqual(Audit.objects.filter(action='status.read').count(), 1)
        self.assertEqual(self.get('/api/audit').json()['entries'][0]['action'], 'status.read')

    def test_recent_and_stale_observations(self):
        self.signed_in()
        row = Snapshot.objects.create(payload={'wg_service': 'ACTIVE'})
        self.assertEqual(self.get('/api/status').json()['freshness'], 'fresh')
        row.observed_at = timezone.now() - timedelta(minutes=10)
        row.save()
        self.assertEqual(self.get('/api/status').json()['freshness'], 'stale')

    def test_local_password_cannot_authenticate_even_if_one_was_set(self):
        user = self.signed_in()
        user.set_password('synthetic-test-password')
        user.save()
        self.assertIsNone(authenticate(username=user.username, password='synthetic-test-password'))
        for path in ['/accounts/password/set/', '/accounts/password/reset/', '/accounts/signup/',
                     '/accounts/email/', '/accounts/social/connections/']:
            self.assertEqual(self.get(path).status_code, 404)

    def test_mfa_seeds_are_encrypted_and_cannot_be_disabled(self):
        user = self.signed_in()
        factor = Authenticator.objects.get(user=user, type='totp')
        self.assertNotIn(SECRET, json.dumps(factor.data))
        adapter = EncryptedMFAAdapter()
        self.assertEqual(adapter.decrypt(factor.data['secret']), SECRET)
        self.assertFalse(adapter.can_delete_authenticator(factor))
        self.post('/accounts/2fa/totp/deactivate/')
        self.assertTrue(Authenticator.objects.filter(pk=factor.pk).exists())

    def test_security_headers_cookies_https_and_host_validation(self):
        response = self.get('/login/')
        self.assertEqual(response['Cache-Control'], 'no-store')
        self.assertEqual(response['X-Frame-Options'], 'DENY')
        self.assertIn("frame-ancestors 'none'", response['Content-Security-Policy'])
        self.assertIn("form-action 'self' https://github.com", response['Content-Security-Policy'])
        csrf = response.cookies[settings.CSRF_COOKIE_NAME]
        self.assertTrue(csrf['secure']); self.assertTrue(csrf['httponly'])
        self.assertEqual(self.client.get('/login/').status_code, 301)
        self.assertEqual(self.get('/login/', HTTP_HOST='attacker.example.com').status_code, 400)

    def test_health_has_no_data_and_is_loopback_only(self):
        with patch('console.views.control.call',side_effect=OSError()):
            self.assertEqual(self.get('/api/health').json(), {'ready': True,'control':{'ready':False}})
        with patch('console.views.control.call',return_value={'observed_at':123,'error':None,'users':[{'name':'sensitive-name'}],
                   'peers':[{'managed':True,'public_key':'sensitive-peer'}],'budget':{'guard_enabled':False,'remaining_bytes':None}}) as rpc:
            value=self.get('/api/health').json()
            self.assertTrue(value['control']['ready']);self.assertEqual(value['control']['peer_count'],1)
            self.assertNotIn('sensitive',json.dumps(value))
            rpc.reset_mock()
            self.assertEqual(self.get('/api/health', REMOTE_ADDR='192.0.2.1').status_code,404)
            rpc.assert_not_called()

    def oauth_login(self, uid=204281968):
        response = self.post('/accounts/github/login/')
        self.assertEqual(response.status_code, 302)
        params = parse_qs(urlsplit(response['Location']).query)
        self.assertEqual(params['code_challenge_method'], ['S256'])
        self.assertEqual(params['redirect_uri'], [f'https://{HOST}/accounts/github/login/callback/'])
        def remote(method, url, **kwargs):
            response = requests.Response()
            response.status_code = 200
            response.headers['content-type'] = 'application/json'
            if url == 'https://github.com/login/oauth/access_token':
                self.assertTrue(kwargs['data']['code_verifier'])
                data = {'access_token': 'synthetic-oauth-token', 'token_type': 'bearer'}
            elif url == 'https://api.github.com/user':
                data = {'id': uid, 'login': 'Morandi-official', 'name': 'Morandi', 'email': None}
            else:
                raise AssertionError(f'Unexpected external request: {url}')
            response._content = json.dumps(data).encode()
            return response
        with patch('requests.sessions.Session.request', side_effect=remote):
            return self.get('/accounts/github/login/callback/', {'state': params['state'][0], 'code': 'synthetic-code'})

    def test_real_oauth_callback_rejects_wrong_account_and_does_not_store_token(self):
        response = self.oauth_login(uid=999)
        self.assertEqual(response.status_code, 403)
        self.assertEqual(SocialAccount.objects.count(), 0)
        self.assertEqual(SocialToken.objects.count(), 0)

    def test_real_oauth_state_mismatch_never_calls_provider(self):
        self.post('/accounts/github/login/')
        with patch('requests.sessions.Session.request') as remote:
            response = self.get('/accounts/github/login/callback/', {'state': 'forged', 'code': 'synthetic'})
        self.assertNotEqual(response.status_code, 302)
        remote.assert_not_called()

    def test_oauth_enrollment_and_actual_mfa_challenge_gate_dashboard(self):
        response = self.oauth_login()
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.get('/api/status').status_code, 403)
        activation = self.get('/accounts/2fa/totp/activate/')
        self.assertEqual(activation.status_code, 200)
        seed = self.client.session['mfa.totp.secret']
        code = format_hotp_value(hotp_value(seed, int(time.time()) // 30))
        self.assertEqual(self.post('/accounts/2fa/totp/activate/', {'code': code}).status_code, 302)
        self.assertEqual(self.get('/api/status').status_code, 403)  # Enrollment is not a verified login.
        self.post('/accounts/logout/')
        response = self.oauth_login()
        self.assertIn('/accounts/2fa/authenticate/', response['Location'])
        self.assertEqual(self.get('/api/status').status_code, 401)
        response = self.post('/accounts/2fa/authenticate/', {'code': 'wrong'})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.get('/api/status').status_code, 401)
        response = self.post('/accounts/2fa/authenticate/', {'code': code})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.get('/api/status').status_code, 200)
        self.assertEqual(SocialToken.objects.count(), 0)
        self.assertFalse(get_user_model().objects.get(username='Morandi-official').has_usable_password())
        # A second fresh OAuth flow cannot reuse the same time-step code.
        self.post('/accounts/logout/')
        self.oauth_login()
        self.assertEqual(self.post('/accounts/2fa/authenticate/', {'code': code}).status_code, 200)
        self.assertEqual(self.get('/api/status').status_code, 401)

    @patch('console.collector.socket.if_nameindex', return_value=[(1, 'lo'), (2, 'wg0')])
    @patch('console.collector.subprocess.run', return_value=Mock(returncode=0, stdout='active\n'))
    @patch('console.collector.Path.read_text', return_value='header\n1: 00000000:CA6C 00000000:0000\n')
    def test_collector_uses_fixed_unprivileged_queries(self, read, run, interfaces):
        report = collect()
        self.assertEqual(report['wg_service'], 'ACTIVE')
        self.assertEqual(report['wg_interface'], 'PRESENT')
        self.assertEqual(report['udp_listener'], 'LISTENING')
        self.assertEqual(run.call_args.args[0], ['/usr/bin/systemctl', 'is-active', 'wg-quick@wg0'])
        self.assertNotIn('shell', run.call_args.kwargs)
        self.assertEqual(Snapshot.objects.count(), 1)

    @patch('console.collector.subprocess.run', return_value=Mock(returncode=4, stdout='unknown'))
    def test_failed_collection_does_not_publish_false_healthy_state(self, run):
        with self.assertRaises(RuntimeError):
            collect()
        self.assertEqual(Snapshot.objects.count(), 0)
