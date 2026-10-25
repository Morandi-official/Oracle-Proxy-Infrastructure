import re
from datetime import timedelta
from unittest.mock import patch
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import make_password
from django.core.management import call_command
from django.test import Client, TestCase, override_settings
from django.conf import settings
from django.utils import timezone
from .models import Audit, Snapshot


@override_settings(ADMIN_AUTH_MODE='local',ADMIN_LOCAL_USERNAME='owner-local',
                   AUTHENTICATION_BACKENDS=['console.local_auth.LocalAdminBackend'])
class LocalAdminTests(TestCase):
    password='synthetic-12!'

    def setUp(self):
        self.owner=get_user_model().objects.create_user(username='owner-local',password=self.password,is_staff=True)
        Snapshot.objects.create(payload={'test':True})

    def test_login_without_github_or_mfa_allows_only_provisioned_owner_and_logout_clears_it(self):
        self.assertNotContains(self.client.get('/login/',secure=True),'GitHub')
        self.assertEqual(self.client.post('/login/',{'username':'owner-local','password':self.password},secure=True).status_code,302)
        self.assertEqual(self.client.get('/api/status',secure=True).status_code,200)
        self.assertTrue(Audit.objects.filter(actor=f'local:{self.owner.pk}',action='admin.login').exists())
        self.assertContains(self.client.get('/',secure=True),'固定账号密码')
        self.assertEqual(self.client.post('/logout/',secure=True).status_code,302)
        self.assertEqual(self.client.get('/api/status',secure=True).status_code,401)
        for path in ('/accounts/github/login/','/accounts/login/','/accounts/2fa/','/accounts/signup/','/accounts/password/reset/'):
            self.assertEqual(self.client.get(path,secure=True).status_code,404)

    def test_password_without_admin_role_and_unprovisioned_staff_cannot_authenticate(self):
        self.owner.is_staff=False;self.owner.save()
        self.assertEqual(self.client.post('/login/',{'username':'owner-local','password':self.password},secure=True).status_code,401)
        get_user_model().objects.create_user(username='other-admin',password=self.password,is_staff=True)
        self.assertEqual(self.client.post('/login/',{'username':'other-admin','password':self.password},secure=True).status_code,401)
        self.assertEqual(self.client.get('/api/control',secure=True).status_code,401)

    def test_csrf_and_session_fixation_and_password_session_assurance(self):
        client=Client(enforce_csrf_checks=True)
        self.assertEqual(client.post('/login/',{'username':'owner-local','password':self.password},secure=True).status_code,403)
        response=client.get('/login/',secure=True)
        token=re.search(rb'name="csrfmiddlewaretoken" value="([^"]+)"',response.content).group(1).decode()
        session=client.session;session['before_login']='exists';session.save();old=session.session_key
        self.assertEqual(client.post('/login/',{'username':'owner-local','password':self.password,'csrfmiddlewaretoken':token},secure=True,HTTP_ORIGIN='https://testserver').status_code,302)
        self.assertNotEqual(old,client.session.session_key)
        self.assertEqual(client.get('/api/status',secure=True).status_code,200)
        session=client.session;session.pop('admin_password_at');session.save()
        self.assertEqual(client.get('/api/status',secure=True).status_code,403)

    def test_failed_login_throttle_is_persistent_and_does_not_expose_password(self):
        for _ in range(5):self.assertEqual(self.client.post('/login/',{'username':'owner-local','password':'synthetic-wrong'},secure=True).status_code,401)
        self.assertEqual(Client().post('/login/',{'username':'owner-local','password':self.password},secure=True).status_code,429)
        self.assertFalse(Audit.objects.filter(actor__contains='synthetic').exists())

    def test_remember_device_has_fixed_30_day_expiry_and_logout_revokes_saved_cookie(self):
        response=self.client.post('/login/',{'username':'owner-local','password':self.password},secure=True)
        cookie=response.cookies[settings.SESSION_COOKIE_NAME]
        self.assertTrue(cookie['secure']);self.assertTrue(cookie['httponly'])
        self.assertEqual(cookie['samesite'],'Lax')
        self.assertTrue(30*86400-5 <= int(cookie['max-age']) <= 30*86400)
        expires=self.client.session.get_expiry_date()
        at=self.client.session['admin_password_at']
        saved=cookie.value
        with patch('console.views.time',return_value=at+29*86400):
            self.assertEqual(self.client.get('/api/status',secure=True).status_code,200)
        self.assertEqual(self.client.session.get_expiry_date(),expires)
        with patch('console.views.time',return_value=at+30*86400+1):
            self.assertEqual(self.client.get('/api/status',secure=True).status_code,403)
        self.assertEqual(Client().get('/api/status',secure=True).status_code,401)
        self.client.post('/logout/',secure=True)
        restored=Client();restored.cookies[settings.SESSION_COOKIE_NAME]=saved
        self.assertEqual(restored.get('/api/status',secure=True).status_code,401)

    def test_password_change_invalidates_remembered_browser(self):
        self.client.post('/login/',{'username':'owner-local','password':self.password},secure=True)
        self.owner.set_password('synthetic-changed-password');self.owner.save()
        self.assertEqual(self.client.get('/api/status',secure=True).status_code,401)

    @override_settings(ADMIN_DEVICE_ACCOUNT_USERNAME='vpn-owner')
    def test_device_owner_marker_uses_exact_account_not_display_name_and_grants_no_role(self):
        import uuid
        from .models import ClientAccount
        first=str(uuid.uuid4());second=str(uuid.uuid4())
        ClientAccount.objects.create(user_id=first,username='vpn-owner',password='synthetic-not-login')
        ClientAccount.objects.create(user_id=second,username='someone-else',password='synthetic-not-login')
        self.client.post('/login/',{'username':'owner-local','password':self.password},secure=True)
        value={'users':[{'id':first,'name':'Owner'},{'id':second,'name':'vpn-owner'}],'peers':[]}
        with patch('console.control.call',return_value=value):
            data=self.client.get('/api/control',secure=True).json()
        self.assertTrue(data['users'][0]['is_admin_account'])
        self.assertFalse(data['users'][1]['is_admin_account'])
        self.assertEqual(data['administrator']['device_account_username'],'vpn-owner')

    def test_host_provision_stores_hash_and_does_not_grant_django_superuser(self):
        encoded=make_password(self.password)
        with override_settings(ADMIN_LOCAL_PASSWORD_HASH=encoded):call_command('provision_local_admin',verbosity=0)
        self.owner.refresh_from_db()
        self.assertTrue(self.owner.check_password(self.password));self.assertNotEqual(self.owner.password,self.password)
        self.assertFalse(self.owner.is_superuser)

    def test_existing_authorized_github_owner_can_keep_username_when_switching_mode(self):
        from allauth.socialaccount.models import SocialAccount
        SocialAccount.objects.create(user=self.owner,provider='github',uid='204281968')
        with override_settings(ADMIN_LOCAL_PASSWORD_HASH=make_password(self.password)):call_command('provision_local_admin',verbosity=0)
        self.assertEqual(self.client.post('/login/',{'username':'owner-local','password':self.password},secure=True).status_code,302)
