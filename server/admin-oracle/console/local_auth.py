"""Single provisioned administrator; no registration, OAuth or MFA in local mode."""
import hashlib
from datetime import timedelta
from django.conf import settings
from django.contrib.auth.backends import ModelBackend
from django.db import transaction
from django.db.models import F
from django.utils import timezone
from .models import ClientLoginThrottle


def enabled(): return settings.ADMIN_AUTH_MODE == 'local'


def permitted(user):
    return bool(user and user.is_active and user.is_staff and user.get_username() == settings.ADMIN_LOCAL_USERNAME)


class LocalAdminBackend(ModelBackend):
    def authenticate(self, request, username=None, password=None, **kwargs):
        if not enabled(): return None
        user = super().authenticate(request,username=username,password=password,**kwargs)
        return user if permitted(user) else None

    def get_user(self,user_id):
        user = super().get_user(user_id)
        return user if enabled() and permitted(user) else None


def throttle(username):
    now = timezone.now(); minute = int(now.timestamp()) // 60
    with transaction.atomic():
        ClientLoginThrottle.objects.filter(expires_at__lt=now).delete()
        for name,maximum in [('global',30),('user:'+hashlib.sha256(username.encode()).hexdigest(),5)]:
            bucket=f'admin:{minute}:{name}'
            ClientLoginThrottle.objects.get_or_create(bucket=bucket,defaults={'expires_at':now+timedelta(minutes=2)})
            ClientLoginThrottle.objects.filter(bucket=bucket).update(attempts=F('attempts')+1)
            if ClientLoginThrottle.objects.get(bucket=bucket).attempts > maximum: return False
    return True
