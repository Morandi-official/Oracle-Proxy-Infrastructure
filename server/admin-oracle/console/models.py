import uuid
from django.db import models
from django.utils import timezone


class Snapshot(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    observed_at = models.DateTimeField(default=timezone.now, db_index=True)
    payload = models.JSONField()


class Audit(models.Model):
    occurred_at = models.DateTimeField(default=timezone.now, db_index=True)
    actor = models.CharField(max_length=120)
    action = models.CharField(max_length=80)
    resource = models.CharField(max_length=80, default='oracle-primary')


class RateLimitCache(models.Model):
    cache_key = models.CharField(max_length=255, primary_key=True)
    value = models.TextField()
    expires = models.DateTimeField(db_index=True)

    class Meta:
        db_table = 'console_ratelimit'


class ClientAccount(models.Model):
    """VPN credentials are independent of Django/GitHub administrator identities."""
    user_id = models.UUIDField(primary_key=True)
    username = models.CharField(max_length=64, unique=True)
    password = models.CharField(max_length=256)
    updated_at = models.DateTimeField(auto_now=True)


class ClientSession(models.Model):
    token_hash = models.CharField(max_length=64, primary_key=True)
    account = models.ForeignKey(ClientAccount, on_delete=models.CASCADE)
    public_key = models.CharField(max_length=44)
    expires_at = models.DateTimeField(db_index=True)
    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        constraints = [models.UniqueConstraint(fields=['account', 'public_key'], name='client_session_per_device')]


class ClientLoginThrottle(models.Model):
    bucket = models.CharField(max_length=100, primary_key=True)
    attempts = models.PositiveIntegerField(default=0)
    expires_at = models.DateTimeField(db_index=True)
