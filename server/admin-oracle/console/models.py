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
    enrollment_flow = models.BooleanField(default=False)
    proposed_name = models.CharField(max_length=80, default='')
    client_version = models.CharField(max_length=100, default='')
    last_seen_at = models.DateTimeField(null=True)
    reported_mode = models.CharField(max_length=16, default='unknown')
    reported_transport = models.CharField(max_length=24, default='')

    class Meta:
        constraints = [models.UniqueConstraint(fields=['account', 'public_key'], name='client_session_per_device')]


class ClientLoginThrottle(models.Model):
    bucket = models.CharField(max_length=100, primary_key=True)
    attempts = models.PositiveIntegerField(default=0)
    expires_at = models.DateTimeField(db_index=True)


class FlClashProfile(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    account = models.ForeignKey(ClientAccount, on_delete=models.CASCADE)
    name = models.CharField(max_length=80)
    public_key = models.CharField(max_length=44, unique=True)
    token_hash = models.CharField(max_length=64)
    encrypted_material = models.TextField()
    phase = models.CharField(max_length=16, default='pending')
    last_used_at = models.DateTimeField(null=True)
    created_at = models.DateTimeField(default=timezone.now)


class HostMetricMinute(models.Model):
    # Compact minute sums/counts; raw host samples retain their shorter lifetime.
    at = models.DateTimeField(primary_key=True)
    aggregates = models.JSONField(default=dict)


class UdpDiagnostic(models.Model):
    id=models.UUIDField(primary_key=True,default=uuid.uuid4,editable=False)
    account=models.ForeignKey(ClientAccount,on_delete=models.CASCADE)
    device_id=models.CharField(max_length=12)
    started_at=models.DateTimeField(default=timezone.now,db_index=True)
    updated_at=models.DateTimeField(auto_now=True)
    phase=models.CharField(max_length=16,default='running')
    report=models.JSONField(default=dict)
