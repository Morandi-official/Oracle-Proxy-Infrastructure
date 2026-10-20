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
