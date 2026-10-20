from datetime import timedelta
import subprocess
from django.core.management.base import BaseCommand, CommandError
from django.contrib.sessions.models import Session
from django.utils import timezone
from console.collector import collect
from console.models import Audit, Snapshot


class Command(BaseCommand):
    help = 'Collect fixed, non-root Oracle service observations and enforce retention'

    def handle(self, **options):
        try:
            collect()
        except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
            Audit.objects.create(actor='collector:local-readonly', action='snapshot.failed')
            raise CommandError('Observation failed; last known state retained') from error
        cutoff = timezone.now() - timedelta(days=30)
        Snapshot.objects.filter(observed_at__lt=cutoff).delete()
        Audit.objects.filter(occurred_at__lt=cutoff).delete()
        Session.objects.filter(expire_date__lt=timezone.now()).delete()
        self.stdout.write('ORACLE_ADMIN_STATUS=COLLECTED')
