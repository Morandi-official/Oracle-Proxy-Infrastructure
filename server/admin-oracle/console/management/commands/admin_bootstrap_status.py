"""Read-only, local deployment evidence; never expose credentials over HTTP."""
import hmac
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError
from console import local_auth

class Command(BaseCommand):
    help='Report whether initial admin credentials still match, without printing hashes or passwords'
    def handle(self,**options):
        if not local_auth.enabled():
            self.stdout.write('ADMIN_BOOTSTRAP_BROWSER=NOT_LOCAL');return
        user=get_user_model().objects.filter(username=settings.ADMIN_LOCAL_USERNAME).first()
        if not local_auth.permitted(user) or not user.has_usable_password():
            raise CommandError('ADMIN_IDENTITY_UNAVAILABLE')
        state='READY' if hmac.compare_digest(user.password,settings.ADMIN_LOCAL_PASSWORD_HASH) else 'CHANGED'
        self.stdout.write('ADMIN_BOOTSTRAP_BROWSER='+state)
