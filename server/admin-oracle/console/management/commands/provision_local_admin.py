from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import identify_hasher
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from allauth.socialaccount.models import SocialAccount


class Command(BaseCommand):
    help='Provision only the single host-configured local administrator, never from HTTP.'

    def handle(self,**options):
        if settings.ADMIN_AUTH_MODE != 'local':
            self.stdout.write('LOCAL_ADMIN=NOT_SELECTED'); return
        encoded=settings.ADMIN_LOCAL_PASSWORD_HASH
        try: identify_hasher(encoded)
        except ValueError: raise CommandError('INVALID_ADMIN_PASSWORD_HASH') from None
        with transaction.atomic():
            user,created=get_user_model().objects.get_or_create(username=settings.ADMIN_LOCAL_USERNAME)
            if SocialAccount.objects.filter(user=user).exclude(provider='github',uid__in=settings.ADMIN_GITHUB_IDS).exists():
                raise CommandError('ADMIN_USERNAME_LINKED_TO_EXTERNAL_IDENTITY')
            user.password=encoded;user.is_active=True;user.is_staff=True;user.is_superuser=False
            user.save(update_fields=['password','is_active','is_staff','is_superuser'])
        self.stdout.write('LOCAL_ADMIN=PROVISIONED')
