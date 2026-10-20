from allauth.account.signals import user_logged_in, user_logged_out
from allauth.mfa.signals import authenticator_added
from django.dispatch import receiver
from .models import Audit


@receiver(user_logged_in)
def logged_in(sender, request, user, **kwargs):
    Audit.objects.create(actor=f'user:{user.pk}', action='authentication.login')


@receiver(user_logged_out)
def logged_out(sender, request, user, **kwargs):
    if user is not None:
        Audit.objects.create(actor=f'user:{user.pk}', action='authentication.logout')


@receiver(authenticator_added)
def factor_added(sender, request, user, authenticator, **kwargs):
    Audit.objects.create(actor=f'user:{user.pk}', action='authentication.factor_added')
