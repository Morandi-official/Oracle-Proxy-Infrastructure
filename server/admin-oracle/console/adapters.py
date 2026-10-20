from cryptography.fernet import Fernet
from django.conf import settings
from django.http import HttpResponseForbidden
from allauth.account.adapter import DefaultAccountAdapter
from allauth.account.auth_backends import AuthenticationBackend
from allauth.core.exceptions import ImmediateHttpResponse
from allauth.mfa.adapter import DefaultMFAAdapter
from allauth.socialaccount.adapter import DefaultSocialAccountAdapter


class ClosedAccountAdapter(DefaultAccountAdapter):
    def is_open_for_signup(self, request):
        return False  # No local/password signups or recovery bypass.


class GitHubSessionBackend(AuthenticationBackend):
    def authenticate(self, request, **credentials):
        return None  # OAuth completes through allauth; passwords never authenticate.


class GitHubAllowlistAdapter(DefaultSocialAccountAdapter):
    @staticmethod
    def permitted(sociallogin):
        return (sociallogin.account.provider == 'github' and
                sociallogin.account.uid in settings.ADMIN_GITHUB_IDS)

    def pre_social_login(self, request, sociallogin):
        if not self.permitted(sociallogin):
            raise ImmediateHttpResponse(HttpResponseForbidden('Administrator GitHub account required'))

    def is_open_for_signup(self, request, sociallogin):
        return self.permitted(sociallogin)


class EncryptedMFAAdapter(DefaultMFAAdapter):
    def encrypt(self, text):
        return Fernet(settings.MFA_ENCRYPTION_KEY.encode()).encrypt(text.encode()).decode()

    def decrypt(self, encrypted_text):
        return Fernet(settings.MFA_ENCRYPTION_KEY.encode()).decrypt(encrypted_text.encode()).decode()

    def can_delete_authenticator(self, authenticator):
        return False  # Recovery is an attended host-administrator operation.

    def send_notification_mail(self, *args, **kwargs):
        return None  # GitHub-only identity needs no SMTP or emailed secrets.
