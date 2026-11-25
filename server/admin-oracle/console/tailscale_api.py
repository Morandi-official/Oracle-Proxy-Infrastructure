"""Native client API for the new Tailscale applications."""

import re

from django.contrib.auth.hashers import check_password
from django.core import signing
from django.db import DatabaseError
from django.utils.crypto import constant_time_compare, salted_hmac
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET, require_POST

from . import control
from .client_api import DUMMY_PASSWORD, native_only, payload, response, throttle
from .models import ClientAccount

SESSION_SALT = "proxy-tailscale-session-v1"
SESSION_AGE = 12 * 3600


def password_proof(account):
    return salted_hmac(SESSION_SALT + ".password", account.password, algorithm="sha256").hexdigest()


@csrf_exempt
@require_POST
def login(request):
    if not native_only(request):
        return response({"error": "INVALID_REQUEST"}, 400)
    try:
        value = payload(request, {"username", "password", "device"})
        username, password, device = (value[field] for field in ("username", "password", "device"))
        if not (isinstance(username, str) and re.fullmatch(r"[a-z0-9][a-z0-9_.-]{2,63}", username)
                and isinstance(password, str) and 1 <= len(password) <= 128
                and isinstance(device, str) and re.fullmatch(r"[a-f0-9]{64}", device)):
            return response({"error": "INVALID_CREDENTIALS"}, 401)
        if not throttle(username):
            return response({"error": "RATE_LIMITED"}, 429)
        account = ClientAccount.objects.filter(username=username).first()
        if not check_password(password, account.password if account else DUMMY_PASSWORD) or account is None:
            return response({"error": "INVALID_CREDENTIALS"}, 401)
        token = signing.dumps([str(account.user_id), device, password_proof(account)], salt=SESSION_SALT)
        return response({"token": token, "username": account.username})
    except (ValueError, TypeError):
        return response({"error": "INVALID_REQUEST"}, 400)
    except DatabaseError:
        return response({"error": "ACCOUNT_SERVICE_UNAVAILABLE"}, 503)


def profile_request(request, operation):
    if not native_only(request):
        return response({"error": "INVALID_REQUEST"}, 400)
    bearer = request.META.get("HTTP_AUTHORIZATION", "")
    if not bearer.startswith("Bearer ") or len(bearer) > 2048:
        return response({"error": "LOGIN_REQUIRED"}, 401)
    try:
        payload(request, set())
        user, device, proof = signing.loads(bearer[7:], salt=SESSION_SALT, max_age=SESSION_AGE)
        account = ClientAccount.objects.filter(user_id=user).first()
        if account is None or not constant_time_compare(proof, password_proof(account)):
            return response({"error": "LOGIN_REQUIRED"}, 401)
        return response(control.call("tailscale." + operation, "system:client-api", {"user_id": user, "device": device}))
    except signing.BadSignature:
        return response({"error": "LOGIN_REQUIRED"}, 401)
    except ValueError as error:
        code = str(error)
        status = 503 if code in ("CONTROL_UNAVAILABLE", "TAILSCALE_SERVICE_UNAVAILABLE") else 409
        return response({"error": code if re.fullmatch(r"[A-Z_]{1,80}", code) else "INVALID_REQUEST"}, status)
    except (OSError, TimeoutError, DatabaseError):
        return response({"error": "TAILSCALE_SERVICE_UNAVAILABLE"}, 503)


@csrf_exempt
@require_POST
def profile(request):
    return profile_request(request, "profile")


@csrf_exempt
@require_POST
def retry_profile(request):
    return profile_request(request, "retry_profile")


@csrf_exempt
@require_POST
def confirm(request):
    return profile_request(request, "confirm")


@csrf_exempt
@require_POST
def release(request):
    return profile_request(request, "release")


@require_GET
def ready(request):
    try:
        is_ready = control.call("tailscale.ready", "system:health", {}) == {"ready": True}
    except (OSError, ValueError):
        is_ready = False
    return response({"ready": is_ready}, 200 if is_ready else 503)
