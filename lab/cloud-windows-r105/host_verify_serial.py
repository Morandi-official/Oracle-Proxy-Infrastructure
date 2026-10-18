"""R105 host-side strict verifier for future no-network Windows guest serial witness.

A guest COM1 response corroborates, but NEVER replaces, offline EVTX Windows
Kernel-General/EventLog witness, guest reboot or WFP/packet measurements.
No guest executable is installed or run by R105 CI.
"""
from __future__ import annotations
import re
import secrets

CHALLENGE = re.compile(r"^OPX-R105-CHAL/1/([A-F0-9]{64})$")
RESPONSE = re.compile(r"^OPX-R105-READONLY/1/([A-F0-9]{64})/([0-9]{5})/(SYSTEM|NOT_SYSTEM)$")
MAX_BYTES = 128

def generate_one_time_challenge() -> str:
    return "OPX-R105-CHAL/1/" + secrets.token_hex(32).upper()

def evaluate(challenge: str, response: str) -> tuple[bool,str]:
    """No external actions; no arbitrary command execution or trust promotion."""
    if not isinstance(challenge,str) or not isinstance(response,str) or (
        len(challenge.encode("utf-8")) > MAX_BYTES or
        len(response.encode("utf-8")) > MAX_BYTES
    ):
        return False, "R105_REFUSED_UNBOUNDED_SERIAL_RECORD"
    req=CHALLENGE.fullmatch(challenge)
    res=RESPONSE.fullmatch(response)
    if not req or not res:
        return False, "R105_REFUSED_INVALID_READONLY_PROTOCOL"
    if not secrets.compare_digest(req.group(1),res.group(1)):
        return False, "R105_REFUSED_NONCE_REPLAY_OR_MISMATCH"
    if res.group(3)!="SYSTEM":
        return False, "R105_REFUSED_GUEST_NOT_LOCALSYSTEM"
    build=int(res.group(2))
    if build < 19041 or build > 99999:
        return False, "R105_REFUSED_UNSUPPORTED_WINDOWS_BUILD"
    return True, "R105_GUEST_OS_REPORTED_SYSTEM_NONCE_CORROBORATION_ONLY"

def release_approved_from_serial(_challenge: str, _response: str) -> bool:
    # Deliberately impossible even when the one-time guest response passes.
    return False
