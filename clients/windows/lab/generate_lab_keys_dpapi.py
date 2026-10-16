"""R44: create ephemeral X25519 keys, seal with Windows DPAPI before any disk write.

Disposable GitHub Windows CI ONLY. DPAPI LocalMachine is not an access-control
boundary by itself; the PowerShell staging step sets NTFS ACLs before use.
This is NOT a production key vault and does not use user/Oracle keys.
"""
import ctypes
import os
from ctypes import wintypes
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding, PrivateFormat, PublicFormat, NoEncryption,
)


class DATA_BLOB(ctypes.Structure):
    _fields_ = [
        ("cbData", wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_ubyte)),
    ]


_CONTEXT = b"OracleProxy.R44.CI.NativeMemory.v1"
_CRYPTPROTECT_LOCAL_MACHINE = 0x4
_CRYPTPROTECT_UI_FORBIDDEN = 0x1


def _seal(raw: bytearray) -> bytes:
    crypt = ctypes.WinDLL("crypt32", use_last_error=True)
    crypt.CryptProtectData.argtypes = (
        ctypes.POINTER(DATA_BLOB), wintypes.LPCWSTR,
        ctypes.POINTER(DATA_BLOB), ctypes.c_void_p, ctypes.c_void_p,
        wintypes.DWORD, ctypes.POINTER(DATA_BLOB),
    )
    crypt.CryptProtectData.restype = wintypes.BOOL
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.LocalFree.argtypes = (ctypes.c_void_p,)
    kernel.LocalFree.restype = ctypes.c_void_p

    source = (ctypes.c_ubyte * len(raw)).from_buffer(raw)
    entropy_bytes = (ctypes.c_ubyte * len(_CONTEXT)).from_buffer_copy(_CONTEXT)
    input_blob = DATA_BLOB(len(raw), source)
    entropy_blob = DATA_BLOB(len(_CONTEXT), entropy_bytes)
    output_blob = DATA_BLOB()
    try:
        if not crypt.CryptProtectData(
            ctypes.byref(input_blob), None, ctypes.byref(entropy_blob),
            None, None,
            _CRYPTPROTECT_LOCAL_MACHINE | _CRYPTPROTECT_UI_FORBIDDEN,
            ctypes.byref(output_blob),
        ):
            raise OSError("DPAPI protection failed, error code " +
                          str(ctypes.get_last_error()))
        if output_blob.cbData <= len(raw) or output_blob.cbData > 4096:
            raise RuntimeError("Invalid sealed DPAPI blob length")
        return ctypes.string_at(output_blob.pbData, output_blob.cbData)
    finally:
        ctypes.memset(ctypes.addressof(source), 0, len(raw))
        if output_blob.pbData:
            ctypes.memset(output_blob.pbData, 0, output_blob.cbData)
            kernel.LocalFree(output_blob.pbData)


def main() -> None:
    if (os.name != "nt" or os.environ.get("GITHUB_ACTIONS") != "true"
            or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"
            or os.environ.get("RUNNER_OS") != "Windows"
            or os.environ.get("ORACLE_R44_DPAPI_TEST") != "CI_ONLY"):
        raise RuntimeError("R44_REFUSED: disposable Windows runner only")
    target = Path(os.environ["WG_LAB_EPHEMERAL_KEY_FILE"]).resolve()
    root = Path(os.environ["RUNNER_TEMP"]).resolve()
    if target.parent != root or target.name != "wg-r44-session.dpapi":
        raise RuntimeError("R44_REFUSED: sealed file must stay inside runner temp")

    alice = X25519PrivateKey.generate()
    bob = X25519PrivateKey.generate()
    raw = bytearray(
        alice.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        + bob.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        + bob.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        + alice.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    )
    if len(raw) != 128:
        raise RuntimeError("Invalid ephemeral key length")
    try:
        encrypted = _seal(raw)
    finally:
        for i in range(len(raw)):
            raw[i] = 0
    # No plaintext temp file, no key stdout, exact one-time create.
    with os.fdopen(os.open(str(target), os.O_CREAT | os.O_EXCL | os.O_WRONLY,
                           0o600), "wb") as handle:
        handle.write(encrypted)
        handle.flush()
        os.fsync(handle.fileno())
    print("R44_DPAPI_SEALED_KEYS_PASS: fresh ephemeral material sealed before disk write")


if __name__ == "__main__":
    main()
