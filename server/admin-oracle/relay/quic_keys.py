"""Root-only generation/renewal of a fixed-host QUIC TLS certificate.

Only the public certificate is distributed through authenticated HTTPS.
No private key is logged, exported, accepted from HTTP or sent to GitHub.
"""
import datetime as dt
import grp
import os
import stat
import subprocess
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

ROOT = Path('/etc/oracle-proxy-quic')
HOST = 'vpn-admin.morandi.dpdns.org'


def certificate(key):
    now = dt.datetime.now(dt.timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, HOST)])
    return (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now-dt.timedelta(minutes=5))
            .not_valid_after(now+dt.timedelta(days=90))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(HOST)]), critical=False)
            .add_extension(x509.BasicConstraints(ca=True,path_length=0), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(key, hashes.SHA256()))


def read(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_size > 8192:
        raise ValueError('QUIC_KEY_FILE_REJECTED')
    return path.read_bytes()


def atomic(path, data, mode, gid):
    temporary = path.with_suffix(path.suffix+'.new')
    descriptor = os.open(temporary, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, mode)
    try:
        os.fchown(descriptor, 0, gid)
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, 'wb', closefd=False) as stream:
            stream.write(data); stream.flush(); os.fsync(descriptor)
        os.replace(temporary, path)
    finally: os.close(descriptor)


def ensure():
    if os.geteuid() != 0 or ROOT.is_symlink(): raise ValueError('ROOT_QUIC_KEY_OPERATION_REQUIRED')
    group = grp.getgrnam('oracle-proxy-quic').gr_gid
    ROOT.mkdir(mode=0o755, exist_ok=True)
    os.chown(ROOT, 0, group); ROOT.chmod(0o755)
    private, public = ROOT/'private.pem', ROOT/'certificate.pem'
    if private.exists():
        if private.stat().st_mode & 0o037: raise ValueError('QUIC_PRIVATE_KEY_PERMISSIONS_REJECTED')
        key = serialization.load_pem_private_key(read(private), password=None)
        if not isinstance(key, ec.EllipticCurvePrivateKey): raise ValueError('QUIC_KEY_TYPE_REJECTED')
    else:
        if public.exists(): raise ValueError('QUIC_KEY_PAIR_INCOMPLETE')
        key = ec.generate_private_key(ec.SECP256R1())
        atomic(private,key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,
                                        serialization.NoEncryption()),0o640,group)
    if public.exists():
        current = x509.load_pem_x509_certificate(read(public))
        encoding = (serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)
        if current.public_key().public_bytes(*encoding) != key.public_key().public_bytes(*encoding):
            raise ValueError('QUIC_KEY_PAIR_MISMATCH')
        if current.not_valid_after_utc > dt.datetime.now(dt.timezone.utc)+dt.timedelta(days=7): return False
    atomic(public,certificate(key).public_bytes(serialization.Encoding.PEM),0o644,group)
    return True


if __name__ == '__main__':
    if ensure():
        subprocess.run(['systemctl','try-restart','oracle-proxy-quic.service'],check=False,
                       stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    print('QUIC_CERTIFICATE=READY')
