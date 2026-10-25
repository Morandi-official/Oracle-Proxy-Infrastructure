"""Publish a hash-pinned account-free QUIC version-negotiation diagnostic."""
import importlib.util
from pathlib import Path

SOURCE=Path(__file__).resolve().parents[2]/'clients/windows/diagnostics/Test-QuicUdpReturn.ps1'
DIGEST='e700eab9cf46f5aa7a04398f54dfc97b0982307ad454d497276d327a442f6a52'
NAME='Test-QuicUdpReturn-'+DIGEST[:12]+'.ps1'
ROOT=Path('/var/lib/oracle-proxy-downloads/diagnostics')
_spec=importlib.util.spec_from_file_location('pinned_udp_control_publisher',Path(__file__).with_name('publish_port_diagnostic.py'))
_module=importlib.util.module_from_spec(_spec);_spec.loader.exec_module(_module)
_module.SOURCE=SOURCE;_module.DIGEST=DIGEST;_module.NAME=NAME


def install(source=SOURCE,root=ROOT):
    return _module.install(source=source,root=root)


def verify_public():
    return _module.verify_public()
