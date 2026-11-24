"""Fetch exact official Linux artifacts without installing host packages."""

import hashlib
import json
import os
import platform
import re
import sys
import tarfile
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


HEADSCALE = {
    "amd64": "e827fc9b12d958bc95b081c4401dd63f8e0471d025b45b508535a920532150a8",
    "arm64": "4357b38ac63c1e425f190819fd2ee078f13e01a6d7559b15811154e2475df5e4",
}
TAILSCALE = {
    "amd64": (
        "879983961818dbc4b3a1985241784bf3c8f88d29a90b0c7a094fb46c46889e16",
        58_173_751,
        {
            "tailscale": (34_347_181, "27727240e017011fa068c4fe81c8373c2a3acb281659f3541b2bd1800e8bed30"),
            "tailscaled": (43_926_944, "feb7193e43600f6c2e70e746dd6692dc3117d61d60bc4312cbc32304eaf4df78"),
        },
    ),
    "arm64": (
        "3ef47d79a9faa0c2635ea2e30a85eb88daa6071a2439e968541b1fdc13258228",
        52_987_374,
        {
            "tailscale": (31_912_897, "7a5f41792c1a32dc63ee2759c93d55ac353ae0ae25414c04ba4bec4f4e2d46c3"),
            "tailscaled": (40_983_898, "ca9d654996582ba0e7f190ff15ce2da84d539cf7ce366a92548516cd74402ff7"),
        },
    ),
}
USER_AGENT = "Oracle-Proxy-Tailnet-Stage/1"


class PublicRedirect(HTTPRedirectHandler):
    def __init__(self, hosts):
        self.hosts = hosts

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        url = urlsplit(newurl)
        if url.scheme != "https" or url.hostname not in self.hosts or url.port not in (None, 443) or url.username:
            raise ValueError("UNTRUSTED_ASSET_REDIRECT")
        # The anonymous registry bearer is scoped to ghcr.io.
        if newurl == req.full_url:
            raise ValueError("REPEATED_ASSET_REDIRECT")
        return Request(newurl, headers={"User-Agent": USER_AGENT})


def copy_verified(source, destination, size_limit, sha256):
    digest = hashlib.sha256()
    count = 0
    with destination.open("xb") as output:
        while chunk := source.read(1024 * 1024):
            count += len(chunk)
            if count > size_limit:
                raise ValueError("TAILNET_ARTIFACT_TOO_LARGE")
            digest.update(chunk)
            output.write(chunk)
    if digest.hexdigest() != sha256:
        raise ValueError("TAILNET_ARTIFACT_DIGEST_MISMATCH")


def fetch(output):
    architecture = {"x86_64": "amd64", "aarch64": "arm64"}.get(platform.machine())
    if architecture is None:
        raise ValueError("UNSUPPORTED_TAILNET_ARCHITECTURE")
    github = build_opener(PublicRedirect({"release-assets.githubusercontent.com", "github.com"}))
    url = f"https://github.com/juanfont/headscale/releases/download/v0.29.7/headscale_0.29.7_linux_{architecture}"
    with github.open(Request(url, headers={"User-Agent": USER_AGENT}), timeout=30) as source:
        copy_verified(source, output / "headscale", 100 * 1024 * 1024, HEADSCALE[architecture])

    ghcr = build_opener(PublicRedirect({"ghcr.io", "pkg-containers.githubusercontent.com"}))
    token_url = "https://ghcr.io/token?scope=repository%3Atailscale%2Ftailscale%3Apull&service=ghcr.io"
    with ghcr.open(Request(token_url, headers={"User-Agent": USER_AGENT}), timeout=15) as source:
        token = json.loads(source.read(32768))["token"]
    if not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9._=+/-]{16,16384}", token):
        raise ValueError("INVALID_REGISTRY_TOKEN")
    digest, layer_size, binaries = TAILSCALE[architecture]
    blob = Request("https://ghcr.io/v2/tailscale/tailscale/blobs/sha256:" + digest,
                   headers={"User-Agent": USER_AGENT})
    blob.add_unredirected_header("Authorization", "Bearer " + token)
    archive = output / "tailscale-layer.tar.gz"
    with ghcr.open(blob, timeout=30) as source:
        copy_verified(source, archive, layer_size, digest)
    with tarfile.open(archive, "r:gz") as layer:
        for name, (size, binary_digest) in binaries.items():
            matches = [member for member in layer.getmembers() if member.name == "/usr/local/bin/" + name]
            if len(matches) != 1 or not matches[0].isreg() or matches[0].size != size:
                raise ValueError("INVALID_TAILNET_ARCHIVE")
            with layer.extractfile(matches[0]) as source:
                copy_verified(source, output / name, size, binary_digest)
    archive.unlink()
    for name in ("headscale", *binaries):
        (output / name).chmod(0o755)


if __name__ == "__main__":
    os.umask(0o077)
    try:
        fetch(Path(sys.argv[1]).resolve(strict=True))
    except Exception:
        # Upstream errors and URLs may contain registry authorization.
        print("TAILNET_OFFICIAL_ASSET_FETCH_FAILED", file=sys.stderr)
        raise SystemExit(1) from None
