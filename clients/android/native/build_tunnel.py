"""Build the two Android LP64 WireGuard libraries, retaining the pinned AAR's public API."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tarfile
import tempfile
import urllib.request
import zipfile

SOURCE = "09b75c2bd37f749e2a8c85876394854113c74be7"
ARCHIVE_SHA = "63dc6fef19010a87a56f28b1dd41227a8ef3d282c6d6ce76182a5afec1140f7a"
AAR_SHA = "2b9c16db026496123e4db695d26d03d1958a201096c7c4c89b21077dc70f3119"
NDK = "27.0.12077973"
GO = "go1.24.3"
HERE = Path(__file__).resolve().parent
TARGETS = {"arm64-v8a": ("arm64", "aarch64"), "x86_64": ("amd64", "x86_64")}
ALL_ABIS = {*TARGETS, "armeabi-v7a", "x86"}
JNI = {f"Java_com_wireguard_android_backend_GoBackend_wg{name}" for name in
       ("TurnOn", "TurnOff", "Version", "GetConfig", "GetSocketV4", "GetSocketV6")}
TELEMETRY = "Java_org_morandi_proxy_ProxyVpnService_carrierReceiveOptionsForTest"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def run(arguments, cwd, env=None):
    subprocess.run(arguments, cwd=cwd, env=env, check=True)


def output(arguments, cwd, env=None):
    return subprocess.check_output(arguments, cwd=cwd, env=env, text=True).strip()


def get_source(cache):
    cache.mkdir(parents=True, exist_ok=True)
    archive = cache / (SOURCE + ".tar.gz")
    if archive.is_file() and digest(archive.read_bytes()) == ARCHIVE_SHA:
        return archive
    url = f"https://codeload.github.com/WireGuard/wireguard-android/tar.gz/{SOURCE}"
    with urllib.request.urlopen(url, timeout=90) as response:
        data = response.read(8 * 1024 * 1024)
    if digest(data) != ARCHIVE_SHA:
        raise ValueError("WireGuard Android source archive checksum mismatch")
    with tempfile.NamedTemporaryFile(dir=cache, delete=False) as new:
        new.write(data)
    os.replace(new.name, archive)
    return archive


def extract_source(archive, module):
    prefix = f"wireguard-android-{SOURCE}/"
    names = ("api-android.go", "jni.c", "go.mod", "go.sum", "goruntime-boottime-over-monotonic.diff")
    with tarfile.open(archive, "r:gz") as source:
        for name in names:
            (module / name).write_bytes(source.extractfile(prefix + "tunnel/tools/libwg-go/" + name).read())
        return source.extractfile(prefix + "COPYING").read()


def check_library(readelf, library, target, work):
    text = output([readelf, "--wide", "--dyn-syms", "--program-headers", "--file-header", "--dynamic", library], work)
    names = {line.split()[-1] for line in text.splitlines() if "Java_" in line and " UND " not in line}
    segments = [line.split() for line in text.splitlines() if line.lstrip().startswith("LOAD ")]
    machine = "AArch64" if target == "arm64" else "X86-64"
    if (names != JNI | {TELEMETRY} or not segments or not all(int(s[-1], 16) >= 16384 for s in segments)
            or not any("Machine:" in s and machine.lower() in s.lower() for s in text.splitlines())
            or not any("SONAME" in s and "[libwg-go.so]" in s for s in text.splitlines())):
        raise ValueError(f"Unexpected ABI, JNI exports, SONAME or page size for {target}")


def build(args):
    aar, ndk, destination = args.aar.resolve(), args.ndk.resolve(), args.destination.resolve()
    if digest(aar.read_bytes()) != AAR_SHA:
        raise ValueError("Unexpected upstream WireGuard tunnel AAR")
    if f"Pkg.Revision = {NDK}" not in (ndk / "source.properties").read_text().splitlines():
        raise ValueError(f"Install Android NDK {NDK}")
    host = {"Linux": "linux-x86_64", "Windows": "windows-x86_64", "Darwin": "darwin-x86_64"}[platform.system()]
    bin_dir = ndk / "toolchains" / "llvm" / "prebuilt" / host / "bin"
    exe = ".exe" if os.name == "nt" else ""
    go_env = dict(os.environ, GOTOOLCHAIN=GO, GOWORK="off", GOENV="off", GOFLAGS="")
    compiler = shutil.which("go")
    if not compiler:
        raise ValueError(f"Install {GO} or a Go installation with toolchain selection")
    version, goroot = output([compiler, "env", "GOVERSION", "GOROOT"], HERE, go_env).splitlines()
    if version != GO:
        raise ValueError(f"Expected {GO}")
    archive = get_source(args.cache)
    with tempfile.TemporaryDirectory(prefix="proxy-wireguard-build-") as temp:
        work = Path(temp).resolve()
        module = work / "jni"
        module.mkdir()
        license_text = extract_source(archive, module)
        shutil.copyfile(HERE / "carrier_socket_android.c", module / "carrier_socket_android.c")
        # Apply the same WireGuard suspend-aware Go runtime change in a private
        # toolchain. The installed toolchain and shared Go module cache stay intact.
        private_go = work / "go"
        shutil.copytree(goroot, private_go, symlinks=os.name != "nt")
        run(["git", "init", "--quiet"], private_go)
        run(["git", "apply", "--include=src/runtime/sys_linux_amd64.s",
             "--include=src/runtime/sys_linux_arm64.s", module / "goruntime-boottime-over-monotonic.diff"], private_go)
        go_env.update(GOROOT=str(private_go), GOTOOLCHAIN="local")
        compiler = private_go / "bin" / ("go" + exe)
        run([compiler, "mod", "download"], module, go_env)
        run([compiler, "mod", "verify"], module, go_env)
        run([compiler, "mod", "vendor"], module, go_env)
        xnet = module / "vendor/golang.org/x/net"
        run(["git", "init", "--quiet"], xnet)
        run(["git", "apply", HERE / "android-recvmmsg.patch"], xnet)
        generated = {}
        for abi, (arch, triple) in TARGETS.items():
            target = f"--target={triple}-linux-android24"
            # The upstream shared library uses a DT_SONAME and 16 KiB alignment.
            env = dict(go_env, GOOS="android", GOARCH=arch, CGO_ENABLED="1",
                       CC='"' + str(bin_dir / ("clang" + exe)) + '"',
                       CGO_CFLAGS=f"{target} -O2 -fPIC -fstack-protector-strong -D_FORTIFY_SOURCE=2",
                       CGO_LDFLAGS=f"{target} -Wl,-soname,libwg-go.so -Wl,-z,max-page-size=16384 -Wl,-z,relro,-z,now -Wl,--build-id=none")
            library = work / abi / "libwg-go.so"
            library.parent.mkdir()
            run([compiler, "build", "-mod=vendor", "-buildvcs=false", "-trimpath", "-tags", "linux",
                 "-ldflags", "-X golang.zx2c4.com/wireguard/ipc.socketDirectory=/data/data/com.wireguard.android/cache/wireguard -buildid=",
                 "-buildmode=c-shared", "-o", library, "."], module, env)
            run([bin_dir / ("llvm-strip" + exe), "--strip-unneeded", library], work)
            check_library(bin_dir / ("llvm-readelf" + exe), library, arch, work)
            generated[f"jni/{abi}/libwg-go.so"] = library.read_bytes()

        with zipfile.ZipFile(aar) as original:
            native = {f"jni/{abi}/libwg-go.so" for abi in ALL_ABIS}
            if {s for s in original.namelist() if s.endswith("/libwg-go.so")} != native:
                raise ValueError("Unexpected upstream WireGuard ABI set")
            licenses = {"jni-wrapper.txt": license_text, "Go.txt": (private_go / "LICENSE").read_bytes()}
            for module_name in ("golang.zx2c4.com/wireguard", "golang.org/x/net", "golang.org/x/sys", "golang.org/x/crypto"):
                licenses[module_name.replace("/", "-") + ".txt"] = (module / "vendor" / module_name / "LICENSE").read_bytes()
            manifest = dict(wireguardAndroidRevision=SOURCE, upstreamAarSha256=AAR_SHA, go=GO, ndk=NDK,
                            androidReadPatchSha256=digest((HERE / "android-recvmmsg.patch").read_bytes()),
                            sha256={path: digest(generated.get(path) or original.read(path)) for path in sorted(native)})
            destination.parent.mkdir(parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile(dir=destination.parent, suffix=".pending", delete=False) as pending_file:
                pending = Path(pending_file.name)
            try:
                with zipfile.ZipFile(pending, "w") as derived:
                    for info in original.infolist():
                        derived.writestr(info, generated.get(info.filename) or original.read(info))
                    for name, data in {**licenses, "go.sum": (module / "go.sum").read_bytes(),
                                       "build.json": json.dumps(manifest, sort_keys=True, indent=2).encode()}.items():
                        info = zipfile.ZipInfo("assets/wireguard-native/" + name, (1980, 1, 1, 0, 0, 0))
                        derived.writestr(info, data, compress_type=zipfile.ZIP_DEFLATED)
                os.replace(pending, destination)
            finally:
                pending.unlink(missing_ok=True)


def verify_apk(args):
    with zipfile.ZipFile(args.aar) as aar, zipfile.ZipFile(args.apk) as apk:
        manifest = json.loads(aar.read("assets/wireguard-native/build.json"))
        if apk.read("assets/wireguard-native/build.json") != aar.read("assets/wireguard-native/build.json"):
            raise ValueError("APK missing WireGuard native source provenance")
        libraries = [item for item in apk.namelist() if item.startswith("lib/") and item.endswith(".so")]
        expected = {f"lib/{abi}/libwg-go.so" for abi in ALL_ABIS}
        if len(libraries) != len(expected) or set(libraries) != expected:
            raise ValueError("Unexpected APK native libraries")
        for item in libraries:
            if digest(apk.read(item)) != manifest["sha256"]["jni/" + item[4:]]:
                raise ValueError("Packaged library differs from the verified AAR: " + item)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    actions = parser.add_subparsers(dest="action", required=True)
    prepare = actions.add_parser("build")
    for name in ("aar", "ndk", "destination", "cache"):
        prepare.add_argument(name, type=Path)
    check = actions.add_parser("verify-apk")
    check.add_argument("aar", type=Path)
    check.add_argument("apk", type=Path)
    args = parser.parse_args()
    (build if args.action == "build" else verify_apk)(args)
