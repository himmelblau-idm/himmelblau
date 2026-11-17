"""DDI payload construction and transient OpenPGP-to-X.509 signing."""

from contextlib import contextmanager
from dataclasses import dataclass
import datetime as dt
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import shutil
import signal
import subprocess
import tarfile
import tempfile


CONFIG = Path(__file__).resolve().parents[1] / "ddi"
ARCHITECTURES = {"amd64": ("x86-64", 62), "arm64": ("arm64", 183)}
ROOT_VERITY_SIGNATURE_TYPES = {
    "amd64": "41092b05-9fc8-4523-994f-2def0408b176",
    "arm64": "6db69de6-29f4-4758-a7a5-962190f00ce3",
}
PAYLOAD_PACKAGES = {
    "sysext": ("himmelblau", "pam-himmelblau", "nss-himmelblau", "himmelblau-broker"),
    "portable": ("himmelblau", "nss-himmelblau", "himmelblau-broker"),
}
PORTABLE_RUNTIME_PACKAGES = {
    "fedora": (
        "filesystem", "ca-certificates", "bash", "coreutils",
        "glibc-common", "grep", "shadow-utils", "util-linux-core",
        # Fedora packages the HSM helper's systemd-creds in systemd itself.
        "systemd", "tpm2-tools",
        "pinentry", "pinentry-gnome3", "xdg-utils",
    ),
}


def run(command, *, capture=False, extra_env=None, **kwargs):
    explicit_env = kwargs.pop("env", None)
    env = dict(os.environ if explicit_env is None else explicit_env)
    env.update(extra_env or {})
    for name in ("PACKAGE_SIGNING_KEY", "PACKAGE_SIGNING_PASSPHRASE"):
        env.pop(name, None)
    if explicit_env is None:
        env.pop("CLOUDSMITH_API_KEY", None)
    try:
        return subprocess.run(
            [str(arg) for arg in command], check=True,
            stdout=kwargs.pop("stdout", subprocess.PIPE if capture else None),
            env=env, **kwargs,
        )
    except subprocess.CalledProcessError as error:
        if command[0] in ("gpg", "gpgsm"):
            raise RuntimeError(f"{command[0]} failed (status {error.returncode}); see diagnostics") from None
        raise


def release_fields(text):
    result = {}
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        name, separator, value = line.partition("=")
        values = shlex.split(value)
        if not separator or len(values) > 1:
            raise ValueError("Malformed OS release metadata")
        result[name] = values[0] if values else ""
    if not result.get("ID") or result["ID"] == "_any":
        raise ValueError("DDIs require the actual build distribution ID")
    return result


def validate_elf(path, architecture):
    with path.open("rb") as stream:
        header = stream.read(20)
    if (len(header) != 20 or header[:6] != b"\x7fELF\x02\x01"
            or int.from_bytes(header[18:20], "little") != ARCHITECTURES[architecture][1]):
        raise ValueError(f"Not a {architecture} ELF64 payload: {path}")


def copy_payload(source, root, relative):
    src, dst = source / relative, root / relative
    dst.parent.mkdir(parents=True, exist_ok=True)
    if src.is_dir():
        shutil.copytree(src, dst, symlinks=True, dirs_exist_ok=True)
    else:
        shutil.copy2(src, dst, follow_symlinks=False)


def extract_package(package, destination):
    destination.mkdir(parents=True)
    if package.suffix == ".deb":
        run(["dpkg-deb", "--extract", package, destination])
    elif package.suffix == ".rpm":
        archive = destination.parent / (destination.name + ".cpio")
        with archive.open("wb") as stream:
            run(["rpm2cpio", package], stdout=stream)
        with archive.open("rb") as stream:
            run(["cpio", "--extract", "--make-directories", "--no-absolute-filenames"],
                cwd=destination, stdin=stream)
        archive.unlink()
    else:
        raise ValueError(f"Unsupported package: {package}")


def stage_sysext(packages, root, architecture):
    root.mkdir(parents=True)
    with tempfile.TemporaryDirectory(prefix="extract-", dir=root.parent) as temporary:
        for name, package in packages.items():
            source = Path(temporary) / name
            extract_package(package, source)
            if name == "himmelblau-broker":
                copy_payload(source, root, "usr/share/dbus-1/services/com.microsoft.identity.broker1.service")
                continue
            if name != "himmelblau":
                copy_payload(source, root, "usr")
                continue
            for relative in ("usr/bin/aad-tool", "usr/lib/himmelblau"):
                copy_payload(source, root, relative)
            for relative in ("usr/lib/tmpfiles.d", "usr/share/doc/himmelblau", "usr/share/man"):
                if (source / relative).is_dir():
                    copy_payload(source, root, relative)
            for path in source.glob("usr/share/locale/*/LC_MESSAGES/himmelblau.mo"):
                copy_payload(source, root, path.relative_to(source))
    for relative in ("usr/lib/systemd/system", "usr/lib/systemd/user"):
        if any((root / relative).rglob("*")):
            raise ValueError("Sysext component packages must not contain systemd units")
    for name in ("aad-tool", "pam_himmelblau.so", "libnss_himmelblau.so.2"):
        paths = list((root / "usr").rglob(name))
        if len(paths) != 1:
            raise ValueError(f"Expected exactly one {name} in the sysext")
        validate_elf(paths[0], architecture)


def extension_release(root, release, name, version, architecture):
    fields = {
        "ID": release["ID"], "ARCHITECTURE": ARCHITECTURES[architecture][0],
        "SYSEXT_SCOPE": "system", "SYSEXT_ID": "himmelblau", "SYSEXT_VERSION_ID": version,
    }
    if release.get("VERSION_ID"):
        fields["VERSION_ID"] = release["VERSION_ID"]
    elif release.get("SYSEXT_LEVEL"):
        fields["SYSEXT_LEVEL"] = release["SYSEXT_LEVEL"]
    path = root / "usr/lib/extension-release.d" / (
        "extension-release." + name.removesuffix(".sysext.raw").partition("_")[0]
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(f"{key}={json.dumps(value)}\n" for key, value in fields.items()))


def resolve_in_root(root, path):
    relative = Path(path.lstrip("/"))
    for _ in range(40):
        for index in range(len(relative.parts)):
            prefix = Path(*relative.parts[:index + 1])
            link = root / prefix
            if not link.is_symlink():
                continue
            target = Path(os.readlink(link))
            resolved = target.relative_to("/") if target.is_absolute() else prefix.parent / target
            relative = Path(os.path.normpath(resolved / Path(*relative.parts[index + 1:])))
            if ".." in relative.parts:
                raise ValueError(f"Package symlink escapes installroot: {path}")
            break
        else:
            return root / relative
    raise ValueError(f"Package symlink loop: {path}")


def configure_portable_units(root):
    version = run([
        "rpm", "--root", root, "--query", "--queryformat", "%{VERSION}\n", "systemd",
    ], capture=True).stdout.decode("ascii").strip()
    if not re.fullmatch(r"[0-9][A-Za-z0-9._+~^]*", version):
        raise ValueError(f"Invalid installed systemd package version: {version!r}")
    # Use RPM ordering so prereleases such as 263~rc1 remain below 263.
    legacy = run([
        "rpm", "--eval",
        '%{lua:print(rpm.vercmp(os.getenv("HIMMELBLAU_DDI_SYSTEMD_VERSION"), "263") < 0 and "1" or "0")}',
    ], capture=True, extra_env={"HIMMELBLAU_DDI_SYSTEMD_VERSION": version}).stdout.strip()
    if legacy not in (b"0", b"1"):
        raise ValueError(f"Invalid systemd package version comparison result: {legacy!r}")
    for name in ("himmelblaud.service", "himmelblaud-tasks.service"):
        path = resolve_in_root(root, "/usr/lib/systemd/system/" + name)
        with path.open("r+") as unit:
            unit.seek(0, os.SEEK_END)
            unit.write(
                "\n[Service]\n"
                "Environment=SYSTEMD_NSS_SERVER_SIDE_NSS=1\n"
                "BindReadOnlyPaths=-/etc/nsswitch.conf\n"
            )
            # Needed until nss-systemd supports querying other databases from inside the image
            if legacy == b"1":
                unit.write("BindReadOnlyPaths=/etc/passwd /etc/group\n")
            if name == "himmelblaud-tasks.service":
                unit.write("BindPaths=-/var/lib/AccountsService/\n")


def stage_portable(packages, root, fedora, architecture, version):
    dnf = [
        "dnf", "--assumeyes", "--use-host-config", f"--installroot={root}",
        f"--releasever={fedora.removeprefix('fedora')}",
        "--setopt=install_weak_deps=False", "--setopt=localpkg_gpgcheck=False",
        "--setopt=tsflags=nodocs",
    ]
    run(dnf + [
        "install", *[packages[name] for name in PAYLOAD_PACKAGES["portable"]],
        *PORTABLE_RUNTIME_PACKAGES["fedora"],
    ])
    run(dnf + ["clean", "all"])
    for name in ("himmelblaud", "himmelblaud_tasks", "himmelblau_broker"):
        validate_elf(resolve_in_root(root, "/usr/sbin/" + name), architecture)
    for name in ("aad-tool", "pinentry-gnome3"):
        validate_elf(root / "usr/bin" / name, architecture)
    for relative in (
        "usr/bin/pinentry",
        "usr/bin/xdg-open",
        "usr/lib/systemd/system/himmelblaud.service",
        "usr/lib/systemd/system/himmelblaud-tasks.service",
        "usr/lib/systemd/system/himmelblau-hsm-pin-init.service",
        "usr/lib/systemd/user/himmelblau-broker.service",
        "usr/share/dbus-1/services/com.microsoft.identity.broker1.service",
    ):
        if not (root / relative).is_file():
            raise ValueError(f"Missing portable runtime file: {relative}")
    configure_portable_units(root)
    for relative in (
        "proc", "sys", "dev", "run", "tmp", "var/tmp", "home",
        "run/himmelblaud", "etc/himmelblau", "etc/krb5.conf.d",
        "var/lib/himmelblaud", "var/cache/himmelblaud",
        "var/lib/private/himmelblaud", "var/cache/private/himmelblaud",
        "var/cache/nss-himmelblau", "var/cache/himmelblau-policies",
        "var/lib/AccountsService",
    ):
        (root / relative).mkdir(parents=True, exist_ok=True)
    for relative in ("etc/machine-id", "etc/resolv.conf", "etc/nsswitch.conf"):
        path = root / relative
        path.unlink(missing_ok=True)
        path.touch()
    os_release = resolve_in_root(root, "/usr/lib/os-release")
    release = release_fields(os_release.read_text())
    if release["ID"] != "fedora" or release.get("VERSION_ID") != fedora.removeprefix("fedora"):
        raise ValueError(f"Portable root does not match {fedora}")
    with os_release.open("a") as stream:
        stream.write(
            '\nPORTABLE_PREFIXES="himmelblaud himmelblau-hsm-pin-init himmelblau-broker himmelblau-compliance-check"\n'
            "PORTABLE_SCOPE=any\nIMAGE_ID=himmelblau\n"
            f"IMAGE_VERSION={json.dumps(version)}\nARCHITECTURE={ARCHITECTURES[architecture][0]}\n"
        )


def native_library_directory(architecture):
    libdir = Path(run(["pkg-config", "--variable=libdir", "pam"], capture=True).stdout.decode().strip())
    if not libdir.is_absolute():
        raise ValueError("Native PAM pkg-config must specify an absolute libdir")
    libdir = libdir.resolve()
    validate_elf(libdir / "security/pam_permit.so", architecture)
    relative = libdir.relative_to("/")
    if not relative.parts or relative.parts[0] != "usr":
        raise ValueError("Native sysext builds require a /usr-merged distribution")
    return relative


def stage_native(source, root, architecture):
    env = os.environ.copy()
    env["CARGO_HOME"] = str(source / "target/cargo-home")
    env["CARGO_TARGET_DIR"] = str(source / "target")
    env["HIMMELBLAU_ALLOW_MISSING_SELINUX"] = "1"
    run([
        "cargo", "build", "--release", "--locked", "--features=himmelblau_unix_common/tpm",
        "-p", "aad-tool", "-p", "pam_himmelblau", "-p", "nss_himmelblau",
    ], cwd=source, env=env)
    libdir = native_library_directory(architecture)
    for name, relative in {
        "aad-tool": Path("usr/bin/aad-tool"),
        "libpam_himmelblau.so": libdir / "security/pam_himmelblau.so",
        "libnss_himmelblau.so": libdir / "libnss_himmelblau.so.2",
    }.items():
        binary = source / "target/release" / name
        validate_elf(binary, architecture)
        linked = run(["ldd", binary], capture=True).stdout.decode()
        if "not found" in linked:
            raise ValueError(f"Unresolved native dependencies for {name}: {linked}")
        run(["strip", "--strip-unneeded", binary])
        destination = root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(binary, destination)
        destination.chmod(0o755)
    config = source / "target/ddi-himmelblau.conf"
    manpages = root / "usr/share/man"
    shutil.copytree(source / "man", manpages, symlinks=True)
    run([
        "python3", source / "src/common/scripts/gen_param_code.py",
        "--gen-conf-example", "--conf-example-output", config,
        "--gen-man", "--man-output", manpages / "man5/himmelblau.conf.5",
    ], cwd=source)
    for original, relative in (
        (config, "usr/lib/himmelblau/himmelblau.conf"),
        (source / "README.md", "usr/share/doc/himmelblau/README"),
        (source / "src/nss/src/nss-himmelblau.tmpfiles.conf", "usr/lib/tmpfiles.d/nss-himmelblau.conf"),
        (source / "src/nss/src/update-nss", "usr/share/nss-himmelblau/update-nss"),
        (source / "src/broker/platform/com.microsoft.identity.broker1.service",
         "usr/share/dbus-1/services/com.microsoft.identity.broker1.service"),
    ):
        destination = root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(original, destination)
    catalogs = list((source / "target/release/locale").glob("*/LC_MESSAGES/himmelblau.mo"))
    if not catalogs:
        raise ValueError("Native build produced no Himmelblau translation catalogs")
    for catalog in catalogs:
        destination = root / "usr/share/locale" / catalog.relative_to(source / "target/release/locale")
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(catalog, destination)


def make_payload(root, output):
    run(["tar", "--create", "--file", output, "--format=posix", "--numeric-owner",
         "--owner=0", "--group=0", "--xattrs", "--acls", "--directory", root, "."])


def select_rsa_key(listing, selector=""):
    keys, current = [], None
    for line in listing.splitlines():
        fields = line.split(":")
        if fields[0] in ("sec", "ssb"):
            current = {"algorithm": fields[3], "validity": fields[1],
                       "expires": fields[6], "capabilities": fields[11]}
            keys.append(current)
        elif current is not None and fields[0] in ("fpr", "grp"):
            current[fields[0]] = fields[9]
    exact = selector.removeprefix("0x").removesuffix("!").upper()
    if exact and not re.fullmatch(r"[0-9A-F]{16,64}", exact):
        raise ValueError("PACKAGE_SIGNING_KEY_ID must be a key ID or fingerprint")
    candidates = [
        key for key in keys if key["algorithm"] in ("1", "3")
        and "s" in key["capabilities"] and "D" not in key["capabilities"]
        and key["validity"] not in ("r", "e", "d")
        and (not int(key["expires"] or 0) or int(key["expires"]) > dt.datetime.now().timestamp())
        and "fpr" in key and "grp" in key
        and (not exact or key["fpr"].endswith(exact))
    ]
    if len(candidates) != 1:
        raise ValueError("Select exactly one valid RSA package signing key with PACKAGE_SIGNING_KEY_ID")
    return candidates[0]


@dataclass
class SigningMaterial:
    private_key: Path
    certificate: Path
    fingerprint: str
    gpg_home: Path | None = None
    passphrase_file: Path | None = None


@contextmanager
def signing_material(work, env=None):
    env = os.environ if env is None else env
    if not env.get("PACKAGE_SIGNING_KEY"):
        raise ValueError("PACKAGE_SIGNING_KEY must export the existing OpenPGP RSA package signing key")
    passphrase = env.get("PACKAGE_SIGNING_PASSPHRASE", "").encode() + b"\n"
    with tempfile.TemporaryDirectory(prefix="ddi-signing-", dir=work) as temporary:
        private = Path(temporary)
        home = private / "gnupg"
        home.mkdir(mode=0o700)
        agent_pid = None
        try:
            agent = run(["gpg-connect-agent", "--homedir", home, "GETINFO pid", "/bye"],
                        capture=True).stdout.decode()
            agent_pid = int(next(line[2:] for line in agent.splitlines() if line.startswith("D ")))
            gpg = ["gpg", "--homedir", home, "--batch", "--yes", "--pinentry-mode=loopback"]
            # GPG import needs a passphrase on some versions. Keep it off argv
            # and use a separate descriptor from the OpenPGP input stream.
            password = private / "passphrase"
            password.touch(mode=0o600)
            password.write_bytes(passphrase)
            run(gpg + ["--passphrase-file", password, "--import"],
                input=env["PACKAGE_SIGNING_KEY"].encode())
            listing = run(gpg + ["--with-colons", "--with-keygrip", "--list-secret-keys"],
                          capture=True).stdout.decode()
            key = select_rsa_key(listing, env.get("PACKAGE_SIGNING_KEY_ID", ""))
            fingerprint = key["fpr"]
            serial = hashlib.sha256(fingerprint.encode()).hexdigest()[:38]
            expiry = (
                dt.datetime.fromtimestamp(int(key["expires"]), dt.timezone.utc)
                if int(key["expires"] or 0)
                else dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=3650)
            )
            request = private / "certificate.conf"
            # Stable signer identity allows the same trusted RSA key to verify
            # signatures made with later ephemeral certificates.
            request.write_text(
                f"Key-Type: RSA\nKey-Grip: {key['grp']}\nKey-Usage: sign\n"
                f"Name-DN: CN=Himmelblau DDI {fingerprint}\n"
                f"Issuer-DN: CN=Himmelblau DDI {fingerprint}\nSerial: {serial}\n"
                f"Not-After: {expiry.strftime('%Y%m%dT%H%M%S')}\nHash-Algo: SHA256\n%commit\n"
            )
            gpgsm = ["gpgsm", "--homedir", home, "--batch", "--yes",
                     "--pinentry-mode=loopback", "--passphrase-fd=0"]
            certificate, pem = private / "certificate.crt", private / "private.pem"
            run(gpgsm + ["--armor", "--output", certificate, "--generate-key", request], input=passphrase)
            run(gpgsm + ["--import", certificate], input=passphrase)
            pem.touch(mode=0o600)
            run(gpgsm + ["--armor", "--output", pem, "--export-secret-key-p8", "&" + key["grp"]],
                input=passphrase)
            run(["openssl", "pkey", "-in", pem, "-check", "-noout"])
            yield SigningMaterial(pem, certificate, fingerprint, home, password)
        finally:
            if agent_pid is not None:
                try:
                    os.kill(agent_pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass


def sign_detached(source, signature, signing):
    if signing.gpg_home is None or signing.passphrase_file is None:
        raise ValueError("OpenPGP signing material is required for the sysupdate manifest")
    run([
        "gpg", "--homedir", signing.gpg_home, "--batch", "--yes",
        "--pinentry-mode=loopback", "--passphrase-file", signing.passphrase_file,
        "--local-user", signing.fingerprint + "!", "--detach-sign",
        "--output", signature, source,
    ])
    signature.chmod(0o644)


def extract_payload(payload, root):
    if payload.is_symlink() or not payload.is_file():
        raise ValueError("Expected a regular payload archive")
    try:
        with tarfile.open(payload, "r:") as archive:
            members = archive.getmembers()
    except tarfile.TarError as error:
        raise ValueError(f"Invalid payload archive: {error}") from error
    paths = {PurePosixPath(member.name): member for member in members}
    if len(paths) != len(members):
        raise ValueError("Duplicate payload archive paths")
    symlinks = {path for path, member in paths.items() if member.issym()}
    for path, member in paths.items():
        if (path.is_absolute() or ".." in path.parts
                or (not path.parts and not member.isdir())
                or any(parent in symlinks for parent in path.parents)):
            raise ValueError(f"Unsafe payload archive path: {member.name}")
        if member.islnk():
            target = paths.get(PurePosixPath(member.linkname))
            if target is None or not target.isfile():
                raise ValueError(f"Unsafe payload hardlink: {member.name}")
        elif not (member.isdir() or member.isfile() or member.issym()):
            raise ValueError(f"Unsupported payload archive entry: {member.name}")
    # Absolute symlinks are valid inside an OS image, but archive entries may
    # never traverse them. Extract only after checking the complete hierarchy.
    root.mkdir()
    run(["tar", "--extract", "--file", payload, "--directory", root,
         "--no-same-owner", "--same-permissions", "--xattrs", "--xattrs-include=*", "--acls"])


# Workaround for old systemd-repart.
# TODO: drop once GHA CI host moves to Ubuntu 26.04
def ensure_signature_read_only(output, architecture):
    table = json.loads(run(["sfdisk", "--json", output], capture=True).stdout)["partitiontable"]
    if table["label"] != "gpt":
        raise ValueError("A signed DDI must have a GPT partition table")
    signatures = [
        partition for partition in table["partitions"]
        if partition["type"].lower() == ROOT_VERITY_SIGNATURE_TYPES[architecture]
    ]
    if len(signatures) != 1:
        raise ValueError("Expected exactly one root verity signature partition")
    signature = signatures[0]
    attributes = signature.get("attrs", "").replace("GUID:", "").replace(",", " ").split()
    if "60" in attributes:
        return
    number = re.fullmatch(re.escape(table["device"]) + r"p?([1-9][0-9]*)", signature["node"])
    if number is None:
        raise ValueError("Cannot determine the verity signature partition number")
    command = ["sfdisk", "--part-attrs", output, number[1]]
    run(command + [" ".join([*attributes, "60"])])
    updated = run(command, capture=True).stdout.decode().replace("GUID:", "").replace(",", " ").split()
    if "60" not in updated:
        raise RuntimeError("Failed to set the verity signature partition read-only flag")


def sign_image(root, output, architecture, signing, kind):
    if kind not in ("portable", "sysext"):
        raise ValueError(f"Unsupported DDI kind: {kind}")
    if kind == "sysext":
        certificate = resolve_in_root(root, "/usr/lib/verity.d/himmelblau.crt")
        certificate.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(signing.certificate, certificate)
        certificate.chmod(0o644)
    run([
        "systemd-repart", "--no-pager", f"--make-ddi={kind}",
        "--dry-run=no", "--offline=yes", "--sector-size=512",
        f"--architecture={ARCHITECTURES[architecture][0]}", f"--copy-source={root}",
        f"--private-key={signing.private_key}", f"--certificate={signing.certificate}", output,
    ], extra_env={"SYSTEMD_REPART_MKFS_OPTIONS_EROFS": "--all-root -zlz4hc"})
    ensure_signature_read_only(output, architecture)
