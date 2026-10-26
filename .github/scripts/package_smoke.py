#!/usr/bin/env python3
"""Build candidate packages and check their services in disposable systemd containers."""

import argparse
import copy
import importlib.util
import inspect
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
TARGETS = {
    "ubuntu26.04": ("ubuntu24.04", "docker.io/ubuntu:26.04", "deb"),
    "fedora44": ("fedora43", "docker.io/fedora:44", "rpm"),
}
PACKAGES = {"himmelblau", "nss-himmelblau"}


def run(*args, timeout=900, check=True):
    print("+", " ".join(map(str, args)), flush=True)
    return subprocess.run(list(map(str, args)), check=check, timeout=timeout)


def render_builder(generator, target):
    fallback, image, _ = TARGETS[target]
    # Older stable branches lack these two distro entries. Reuse their own
    # family recipe with only the target image changed, without editing source.
    config = copy.deepcopy(generator.DISTS[target if target in generator.DISTS else fallback])
    config["image"] = image
    if config.get("scc"):
        raise ValueError("Smoke builds must not require registration secrets")
    kwargs = {"patch_libhimmelblau": False} if "patch_libhimmelblau" in inspect.signature(generator.render).parameters else {}
    return generator.render(target, config, **kwargs)


def load_generator(path):
    spec = importlib.util.spec_from_file_location("smoke_generator", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def build(target, artifacts):
    _, _, fmt = TARGETS[target]
    image = "himmelblau-smoke-build-" + target
    artifacts.mkdir(parents=True, exist_ok=False)
    # A clean CI checkout prevents stale packages from masquerading as this PR.
    output = ROOT / "target" / ("debian" if fmt == "deb" else "generate-rpm")
    if output.exists() and any(output.glob("*." + fmt)):
        raise ValueError("Refusing pre-existing package artifacts")
    (ROOT / "target").mkdir(exist_ok=True)
    (ROOT / "packaging").mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        dockerfile = Path(tmp) / "Dockerfile"
        dockerfile.write_text(render_builder(load_generator(ROOT / "scripts/gen_dockerfiles.py"), target))
        try:
            run("docker", "build", "--platform", "linux/amd64", "-t", image, "-f", dockerfile, ROOT, timeout=5400)
            run("docker", "run", "--rm", "--platform", "linux/amd64", "-v", str(ROOT) + ":/himmelblau", image, timeout=12600)
            found = set()
            for path in sorted(output.glob("*." + fmt)):
                query = ["dpkg-deb", "--field", "/source/" + str(path.relative_to(ROOT)), "Package"] if fmt == "deb" else ["rpm", "-qp", "--qf", "%{NAME}", "/source/" + str(path.relative_to(ROOT))]
                name = subprocess.check_output(["docker", "run", "--rm", "--network", "none", "-v", str(ROOT) + ":/source:ro", "--entrypoint", query[0], image, *query[1:]], text=True, timeout=30).strip()
                if name in PACKAGES:
                    if name in found:
                        raise ValueError("Duplicate package: " + name)
                    found.add(name)
                    shutil.copyfile(path, artifacts / path.name)
            if found != PACKAGES:
                raise ValueError("Missing daemon/NSS packages: " + repr(PACKAGES - found))
        finally:
            run("docker", "image", "rm", "-f", image, check=False, timeout=60)


def runtime_containerfile(target):
    _, image, fmt = TARGETS[target]
    install = ("apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends systemd systemd-sysv dbus ca-certificates python3" if fmt == "deb" else "dnf -y install systemd dbus ca-certificates python3 && dnf clean all")
    return (f"FROM {image}\nRUN {install}\n"
            "RUN rm -f /etc/machine-id /var/lib/dbus/machine-id /usr/sbin/policy-rc.d && touch /etc/machine-id\n"
            "STOPSIGNAL SIGRTMIN+3\nCMD [\"/usr/lib/systemd/systemd\"]\n")


def smoke(target, artifacts, diagnostics):
    _, _, fmt = TARGETS[target]
    name = "himmelblau-smoke-" + target
    image = name + ":runtime"
    diagnostics.mkdir(parents=True, exist_ok=True)
    context = diagnostics / "image"
    context.mkdir()
    (context / "Containerfile").write_text(runtime_containerfile(target))
    packages = sorted(artifacts.glob("*." + fmt))
    if len(packages) != len(PACKAGES):
        raise ValueError("Expected exactly the two candidate packages")
    try:
        run("podman", "build", "-t", image, context)
        run("podman", "run", "--detach", "--name", name, "--privileged", "--systemd=always", "--cgroupns=private", "--tmpfs", "/run", "--tmpfs", "/tmp", "--tmpfs", "/run/lock", "-v", str(artifacts) + ":/packages:ro", "-v", str(ROOT / '.github/scripts') + ":/smoke:ro", image)
        run("podman", "exec", name, "python3", "/smoke/package_smoke_guest.py", "boot", timeout=150)
        paths = ["/packages/" + p.name for p in packages]
        command = ["env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "install", "-y", *paths] if fmt == "deb" else ["dnf", "install", "-y", *paths]
        run("podman", "exec", name, *command)
        run("podman", "exec", name, "python3", "/smoke/package_smoke_guest.py", "services", timeout=600)
        (diagnostics / "passed").write_text("Package installation and service lifecycle passed\n")
    finally:
        for label, args in [("container", ["inspect", name]), ("logs", ["logs", name]), ("journal", ["exec", name, "journalctl", "--no-pager", "-b", "-n", "2000"]), ("units", ["exec", name, "systemctl", "--no-pager", "status", "himmelblaud", "himmelblaud-tasks"])]:
            try:
                with (diagnostics / (label + ".log")).open("w") as log:
                    subprocess.run(["podman", *args], stdout=log, stderr=subprocess.STDOUT, timeout=30, check=False)
            except (OSError, subprocess.TimeoutExpired) as error:
                print("Diagnostic collection failed:", error)
        run("podman", "rm", "--force", "--time", "10", name, check=False, timeout=60)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["build", "smoke"])
    parser.add_argument("target", choices=TARGETS)
    args = parser.parse_args()
    artifacts = (ROOT / "smoke-artifacts").resolve()
    if args.command == "build":
        build(args.target, artifacts)
    else:
        smoke(args.target, artifacts, (ROOT / "smoke-diagnostics").resolve())


if __name__ == "__main__":
    main()
