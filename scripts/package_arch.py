#!/usr/bin/env python3
"""
Himmelblau Arch Linux package builder

Usage:
  python package_arch.py --out ./packaging/

Runs makepkg on platform/arch/PKGBUILD and copies the resulting package into
the output directory. Called by `make arch` inside the Arch build container.

makepkg refuses to run as root, so when this script is root (the container
case) the build is handed to an unprivileged account. makepkg itself writes
to BUILD_ROOT, outside the repository; the generated man pages, service files
and cargo artifacts land in the checkout, as they do for the other targets,
which is why the build account is given the uid that owns it.
"""

import argparse
import os
import pwd
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

BUILDER_USER = "himmelblau-builder"
BUILD_ROOT = Path("/var/tmp/himmelblau-arch")


def run(cmd, **kwargs):
    print("+", " ".join(shlex.quote(str(arg)) for arg in cmd), flush=True)
    subprocess.run(cmd, check=True, **kwargs)


def makepkg_env(repo: Path, pkgdest: Path, home: Path) -> dict:
    """Environment shared by the root and non-root build paths."""
    return {
        "HIMMELBLAU_SRC": str(repo),
        "HOME": str(home),
        "BUILDDIR": str(BUILD_ROOT / "build"),
        "SRCDEST": str(BUILD_ROOT / "src"),
        "PKGDEST": str(pkgdest),
        # Pinned because the Makefile and the README name the extension.
        "PKGEXT": ".pkg.tar.zst",
        # Kept in the mounted target directory so crates survive between runs.
        "CARGO_HOME": str(repo / "target" / "cargo-home"),
    }


def uid_is_free(uid: int) -> bool:
    try:
        pwd.getpwuid(uid)
    except KeyError:
        return True
    return False


def create_builder_user(uid: int) -> pwd.struct_passwd:
    """
    Create the build account.

    It is given the uid owning the checkout where possible, so that the files
    the build generates in the source tree keep the ownership the host expects.
    """
    try:
        return pwd.getpwnam(BUILDER_USER)
    except KeyError:
        pass

    useradd = ["useradd", "--create-home", "--shell", "/bin/bash"]
    if uid > 0 and uid_is_free(uid):
        useradd += ["--uid", str(uid)]
    run(useradd + [BUILDER_USER])
    return pwd.getpwnam(BUILDER_USER)


def create_build_dirs(env: dict) -> list:
    """Create the directories makepkg and cargo write to."""
    paths = [Path(env[key]) for key in ("BUILDDIR", "SRCDEST", "PKGDEST", "CARGO_HOME")]
    for path in paths:
        path.mkdir(parents=True, exist_ok=True)
    return paths


def build_as_builder(pkgbuild_dir: Path, env: dict, builder: pwd.struct_passwd) -> None:
    """Run makepkg as BUILDER_USER, which needs to own its writable directories."""
    for path in create_build_dirs(env):
        os.chown(path, builder.pw_uid, builder.pw_gid)

    # cargo writes below target/, which is a mount of the host target/arch.
    os.chown(Path(env["CARGO_HOME"]).parent, builder.pw_uid, builder.pw_gid)

    assignments = " ".join(f"{k}={shlex.quote(v)}" for k, v in env.items())
    run([
        "su",
        BUILDER_USER,
        "-c",
        f"cd {shlex.quote(str(pkgbuild_dir))} && "
        # --nodeps: the container image already provides the makedepends.
        f"exec env {assignments} makepkg --force --noconfirm --nodeps",
    ])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repo-root",
        default=Path(__file__).resolve().parent.parent,
        type=Path,
        help="Himmelblau checkout to build (default: the parent of scripts/)",
    )
    parser.add_argument(
        "--out",
        type=Path,
        help="Where to copy the built package (default: <repo-root>/packaging)",
    )
    args = parser.parse_args()

    repo = args.repo_root.resolve()
    out = args.out.resolve() if args.out else repo / "packaging"
    pkgbuild_dir = repo / "platform" / "arch"

    if not (pkgbuild_dir / "PKGBUILD").is_file():
        print(f"error: {pkgbuild_dir / 'PKGBUILD'} not found", file=sys.stderr)
        return 1

    out.mkdir(parents=True, exist_ok=True)
    pkgdest = BUILD_ROOT / "pkgdest"

    if os.geteuid() == 0:
        builder = create_builder_user(repo.stat().st_uid)
        env = makepkg_env(repo, pkgdest, Path(builder.pw_dir))
        build_as_builder(pkgbuild_dir, env, builder)
    else:
        env = makepkg_env(repo, pkgdest, Path.home())
        create_build_dirs(env)
        run(
            ["makepkg", "--force", "--noconfirm"],
            cwd=pkgbuild_dir,
            env={**os.environ, **env},
        )

    packages = sorted(pkgdest.glob("himmelblau-*.pkg.tar.*"))
    if not packages:
        print(f"error: makepkg produced no package in {pkgdest}", file=sys.stderr)
        return 1

    for package in packages:
        print(f"copying {package.name} to {out}")
        shutil.copy2(package, out / package.name)

    return 0


if __name__ == "__main__":
    sys.exit(main())
