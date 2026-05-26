#!/usr/bin/env python3
"""Patch himmelblau-apparmor DEB control relationships for a moved file."""

import argparse
import glob
import os
import shutil
import subprocess
import tempfile
from pathlib import Path


BAD_PAM_NIGHTLY_DATE = "20260518"
APPARMOR_PACKAGE = "himmelblau-apparmor"
PAM_PACKAGE = "pam-himmelblau"


def parse_control(text):
    fields = []
    current = None

    for line in text.splitlines():
        if not line:
            continue
        if line[0].isspace():
            if current is None:
                raise ValueError("control continuation found before any field")
            current[1].append(line.strip())
            continue

        if ":" not in line:
            raise ValueError(f"invalid control field line: {line!r}")
        key, value = line.split(":", 1)
        current = [key, [value.strip()]]
        fields.append(current)

    return fields


def render_control(fields):
    lines = []
    for key, values in fields:
        value = ", ".join(v for v in values if v)
        lines.append(f"{key}: {value}" if value else f"{key}:")
    return "\n".join(lines) + "\n"


def add_relation(fields, key, relation):
    for field in fields:
        if field[0].lower() == key.lower():
            field[0] = key
            if relation not in field[1]:
                field[1].append(relation)
            return

    insert_at = len(fields)
    for idx, field in enumerate(fields):
        if field[0].lower() == "depends":
            insert_at = idx + 1
            break
    fields.insert(insert_at, [key, [relation]])


def patch_control(control_path, distro_slug):
    relation = f"{PAM_PACKAGE} (<= 4.0.0-{distro_slug}~{BAD_PAM_NIGHTLY_DATE})"
    fields = parse_control(control_path.read_text())

    package_name = next((values[0] for key, values in fields if key.lower() == "package"), None)
    if package_name != APPARMOR_PACKAGE:
        raise ValueError(f"expected Package: {APPARMOR_PACKAGE}, found {package_name!r}")

    add_relation(fields, "Breaks", relation)
    add_relation(fields, "Replaces", relation)
    control_path.write_text(render_control(fields))


def find_packages(package_dir):
    matches = sorted(glob.glob(str(package_dir / f"{APPARMOR_PACKAGE}_*.deb")))
    if not matches:
        raise FileNotFoundError(f"no {APPARMOR_PACKAGE}_*.deb found in {package_dir}")
    return [Path(match) for match in matches]


def patch_deb(package_path, distro_slug):
    package_path = package_path.resolve()
    package_dir = package_path.parent

    with tempfile.TemporaryDirectory(prefix="himmelblau-apparmor-deb.") as tmp:
        tmp_path = Path(tmp)
        root = tmp_path / "root"
        rebuilt = tmp_path / package_path.name

        subprocess.run(["dpkg-deb", "-R", str(package_path), str(root)], check=True)
        patch_control(root / "DEBIAN" / "control", distro_slug)
        subprocess.run(["dpkg-deb", "-b", str(root), str(rebuilt)], check=True)

        replacement = package_dir / f".{package_path.name}.patched"
        shutil.move(str(rebuilt), replacement)
        os.replace(replacement, package_path)


def main():
    parser = argparse.ArgumentParser(
        description="Add distro-specific Breaks/Replaces to himmelblau-apparmor DEB packages."
    )
    parser.add_argument("--distro", required=True, help="DEB revision distro slug, e.g. ubuntu24.04")
    parser.add_argument("--package-dir", default="target/debian", help="Directory containing the built .deb")
    args = parser.parse_args()

    relation = f"{PAM_PACKAGE} (<= 4.0.0-{args.distro}~{BAD_PAM_NIGHTLY_DATE})"
    for package_path in find_packages(Path(args.package_dir)):
        patch_deb(package_path, args.distro)
        print(f"Patched {package_path}: {relation}")


if __name__ == "__main__":
    main()
