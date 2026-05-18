#!/usr/bin/env python3
"""Smoke tests for the Dockerfile generator."""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
GENERATOR = REPO_ROOT / "scripts" / "gen_dockerfiles.py"


def run_generator(*args: str) -> Path:
    out_dir = Path(tempfile.mkdtemp(prefix="himmelblau-dockerfiles-"))
    subprocess.run(
        [sys.executable, str(GENERATOR), "--out", str(out_dir), *args],
        cwd=REPO_ROOT,
        check=True,
        text=True,
        capture_output=True,
    )
    return out_dir


def assert_contains(path: Path, *needles: str) -> None:
    text = path.read_text(encoding="utf-8")
    missing = [needle for needle in needles if needle not in text]
    if missing:
        raise AssertionError(f"{path.name} is missing expected content: {missing!r}")


def test_arm64_rpm_dockerfiles() -> None:
    out_dir = run_generator("--only", "fedora42,tumbleweed,sle16", "--arch", "arm64")

    expected = {
        "fedora42": "FROM fedora:42",
        "tumbleweed": "FROM opensuse/tumbleweed:latest",
        "sle16": "FROM registry.suse.com/bci/bci-sle16-kernel-module-devel:16.0",
    }

    for distro, base_image in expected.items():
        dockerfile = out_dir / f"Dockerfile.{distro}.arm64"
        if not dockerfile.exists():
            raise AssertionError(f"missing generated ARM64 RPM Dockerfile: {dockerfile}")

        assert_contains(
            dockerfile,
            base_image,
            "FROM --platform=linux/amd64 rust:latest AS tooling",
            "rustup target add aarch64-unknown-linux-gnu",
            "cargo install --target aarch64-unknown-linux-gnu cargo-deb cargo-generate-rpm",
            "COPY --from=tooling /usr/local/cargo/bin/cargo-generate-rpm",
            "cargo generate-rpm",
        )


def main() -> int:
    tests = [test_arm64_rpm_dockerfiles]
    for test in tests:
        test()
        print(f"PASS {test.__name__}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
