#!/usr/bin/env bash
# platform/arch/test/lint.sh — local validation harness for the AUR PKGBUILD.
#
# Renders PKGBUILD.in inside an archlinux:base-devel container, then either
# lints it (default, ~30s) or runs a full makepkg build (--build, 20–40 min).
#
# Targets: macOS or Linux host with podman + archlinux:base-devel.
# See platform/arch/test/README.md for usage, env caveats, and design notes.

set -euo pipefail

# ── Locate repo root (this script lives at platform/arch/test/lint.sh) ─────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"

# ── CLI ────────────────────────────────────────────────────────────────────────
MODE="lint"
VERSION=""

usage() {
  cat <<'EOF'
Usage: platform/arch/test/lint.sh [--build] [--version X.Y.Z] [--help]

Validate platform/arch/PKGBUILD.in inside an archlinux:base-devel container.

Modes:
  (default)           Lint mode (~30s). Renders PKGBUILD with sha256=SKIP,
                      then runs: bash -n, namcap, makepkg --printsrcinfo.
  --build             Full build mode (20–40 min under qemu on Apple Silicon).
                      Computes real sha256 of the upstream tarball, then runs
                      makepkg -s end-to-end and namcaps the built .pkg.tar.zst.

Options:
  --version X.Y.Z     Use this version instead of the latest local git tag.
  --help              Print this message and exit.

Examples:
  platform/arch/test/lint.sh
  platform/arch/test/lint.sh --version 3.1.5
  platform/arch/test/lint.sh --build
  platform/arch/test/lint.sh --build --version 3.1.5
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --build)    MODE="build"; shift ;;
    --version)  VERSION="${2:?--version needs a value}"; shift 2 ;;
    --help|-h)  usage; exit 0 ;;
    *)          echo "error: unknown arg: $1" >&2; usage >&2; exit 2 ;;
  esac
done

# ── Default version = latest semver tag (no pre-release suffix) ────────────────
if [[ -z "${VERSION}" ]]; then
  VERSION="$(git -C "${REPO_ROOT}" tag --list --sort=-v:refname '[0-9]*' \
             | grep -Ev -- '-(alpha|beta|rc)' | head -n1 || true)"
  if [[ -z "${VERSION}" ]]; then
    echo "error: could not determine latest tag; pass --version explicitly" >&2
    exit 2
  fi
fi

# ── Host arch detection: Apple Silicon / aarch64 → qemu emulate amd64 ──────────
HOST_ARCH="$(uname -m)"
PLATFORM_FLAGS=()
if [[ "${HOST_ARCH}" != "x86_64" ]]; then
  PLATFORM_FLAGS=(--platform linux/amd64)
fi

command -v podman >/dev/null \
  || { echo "error: podman not found on PATH" >&2; exit 2; }

IMAGE="archlinux:base-devel"

cat <<EOF
─── AUR PKGBUILD validation harness ───────────────────────────────────
  mode:        ${MODE}
  version:     ${VERSION}
  host arch:   ${HOST_ARCH}$([[ ${#PLATFORM_FLAGS[@]} -gt 0 ]] && echo "  (qemu-emulating linux/amd64)")
  image:       ${IMAGE}
  repo root:   ${REPO_ROOT}
───────────────────────────────────────────────────────────────────────
EOF

# ── In-container driver. /src is the repo (read-only); /work is scratch. ───────
# Reads PKGVER + MODE from the environment we pass via `podman run -e`.
CONTAINER_SCRIPT=$(cat <<'INNER'
set -euo pipefail

: "${PKGVER:?}"
: "${MODE:?}"

# pacman 6.1+ sandbox segfaults under rootless podman. Documented workaround.
sed -i 's/^#DisableSandboxSyscalls$/DisableSandboxSyscalls/' /etc/pacman.conf

echo ">> installing namcap + curl"
pacman -Sy --noconfirm --needed namcap curl >/dev/null

mkdir -p /work && cd /work
cp /src/platform/arch/PKGBUILD.in     PKGBUILD
cp /src/platform/arch/himmelblau.install .

# Guard the *definition* lines (not just any mention) so a sabotaged template
# like `pkgver=BOGUS` is caught even though the comments still mention @PKGVER@.
if ! grep -qE '^pkgver=@PKGVER@$' PKGBUILD; then
  echo "!! PKGBUILD.in is missing the literal 'pkgver=@PKGVER@' line" >&2
  exit 1
fi
if ! grep -qE "^sha256sums=\('@SHA256@'\)$" PKGBUILD; then
  echo "!! PKGBUILD.in is missing the literal sha256sums=('@SHA256@') line" >&2
  exit 1
fi

# Compute sha256 of the upstream tarball for build mode; SKIP for lint mode.
if [[ "${MODE}" == "build" ]]; then
  echo ">> fetching upstream tarball to compute sha256"
  TARBALL_URL="https://github.com/himmelblau-idm/himmelblau/archive/refs/tags/${PKGVER}.tar.gz"
  curl -fsSL "${TARBALL_URL}" -o "himmelblau-${PKGVER}.tar.gz"
  SHA256="$(sha256sum "himmelblau-${PKGVER}.tar.gz" | awk '{print $1}')"
  echo "   sha256=${SHA256}"
else
  SHA256="SKIP"
fi

sed -i -e "s|@PKGVER@|${PKGVER}|g" -e "s|@SHA256@|${SHA256}|g" PKGBUILD

# makepkg refuses to run as root; create a builder and hand it the work dir.
useradd -m builder
chown -R builder:builder /work

# makepkg -s shells out to `sudo pacman -S` for missing depends, so the builder
# needs passwordless sudo. base-devel ships sudo; we just authorize it.
install -d -m 0750 /etc/sudoers.d
echo 'builder ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/builder
chmod 0440 /etc/sudoers.d/builder

echo ">> bash -n PKGBUILD"
bash -n PKGBUILD

echo ">> namcap PKGBUILD"
# namcap exits 0 even on W:/E: lines, so we grep the output ourselves.
namcap PKGBUILD | tee namcap-pkgbuild.log
if grep -E '^(PKGBUILD )?[A-Za-z0-9_.-]+ (W|E): ' namcap-pkgbuild.log; then
  echo "!! namcap reported warnings or errors on PKGBUILD" >&2
  exit 1
fi

echo ">> makepkg --printsrcinfo (as builder)"
su builder -c 'cd /work && makepkg --printsrcinfo' > .SRCINFO
head -n5 .SRCINFO

if [[ "${MODE}" == "build" ]]; then
  echo ">> makepkg -s (full build, this is the long one)"
  # We computed the real sha256 above so makepkg's default integrity
  # checking will verify it. --noconfirm for unattended dep install.
  su builder -c 'cd /work && makepkg -s --noconfirm'

  PKG_FILE="$(ls /work/*.pkg.tar.zst | head -n1)"
  echo ">> namcap on built package: ${PKG_FILE}"
  namcap "${PKG_FILE}" | tee namcap-pkg.log

  # ── Known-benign namcap warnings (allowlisted before fail-on-warning) ──
  # These warnings appear on every clean build because they describe
  # invariants of the Arch base system or Rust binary linking, not
  # actionable PKGBUILD bugs. The full unfiltered namcap output is still
  # printed above for visibility; we only filter the failure check.
  #
  #   1. "Dependency {libgcc,glibc,systemd-libs} detected and implicitly
  #      satisfied" — informational. namcap is confirming that ELF deps
  #      on libgcc_s.so.1, libc.so.6/libm.so.6, libudev.so.1 are pulled
  #      in transitively by base / our declared deps. Arch packaging
  #      guidelines explicitly say NOT to declare these in depends=().
  #
  #   2. "Unused shared library '/usr/lib64/ld-linux-*.so.*'" — namcap
  #      false-positive on Rust binaries. The ELF interpreter path that
  #      rustc emits (/lib64/ld-linux-x86-64.so.2, /lib/ld-linux-aarch64.so.1)
  #      is the canonical glibc dynamic linker; namcap treats it as an
  #      "unused shared library" because no DT_NEEDED entry references
  #      it, which is correct for the interpreter but not actionable.
  #
  #   3. "Referenced library 'sh' is an uninstalled dependency" — namcap
  #      limitation. The himmelblau-init-hsm-pin script uses a /bin/sh
  #      shebang. On Arch, /bin/sh is provided by the bash package
  #      (bash declares provides=('sh')), and we DO declare bash in
  #      depends=() for exactly this reason. namcap, however, does not
  #      consult provides=() when validating shebang interpreters — it
  #      looks up the literal name 'sh', finds no package named 'sh',
  #      and reports it as uninstalled. The dependency is genuinely
  #      satisfied at install time; this warning is a tooling false-positive.
  #
  #   4. "Dependency included, but may not be needed ('bash')" — namcap
  #      limitation. namcap only checks ELF DT_NEEDED entries when deciding
  #      whether a declared dep is "needed". It is unaware of shebang
  #      interpreters, so it cannot see that bash is genuinely required
  #      by the /bin/sh shebang in himmelblau-init-hsm-pin. Removing bash
  #      from depends=() would resurrect warning #3; the two limitations
  #      cancel each other. Allowlisting both is the documented Arch
  #      packaging workaround for shebang-based dependencies.
  #
  #   5. "Dependency included, but may not be needed ('systemd')" — namcap
  #      limitation. The same DT_NEEDED-only heuristic applies here: the
  #      sd-notify crate that himmelblaud / himmelblaud_tasks / broker use
  #      for readiness + watchdog notifications is implemented in pure Rust
  #      (it talks to the $NOTIFY_SOCKET unix domain socket directly,
  #      without linking libsystemd). Thus the built binaries have no
  #      DT_NEEDED on libsystemd.so and namcap reports systemd as
  #      unnecessary. In reality the package's installed unit files
  #      (himmelblaud.service, himmelblaud-tasks.service, etc.) and the
  #      sd-notify protocol both require systemd as the init system at
  #      runtime, so declaring it is correct. The dependency rationale
  #      is documented in PKGBUILD.in alongside the depends=() entry.
  #
  # IMPORTANT: this allowlist does NOT cover "may not be needed" warnings
  # for any other dependency. krb5 / libcap / openssh / pcre2 were
  # previously over-declared and have been resolved by source-audit:
  # libcap and pcre2 dropped (no source or DT_NEEDED usage), krb5 and
  # openssh moved to optdepends (real but optional runtime relationships).
  # See PKGBUILD.in for per-dep rationale and the git history for the
  # commits that landed those changes.
  NAMCAP_ALLOWLIST='(W: Dependency (libgcc|glibc|systemd-libs) detected and implicitly satisfied|W: Unused shared library .(/usr)?/lib(64)?/ld-linux-(x86-64|aarch64)\.so|W: Referenced library .sh. is an uninstalled dependency|W: Dependency included, but may not be needed \(.(bash|systemd).\))'
  NAMCAP_ACTIONABLE="$(grep -E ' (W|E): ' namcap-pkg.log | grep -Ev "${NAMCAP_ALLOWLIST}" || true)"
  if [[ -n "${NAMCAP_ACTIONABLE}" ]]; then
    echo "!! namcap reported actionable warnings or errors on built package" >&2
    echo "${NAMCAP_ACTIONABLE}" >&2
    exit 1
  fi
fi

echo ">> in-container checks PASSED"
INNER
)

# ── Run it ─────────────────────────────────────────────────────────────────────
set +e
podman run --rm \
  "${PLATFORM_FLAGS[@]}" \
  -e PKGVER="${VERSION}" \
  -e MODE="${MODE}" \
  -v "${REPO_ROOT}:/src:ro" \
  "${IMAGE}" \
  bash -c "${CONTAINER_SCRIPT}"
RC=$?
set -e

echo "───────────────────────────────────────────────────────────────────────"
if [[ ${RC} -eq 0 ]]; then
  echo "PASS — ${MODE} mode, version ${VERSION}"
else
  echo "FAIL — ${MODE} mode, version ${VERSION} (exit ${RC})"
fi
echo "───────────────────────────────────────────────────────────────────────"
exit ${RC}
