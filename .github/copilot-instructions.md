# Himmelblau — Copilot Instructions

This repository is a Rust workspace for **Himmelblau**: Azure Entra ID + Intune interoperability for Linux,
including PAM/NSS integration, system daemons, CLI tools, GNOME greeter QR/DAG UX, browser SSO helpers,
policy/compliance support, and SELinux policy.

When helping with this repo:
- **Prefer building packages (usable artifacts)** over raw `cargo build`.
- **Do not guess** distro behavior or file origins — search the repo (`rg`) and identify whether a file is generated.
- **Call out packaging impact**: any change affecting systemd units, PAM/NSS/authselect, SELinux/AppArmor,
  filesystem paths, or credential handling must be highlighted explicitly.

---

## Dev vs Test machines (critical workflow rule)

Developers almost **never** build and install on the same host.

Assume:
- The developer machine is where code changes + package builds happen (often in containers/VM tooling).
- A separate **test machine (VM)** is where packages are installed and where runtime/debug commands are executed.

Guidance rules:
- You MAY assist with builds once the target distro is known (e.g., `make ubuntu24.04`, `make sle16`, etc.).
- DO NOT suggest installing, enabling services, or running runtime/debug steps on the build host.
- When debugging requires installation or runtime inspection, **prompt the developer to run those steps on the test VM**.
- If the distro isn't specified, ask which distro the **test machine** is running and tailor commands to that.

---

## The #1 workflow: Packaging Makefile (use this first)

This repo is driven by a packaging-focused Makefile that builds **real DEB/RPM packages** into `./packaging/`.
Prefer `make` targets over ad-hoc manual commands when guiding users.

Common targets:
- `make` / `make all` — auto-detect host distro and build packages for this host
- `make install` — install packages from `./packaging/` (apt/dnf/yum/zypper auto-detected)
- `make uninstall` — uninstall Himmelblau packages (apt/dnf/yum/zypper auto-detected)
- `make test` — run cargo tests in a container
- `make test-selinux` — ensure SELinux policy builds
- `make clean` — remove cargo artifacts
- `make setup-hooks` — configure git hooks (SELinux tests + NixOS options regen)
- `make nix` — build Nix packages into `./packaging/`
- `make check-licenses` — validate dependent licenses comply with GPLv3
- `make vet` — interactive dependency review with AI analysis
- `make sbom` — generate an SBOM
- `make package` — build packages for all supported distros (DEB + RPM)
- `make deb` — build all DEB targets (continue on failure, summarize)
- `make rpm` — build all RPM targets; continue on failure; then sign whatever exists

Per-distro targets (build only one):
`make ubuntu22.04`, `ubuntu24.04`, `debian12`, `debian13`, `rocky8`, `rocky9`, `rocky10`,
`tumbleweed`, `rawhide`, `fedora42`, `fedora43`, `sle15sp6`, `sle15sp7`, `sle16`, `gentoo`.

Tips / conventions:
- Typical workflow: build packages on dev host → copy to test VM → install/debug there.
- Output packages go to: `./packaging/`
- To use a local libhimmelblau checkout:
  `LIBHIMMELBLAU_LOCAL=/path/to/libhimmelblau make <target>`

---

## libhimmelblau (primary dependency)

Himmelblau depends heavily on **libhimmelblau**, which is typically developed side-by-side with this repo.

Expected checkout layout (common):
- `<parent>/himmelblau/`
- `<parent>/libhimmelblau/`  ← adjacent sibling directory

`libhimmelblau` is the core Entra protocol (_not_ OIDC) and auth implementation (token acquisition, discovery/metadata,
Graph/Intune-related protocol pieces, serialization, error handling, and C/Python bindings).

Where things live in `libhimmelblau`:
- Core Auth workflows: `src/auth.rs`
- Intune logic: `src/intune.rs`
- Graph logic: `src/graph.rs`
- Discovery: `src/discovery.rs`
- Errors: `src/error.rs`
- Bindings:
  - C API: `src/capi.rs` (+ helpers like `src/c_helper.rs`)
  - Python API: `src/pyapi.rs`
- Examples: `example/` (C + Python MSAL examples)

Using a local checkout when building Himmelblau:
- Set `LIBHIMMELBLAU_LOCAL=/path/to/libhimmelblau` when invoking `make <target>`
  to build Himmelblau against the adjacent working tree rather than a packaged/pinned version.

---

## Build system mental model (important)

### Packages are the goal
You *can* run `cargo build`, but producing **usable packages** is generally more helpful. The Makefile +
generator scripts drive the real packaging workflow across distros.

### Where the build logic actually lives
- The Makefile coordinates the build.
- **`scripts/gen_dockerfiles.py` contains most of the build logic**, working together with the Makefile.
- Other scripts in `scripts/` are used for parts of the build/release process; check there before reinventing.

### Packaging tools used
Most packaging heavy-lifting is done via:
- `cargo-deb` (DEB builds)
- `cargo-generate-rpm` (RPM builds)

Definitions and packaging metadata are **scattered across multiple `Cargo.toml` files** (per-crate),
so when adjusting packaging, search across the workspace rather than assuming a single canonical file.

---

## Repo map (where things live)

### Workspace crates (primary code) — `src/`
Core shared library:
- `src/common/` — shared core used by multiple components
  - `src/common/src/auth.rs` — auth workflows (Hello/PIN, token acquisition, etc.)
  - `src/common/src/config.rs` — config parsing/validation and defaults
  - `src/common/src/tpm.rs` — TPM/key handling
  - `src/common/src/idprovider/` — provider implementations
    - `openidconnect.rs` — generic OIDC provider logic
  - `src/common/src/nss_cache.rs`, `idmap_cache.rs`, `mapping.rs` — caching/mapping/idmap behavior

Daemons:
- `src/daemon/` — system daemon + tasks daemon
  - `src/daemon/src/daemon.rs` — main daemon
  - `src/daemon/src/tasks_daemon.rs` — tasks daemon
  - tmpfiles templates:
    - `src/daemon/src/himmelblaud.tmpfiles.conf`
    - `src/daemon/src/himmelblau-policies.tmpfiles.conf`

Auth integration modules:
- `src/pam/` — PAM module implementation (`src/pam/src/pam/*`)
- `src/nss/` — NSS module implementation
  - tmpfiles template: `src/nss/src/nss-himmelblau.tmpfiles.conf`

CLI + tools:
- `src/cli/` — `aad-tool` CLI (`src/cli/src/main.rs`)
- `src/sshd-config/` — sshd config helper
- `src/sshkey-attest/` — ssh key attestation support
- `src/broker/` and `src/broker-client/` — broker service + client library

UX / integrations:
- `src/qr-greeter/` — GNOME greeter extension + QR/DAG UX
  - extension sources: `src/qr-greeter/src/qr-greeter@himmelblau-idm.org/`
- `src/sso/` — browser SSO policy bundles/helpers (`src/sso/src/{chrome,firefox}`)
- `src/o365/` — O365 helpers + desktop entries + url handlers
- `src/policies/` — policy + compliance extensions

Security / identity helpers:
- `src/selinux/` — SELinux policy module sources (`himmelblaud.te`, `.fc`, `.if`)
- `src/idmap/` — idmap library (includes C sources and build.rs)

Other utility crates:
- `src/fxhash/`, `src/paste/`, `src/serde_cbor/`, `src/picky-krb/`, `src/kanidm_build_profiles/`, etc.

---

## Platform integration (packaged system files) — `platform/` (DANGER ZONE)

`platform/` contains distro integration files (systemd units, pam-config, authselect templates, maint scripts).
**Some of these are generated.**

Before editing anything in `platform/`, first determine:
- Is it hand-maintained?
- Or generated from a script/template?

Known generators include:
- `scripts/gen_servicefiles.py` — systemd unit generation
- `scripts/gen_authselect.py` — EL authselect generation

**Be careful to modify the generator, not the generated output.**

---

## Configuration options: source of truth is `docs-xml/`

Adding a new configuration option entails:
- **Adding a new XML file** under `docs-xml/himmelblauconf/` (typically `docs-xml/himmelblauconf/base/`)
- Then regenerating code/docs via the repo's generation workflow (see `scripts/gen_param_code.py` and related steps)

Do not "just add a field in Rust" without also updating the XML source of truth.

---

## "Generated files" rule (global)
If a file appears generated, **edit the source** (XML/templates/scripts) rather than the generated output.
Always point to the generator in your explanation.

---

## Distro / packaging sensitivity (must call out)
Any change that affects:
- `/etc`, `/usr`, `/var`, `/run` paths
- systemd unit names, tmpfiles, credentials
- PAM/NSS/authselect configuration
- SELinux policy
…must be highlighted explicitly, with which generators/scripts and which `platform/*` directories are impacted.

---

## Debugging expectations
When asked for debug collection:
- Prefer `journalctl -u himmelblaud -u himmelblaud-tasks --no-pager`
- Mention config `debug` option and/or `RUST_LOG` if applicable
- Provide redaction guidance (tokens/PRTs/keys)

---

## Contribution style
- Prefer small, reviewable diffs; avoid broad refactors unless requested.
- Provide patch-style output:
  1) files to change
  2) rationale (1–3 bullets)
  3) exact diff or exact edits
