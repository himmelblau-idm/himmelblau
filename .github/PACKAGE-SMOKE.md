# Package, systemd, and NSS smoke tests

`package-smoke.yml` runs only for pull requests targeting `stable-2.x`,
`stable-3.x`, or `stable-4.x`, and pushes to those branches. It does not run
for `main` pull requests or pushes. Fork PRs work without repository secrets.
There are no authentication tests, passwords, host enrollment, or device cleanup.

## Coverage and artifacts

The matrix comes from the tested commit's `DEB_TARGETS`, `RPM_TARGETS`, and
`SLE_TARGETS`, plus the architecture flags and base images in
`scripts/gen_dockerfiles.py`. With the current configuration it covers:

| Family | Versions | Architectures |
| --- | --- | --- |
| Ubuntu | 22.04, 24.04, 25.10, 26.04 | amd64, arm64 |
| Debian | 12, 13 | amd64, arm64 |
| Rocky Linux | 8 | amd64 |
| Rocky Linux | 9, 10 | amd64, arm64 |
| Fedora | 43, 44, rawhide | amd64, arm64 |
| Amazon Linux | 2023 | amd64, arm64 |
| openSUSE | Tumbleweed | amd64, arm64 |
| SLE | 15 SP7, 16 | amd64, arm64 |

These are 31 native runner targets. Rocky 8 arm64 is excluded by the existing
build matrix. Arch, Gentoo, and Nix are outside the selected Debian/RPM release
artifact matrix and are not exercised. Unknown targets/families or
secret-dependent repository setup fail preparation rather than silently losing
coverage. SLE uses public BCI images and the public repositories already used
by its build configuration; no SCC registration is performed.

PR CI previously produced no distro artifacts. The new build matrix calls the
same `stable_packages.build` helper used by release/nightly publishing, once
per target, without publishing, release-tag gating, or a registry login. CI
revisions (`+ciRUN.ATTEMPT` for Debian; `1.ciRUN.ATTEMPT` for RPM) sort above
the ordinary revision of the same upstream version. Every artifact carries
the existing manifest with source SHA, identities, architecture, and checksums.
The smoke matrix consumes those artifacts, never a source build or published
release as its candidate. Publishing workflows are unchanged.

## What each target tests

The harness builds a separate minimal runtime image, without Himmelblau,
then boots it using rootful Podman directly on the GitHub runner. It uses
`--privileged --systemd=always --cgroupns=private`, private runtime tmpfs mounts,
and the distro's real systemd as PID 1. These privileges allow the shipped units
to create their own mount namespaces, credentials, DynamicUser identities, and
other sandboxes. No unit is edited, overridden, or replaced. The harness checks
that the container's cgroup hierarchy is writable. It exposes neither the
runner's root filesystem nor its container-engine socket to the container.

Systemd must finish booting before package installation. A degraded boot is
accepted and its failed units are recorded; Himmelblau service/socket failures
are tested separately. Unrelated container boot failures do not fail the test.

The native package manager installs the built `himmelblau` and `nss-himmelblau`
packages with dependency resolution. The NSS package must configure
`nsswitch.conf` itself. Tests supply this uncredentialed configuration:

```ini
[global]
domain = himmelblau-idm.org
hsm_type = soft
cn_name_mapping = true
```

The test starts the packaged daemon, tasks service, and sockets, then requires
`aad-tool status` to return `working!`. The command's exit status alone is
insufficient: the current client can return zero on connection errors.

After startup, `getent passwd tux`, `getent passwd tux@himmelblau-idm.org`,
numeric UID lookup, and `id tux` must agree. The test excludes a local `tux`
account and also verifies local `root` lookup. No password or authentication
request is sent. These checks depend on the public test tenant and network
availability; tenant/network failures fail visibly rather than becoming skips.

Both services must remain responsive with stable PIDs and no automatic restarts
for a 30-second observation period. Tests exercise restart and stop/start,
then socket activation. Because the sockets have `PartOf=himmelblaud.service`,
they are explicitly started again after stopping the daemon. The daemon must
be inactive and the sockets listening before the status request activates it.
NSS checks are repeated, but are not used to prove activation because NSS can
serve a cached answer. Older systemd versions without `Upholds=` require
explicit startup of the tasks service after daemon socket activation.

## Upgrade baseline and state preservation

A second clean container installs the newest compatible public release pair
for the exact distro and architecture, then starts and probes it. Baselines
come from stable GitHub releases and the existing public Debian `Packages` or
RPM repodata at `https://packages.himmelblau-idm.org/stable/`, or the public
Cloudsmith repositories used by the newer publishing workflows. At each release
version, a complete Cloudsmith pair takes precedence over the legacy host. Downloads are
checked against repository SHA-256 metadata. Native package version comparison
requires both baseline packages to be older than the candidate. Historical
baselines may predate packaged sockets.

If no compatible pair exists, `result.json` and the Actions summary explicitly
report an upgrade skip. The fresh-install test remains mandatory. Missing
repositories/distro directories are treated as absence; broken metadata inside
an advertised repository, network errors, installation failures, and baseline
startup failures fail the job.

The upgrade begins with running services and checks that they recover without
an explicit start/restart by the harness. It verifies installed versions,
configuration preservation, initialized machine/HMAC key hashes, database
integrity, a state-directory sentinel, and stable NSS identity. It then repeats
the candidate lifecycle checks. Package scripts intentionally detect containers;
this test exercises that shipped behavior and does not spoof a physical host.

## Timeouts, diagnostics, and required checks

Image preparation and each package-manager operation have a 15-minute limit.
Boot/readiness and service transitions have 120-second limits; individual
client/NSS requests have 15-second limits. Guest phases and Actions jobs also
have outer limits. Harness cleanup runs on failure, with an additional
`always()` workflow cleanup step for remaining named containers.

Diagnostics include package-manager output, the generated runtime Containerfile,
container inspection/logs, journal entries, failed units, effective units,
systemctl status/properties, exit results, PIDs, invocation IDs, and restart
counters. They are uploaded even when tests fail. Package artifacts are retained
for three days and diagnostics for seven days.

Configure branch protection/rulesets for the three stable branches to require
**Package systemd smoke** from the **Package smoke** workflow. Do not require
this check on `main`, where the workflow deliberately does not run. The final
check runs with `always()` and requires successful preparation/build/smoke jobs
and one valid result per selected matrix target. Only the documented
baseline-unavailable upgrade skip is accepted; missing tests do not pass.
Other matrix targets continue after a target fails.

## Local validation

Run the tooling and existing packaging checks without containers:

```sh
python3 .github/scripts/test_package_smoke.py
python3 .github/scripts/test_stable_packages.py
python3 .github/scripts/test_nightly_packages.py
python3 scripts/test_install_lifecycle.py
python3 scripts/test_systemd_fdstore.py
python3 -m unittest scripts/test_gen_dockerfiles.py
sh src/nss/tests/test-update-nss.sh
actionlint .github/workflows/package-smoke.yml
```

To run an individual target on a Linux host with Docker (for the existing
builder), rootful Podman, systemd, and writable cgroups, select a spec and build
its artifacts once:

```sh
export TARGET_SPEC="$(python3 - <<'PY'
import json, sys
sys.path.insert(0, '.github/scripts')
import package_smoke as smoke
matrix = smoke.matrix(smoke.packages.resolve('HEAD'), 1, 1)
print(next(row['spec'] for row in matrix['include']
           if json.loads(row['spec'])['distro'] == 'ubuntu24.04'
           and json.loads(row['spec'])['architecture'] == 'amd64'))
PY
)"
python3 .github/scripts/package_smoke.py build --artifacts artifacts
sudo --preserve-env=TARGET_SPEC python3 .github/scripts/package_smoke.py smoke \
  --artifacts artifacts --diagnostics diagnostics
```

Repeat with `fedora43` and a different artifact/diagnostic directory for an RPM
representative. Optionally pass `GH_TOKEN` for authenticated public GitHub API
reads. Use a disposable host because the test intentionally runs privileged
containers executing the tested package scripts.

During implementation, tooling/regression tests and workflow linting were run,
and real Ubuntu/Fedora release packages were downloaded and SHA-256 verified.
This development
environment has no Podman, Docker, or sudo, has a non-systemd PID 1 and read-only
cgroups; Debian/RPM runtime smoke tests could not be executed here. Metadata
resolution and mocked tests do not establish runtime success.

Host SELinux enforcement, immutable-host installation, hardware TPM integration,
authentication/enrollment, and full PAM/login flows require separate VM or
end-to-end coverage.
