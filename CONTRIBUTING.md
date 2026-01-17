# Contributing to Himmelblau

💙 Thank you for your interest in contributing! Himmelblau exists because of community collaboration.  
This document explains how to get involved, set up your environment, and follow our contribution process.

---

## Code of Conduct
All contributors are expected to follow our [Code of Conduct](CODE_OF_CONDUCT.md).  
Please read it before participating in issues, discussions, or pull requests.

---

## How to Contribute

There are many ways to contribute:

- **Report bugs** using [GitHub Issues](https://github.com/himmelblau-idm/himmelblau/issues).
- **Suggest new features** or [enhancements](https://github.com/himmelblau-idm/himmelblau/issues).
- **Improve documentation** ([README](https://github.com/himmelblau-idm/himmelblau/edit/main/README.md), [man pages](https://github.com/himmelblau-idm/himmelblau/tree/main/man), [docs](https://github.com/himmelblau-idm/site/tree/main/mkdocs/docs)).
- **Submit code** via pull requests (see guidelines below).
- **Help triage** [issues](https://github.com/himmelblau-idm/himmelblau/issues) or [review pull requests](https://github.com/himmelblau-idm/himmelblau/pulls).
- **Support others** in the [Matrix community](https://matrix.to/#/#himmelblau:matrix.org) or in our [discussions](https://github.com/himmelblau-idm/himmelblau/discussions).

For **security issues**, please follow our [Security Policy](SECURITY.md) instead of filing an issue.

---

## Development Setup

Himmelblau is written in **Rust**, with packaging support for major Linux distributions.

### Prerequisites
The only build requirements are `git`, `make`, and either `docker` or `podman`. All remaining build requirements will be installed in a container automatically.

### Build
To build packages for your host distro (where supported):

```bash
make
```

This runs inside a container and outputs packages into `./packaging/`.

To build for a specific distro:

```bash
make ubuntu22.04   # or rocky9, tumbleweed, etc.
```

Use `make help` to list all currently supported distros. Adding new distro support is always welcomed!

### Install locally

```bash
sudo make install
```

### Uninstall

```bash
sudo make uninstall
```

---

## Git Hooks

The repository includes a pre-commit hook that automatically regenerates generated files
when you modify the XML parameter definitions or the generator script. To enable:

```bash
make setup-hooks
```

This configures git to use `.githooks/pre-commit`, which regenerates the following files
from `docs-xml/himmelblauconf/` whenever those definitions are committed:

* `nix/modules/himmelblau-options.nix` - Typed NixOS module options
* `man/man5/himmelblau.conf.5` - Man page documentation

Note: Rust code generation is handled by the build system, not the pre-commit hook.

---

## Coding Guidelines

* **Rust Style:** Run `cargo fmt` before committing.
* **Linting:** Use `cargo clippy --all-targets --all-features` to catch common issues.
* **Testing:** Run `cargo test` before opening a PR.
* **Commits:** Write clear commit messages in the imperative mood (e.g., "Add Intune compliance check"). Add a signed-off tag to each commit (`git commit --signoff`).
* **Docs:** Update relevant documentation/man pages when you change functionality.
* **Config Parameters:** When adding or modifying configuration options, update the XML definitions in `docs-xml/himmelblauconf/`. The pre-commit hook will regenerate Rust code, man pages, and NixOS options automatically.

---

## Pull Request Process

1. Fork the repo and create a feature branch (`git checkout -b my-name/my-feature`).
2. Ensure your code builds and tests pass.
3. Manually test the feature change.
4. If applicable, update:

   * Tests
   * Documentation/man pages
   * Packaging
5. Open a PR against `main`.
6. Request a review from a maintainer.

Commits should be small and focused. Large changes are easier to merge if split into smaller parts.

---

## Issues

* Use clear, descriptive titles.
* Include environment details (distro, Himmelblau version, logs, etc).
* For bugs: provide steps to reproduce.
* For features: explain use case and benefit.

---

## Packaging Notes

Himmelblau supports multiple distros. Packaging information lives in various Cargo.toml files throughout the project.
If contributing packaging fixes, test on at least one supported distro and note which in your PR.

---

## Getting Help

* 💬 [Himmelblau Matrix channel](https://matrix.to/#/#himmelblau:matrix.org)
* 📧 [security@himmelblau-idm.org](mailto:security@himmelblau-idm.org) for confidential security issues

---

## Recognition

Contributors are recognized in release notes. Your contributions help make Linux a **first-class citizen** in enterprise identity environments.

