# Creating a Himmelblau Developer Build

This document explains how to prepare a **developer build** of Himmelblau.
This build enables developer diagnostics by:

* adding the `developer` feature to `libhimmelblau`, and
* configuring `HTTPS_PROXY` in the systemd service files so traffic is routed through `mitmproxy`.

---

## ⚠️ Important

* These developer builds **must never be deployed to production**.
* They proxy all sensitive authentication traffic to a local debugging proxy for troubleshooting only.

---

## Steps to build a developer version

### 1. Clone Himmelblau & checkout the version to test

```bash
git clone https://github.com/himmelblau-idm/himmelblau.git
cd himmelblau
```

Checkout the branch or commit for the version you’re testing:

```bash
git checkout <branch-or-commit>
```

---

### 2. Apply developer-specific changes

Make the following edits.

#### In `Cargo.toml`

* Change the version to mark it as a developer build:

  ```toml
  version = "0.9.19-dev"
  ```
* Enable the `developer` feature for `libhimmelblau`:

  ```toml
  libhimmelblau = { version = "0.6.27", features = ["broker", "changepassword", "on_behalf_of", "developer"] }
  ```

---

#### In the systemd service files

Add the `HTTPS_PROXY` environment line so `himmelblaud` routes traffic through `mitmproxy`:

```ini
Environment="HTTPS_PROXY=127.0.0.1:8080"
```

Do this in:

* `platform/debian/himmelblaud.service`
* `platform/debian/himmelblaud-tasks.service`
* `platform/opensuse/himmelblaud.service`
* `platform/opensuse/himmelblaud-tasks.service`

Example snippet after change:

```ini
[Service]
User=root
Type=notify
Environment="HTTPS_PROXY=127.0.0.1:8080"
ExecStart=/usr/sbin/himmelblaud
```

---

### 3. Build your packages

Use your normal build process, e.g.:

```bash
make ubuntu24.04
```

---

## Summary

* `libhimmelblau` is now built with the `developer` feature.
* All traffic from `himmelblaud` is proxied through `127.0.0.1:8080` (intended for `mitmproxy`).

