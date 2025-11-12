# Security Policy

## Supported Versions

We maintain security updates for the following Himmelblau releases:

| Version        | Supported |
|----------------|-----------|
| 2.x            | ✅ Yes     |
| 1.x            | ✅ Yes     |
| 0.7.x          | ✅ Yes     |
| < 0.7.x, 0.8.x, 0.9.x | ❌ No      |

Security support is aligned with SUSE Linux Enterprise lifecycles and the latest stable release of Himmelblau.  
We strongly recommend using the most recent supported version for security and feature updates.

## Reporting a Vulnerability

To report a security vulnerability in Himmelblau or any of its components (including `libhimmelblau`), please use the GitHub Security Advisories workflow:

🔐 [Submit a vulnerability report](https://github.com/himmelblau-idm/himmelblau/security/advisories/new)

Reports submitted through this form are private and confidential. We will respond promptly—typically within **72 hours**—and coordinate a fix, disclosure timeline, and CVE issuance if appropriate.

Please include:

- A clear description of the issue
- Steps to reproduce the problem (if applicable)
- Any known workarounds or mitigations
- Your contact information (optional but helpful)

## Disclosure Process

1. Report is received and triaged by maintainers.
2. We investigate, reproduce, and confirm the vulnerability.
3. A patch is developed, tested, and prepared for release.
4. A coordinated disclosure may be arranged depending on scope and impact.
5. A new release is published, including CVE(s) and changelog entry.
6. Public GitHub Security Advisory is published post-fix.

Maintainers follow a published Incident Response Checklist with phase gates (Lead Validation → Mitigation → Scoping → Notification).
- Maintainers: see [Incident Response Checklist](./incident-response.md).
- Users: during notifications we will include a short **How to check if you’re affected** guide.

We follow responsible disclosure practices and work closely with reporters to ensure a safe and timely resolution.
## Contact

General questions about Himmelblau security policies can be sent to:

📧 [security@himmelblau-idm.org](mailto:security@himmelblau-idm.org)
