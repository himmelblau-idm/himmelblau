---
name: Bug report
about: Create a report to help us improve
title: ''
labels: ''
assignees: ''

---

**Description**
Please provide a clear and concise description of the bug, including the expected behavior and what actually happens.

**Steps to Reproduce**
1.
2.
3.

**Screenshots**
If applicable, add screenshots to help explain your problem.

**Logs and Output**
Please attach relevant logs. Make sure to include outputs from the systemd journal by running:
```bash
journalctl -u himmelblaud -u himmelblaud-tasks
```

**Packet Trace (For Authentication Errors)**
If you are encountering an authentication error (check the systemd journal for errors related to the `himmelblaud` daemon), please capture a packet trace of the OAuth2 authentication traffic to Azure Entra ID.

Instructions for capturing the packet trace can be found on the [Himmelblau Wiki](https://github.com/himmelblau-idm/himmelblau/wiki/Capturing-authentication-traffic-using-msal_example).

Please ensure any sensitive data is redacted before submission, including passwords, access tokens, refresh tokens, etc. If you prefer, you can message the developer privately on the [Himmelblau Matrix Channel](https://matrix.to/#/#himmelblau:matrix.org) to provide the packet capture.

**Environment**
- **Linux Distro**: 
- **Package source (distro package/github release/self built)**: 
- **Himmelblau Version**: 

**Additional Information**
Include any additional context that might help diagnose the issue, such as recent configuration changes or related issues.

---

### 💡 Help Make It Happen!
Want to see this bug fixed faster? Fund its implementation through our **Backer's Bounty** program, where you choose which bug fixes get priority!

[![Donate to Our Collective](https://opencollective.com/himmelblau/donate/button.png?color=blue)](https://himmelblau-idm.org/backers.html#backers-bounty)

Your support helps drive Himmelblau’s evolution!
