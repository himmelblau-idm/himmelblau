# Himmelblau Security Incident Response Checklist (IRP)

> **Use this checklist in a single security response.** Keep concise status notes in **📢 Updates** and record durable facts in **🗒️ For the record…**. Link to runbooks and evidence where possible.

---

### 🏷️ Phase
1️⃣ Lead validation
### 📢 Updates
<< Use this section to detail the report received, and include any repro results, mitigating factors and the impact of the issue >>

Ex:

I've read the report and validated this vulnerability does exist.

The exploit is difficult to achieve due to the following:

- It requires precise timing and multiple steps to achieve.
- It requires a specific set of configurations, and advanced knowledge to identify repositories with these configurations.
- The repository owner must approve a PR from the bad actor before they can attempt this exploit.

The impact of the exploit:

- Enables a contributor with read access to gain write access.
- With write access, they can then alter workflows and source code.

### 🤓 Guidance
_helpful things that can help you during this phase_

<< Use this section to link to any reference documentation >>

* [Lead validation runbook]

### ✅ Tasks
_things that should be completed before moving on_

- [ ] Understand vulnerability/situation
- [ ] Update case summary with understanding
- [ ] Determine severity
- [ ] Decide if case will become an investigation. Either:
  - [ ] Dismiss lead as not-actionable and apply `IR Lead - not actionable` label
  - [ ] Convert lead to an investigation

### 🗒️ For the record...
_what did you determine during this phase?_

- Is there a direct risk of [CIA](https://www.energy.gov/femp/operational-technology-cybersecurity-energy-systems#cia) being broken? `Yes|No`
- Which part of [CIA](https://www.energy.gov/femp/operational-technology-cybersecurity-energy-systems#cia) could be broken? `Confidentiality|Integrity|Availability`
- What user data is at risk?
- What is required to exploit this situation?
- Affected component(s): `pam|nss|daemon|idmap|docs|packaging`
- First affected version / branch: `<tag or semver>` / `<branch>`
- The vulnerability was introduced on: `YYYY-MM-DD`
- Is there a pull request where the vulnerability was introduced? <url>

---

### 🏷️ Phase
2️⃣ Mitigation
### 📢 Updates

<< use this section to call out any blockers, challenges, or successes. this section may contain a mitigation plan or strategy to execute >>

To prevent potential exploitation, we've disabled the feature where this vulnerability exists.

We identified the root cause, and are now working on a pull request to mitigate it at the root.


### ✅ Tasks
_things that should be completed before moving on_

- [ ] Re-assess severity and update if necessary
- [ ] Check product surfaces (packages & platforms): `Debian/Ubuntu .deb | RHEL/Fedora/openSUSE .rpm | supported branches`
- [ ] Confirm mitigation across surfaces

### 🗒️ For the record...
_what did you learn during this phase?_

- The vulnerability was first mitigated on: `YYYY-MM-DD`
- The vulnerability affected: `pam_himmelblau|nss_himmelblau|himmelblaud|idmap|docs|packaging|etc`
- Is there a link to the mitigation work? <url>
- Confirmed mitigated on (distros): `Debian|Ubuntu|Fedora|RHEL|openSUSE`

---

### 🏷️ Phase
3️⃣ Scoping
### 📢 Updates
_identify impacted version/distros/component_

### ✅ Tasks
_things that should be completed before moving on_

Scoping means preparing clear detection guidance for users to self-check whether the vulnerability was exploited in their own environments. Our goal is to ship a “User Scoping Kit” (USK): what’s affected, what to look for, and copy/paste commands to collect minimal evidence.

> What is the goal of the scoping work? Writing down specific goals can help reframe the work that needs done.
> How can you identify expected vs exploitative use?
> Are you able to find known use of the vulnerability in the data? Perhaps from the security researcher or from internal validation of the vulnerability.

- [ ] Review available information sources
- [ ] Determine if there was a confirmed breach in CIA.
- [ ] Draft the **User Scoping Kit (USK)** with:
      - Affected versions / components (pam|nss|daemon|idmap)
      - Observable symptoms (auth anomalies, token misuse, DoS, etc)
      - Quick checks (1–2 minute commands) and Deep checks (logs to export)
      - How to safely redact and share evidence
- [ ] Suggest Entra log views (e.g. if tokens are implicated):
      - "Sign-in logs" filtered by app/device you document; export a 7-day CSV


### 📓 Notes
_add your scoping notes here_

### 🗒️ For the record...
_what did you learn during this phase?_

- What is the link to your scoping notebook? <url>
- What is your confidence in the completeness of the scoping? `low|medium|high`
- Was there a CIA breach? `Yes|No`
- How many individual user accounts were affected?
- How many organization or enterprise accounts were affected?
- Were you able to find the data you needed? If not, how come?

---

### 🏷️ Phase
4️⃣ Notification
### 📢 Updates
_how we will be contacting users, e.g. "The community matrix channel will receive a forewarning about a security update about to land, afterward the public channel will receive the official announcement."_

### ✅ Tasks
_things that should be completed before moving on_

When the case moves to the notification phase, please complete this checklist from our preparing to send a notification runbook to ensure all required actions are taken:

- When the decision is made to notify
  - [ ] Double check product involvement
  - [ ] Draft notification content
  - [ ] Prepare data required to send notifications. Include a **"How to check if you’re affected"** section (paste the USK quick checks).
- When the draft notification content is complete
  - [ ] Get approvals from Team Leadership
- When the shared notification time occurs
  - [ ] Security advisory / release notes (include USK + mitigation)
  - [ ] Optional blog/changelog (link back to full advisory)
  - [ ] Send notifications
- When the notifications have been sent
  - [ ] Keep an eye on support channels and assist where possible

### 🗒️ For the record...
_what happened during this phase?_

- When was any advanced warning (minus details) announced? `YYYY-MM-DD:HH-MM-SSZ`
- When were notifications sent/published? `YYYY-MM-DD:HH-MM-SSZ`
- How many notifications were sent?
- What is the link to the notification content? <url>
- Is there a link to a blog/changelog that was published? <url>
