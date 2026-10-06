
# Brute Force → Account Compromise

## Overview

This scenario covers the investigation of multiple failed authentication attempts against a user account, followed by a successful login from the same external source.

The investigation determines whether the activity represents a normal authentication issue, brute-force/password-spraying activity, or a potential account compromise.

## Scenario

```text
Multiple Failed Logins
        ↓
Same Source IP
        ↓
Successful Authentication
        ↓
Post-Login Activity
        ↓
Compromise Assessment
````

In the simulated case, repeated authentication failures were followed by a successful login. Additional activity across endpoint, cloud, and web telemetry was reviewed to determine the likelihood of account compromise.

## Investigation Focus

* Authentication timeline and failure pattern
* Source IP and targeted accounts
* Successful login validation
* MFA and user/device context
* Windows and Linux authentication activity
* CloudTrail / AWS activity
* Cloudflare / WAF traffic
* Post-authentication behaviour
* Endpoint activity

## Tools & Technologies

* **ELK / Kibana** — Log analysis and investigation
* **Cloudflare** — Web/WAF traffic correlation
* **AWS CloudTrail** — Cloud authentication and API activity
* **Windows Security Logs** — Authentication events
* **Linux / SSH Logs** — Authentication activity
* **Symantec / Endpoint Telemetry** — Endpoint validation
* **Splunk / Wazuh / Microsoft Sentinel** — Equivalent investigation queries

## Detection

The detection identifies:

> **5 or more failed authentication attempts followed by a successful authentication from the same source IP for the same user within 10 minutes.**

The detection is documented as a **Sigma rule** in `detection-rule.yml`.

## Response

If account compromise is confirmed or highly suspected:

* Lock or disable the affected account
* Reset password and validate MFA
* Revoke active sessions, tokens, or API keys
* Remove unauthorized privilege changes
* Block the source where appropriate
* Investigate the affected endpoint
* Escalate the incident according to the response process

## Files

| File                 | Purpose                                     |
| -------------------- | ------------------------------------------- |
| `investigation.md`   | Detailed investigation and analysis         |
| `detection-rule.yml` | Sigma detection rule                        |
| `playbook.md`        | Investigation queries and response workflow |
| `sample-logs.json`   | Synthetic multi-source investigation logs   |

