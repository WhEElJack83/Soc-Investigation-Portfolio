# Investigation: Brute Force → Account Compromise

## 1. Investigation Overview

Multiple failed authentication attempts were observed against a user account from the same external source, followed by a successful login. The activity was investigated to determine whether the successful authentication was legitimate or indicated a possible account compromise.

The investigation focused on the authentication pattern, source IP, successful login, and activity observed after authentication.

---

## 2. Investigation Objective

* Identify whether the activity was a genuine brute-force attempt.
* Determine whether the successful login was legitimate.
* Check for signs of account compromise after successful authentication.
* Identify any unauthorized activity performed using the account.
* Contain the account if compromise was confirmed.

---

## 3. Data Sources

Multiple telemetry sources were considered to avoid making the determination from authentication events alone.

### Primary Sources

**SIEM - ELK / Kibana, Splunk, Wazuh, etc**

* Authentication logs
* Windows security events
* Linux authentication logs
* Web/application authentication logs
* Source IP and user activity
* Authentication timeline

**Windows**

* Security Event ID 4625 — Failed logon
* Security Event ID 4624 — Successful logon
* Security Event ID 4740 — Account lockout
* Security Event ID 4672 — Special privileges assigned to new logon
* Event ID 4728 / 4732 — Account added to privileged groups, where applicable

**Linux**

* `/var/log/auth.log`
* `/var/log/secure`
* SSH authentication activity
* `sshd` events
* `sudo` activity

**Cloud - AWS**

* CloudTrail authentication/API activity
* AWS WAF logs
* IAM activity
* Console login events
* Source IP
* User identity
* MFA status
* Subsequent API activity

**WAF - Cloudflare**

Where the affected application was internet-facing, Cloudflare logs were reviewed to determine whether the authentication activity originated from abnormal HTTP traffic.

Relevant information included:

* Client IP
* Request path
* HTTP method
* User-Agent
* Response status
* Request frequency
* WAF/security action
* Bot-related indicators
* Geographic origin

**EDR**

Endpoint/security telemetry was reviewed where available to identify whether the account activity coincided with suspicious endpoint behaviour, malware activity, or a potentially compromised workstation.

---

## 4. Initial Observation

Example activity identified during the investigation:

```text
10:14:02  Failed Login
10:14:08  Failed Login
10:14:15  Failed Login
10:14:21  Failed Login
10:14:29  Failed Login
10:14:36  Failed Login
10:14:44  Failed Login
10:14:51  Failed Login
10:15:03  Successful Login
```

Initial observations:

* Multiple failures within a short period.
* Same source IP targeting the account.
* Successful authentication shortly after the failures.
* Source did not match the user's normal login pattern.

The successful authentication increased the priority of the investigation.

---

## 5. Initial Triage

The following details were reviewed first:

* Affected username
* Source IP
* Destination system/application
* Authentication method
* Number of failed attempts
* Time between attempts
* Successful login timestamp
* User-Agent/device information
* Previous activity from the source

Authentication events were correlated in Kibana to establish the complete timeline.

Example ELK/Kibana filter:

```text
user.name:"j.smith" AND event.category:"authentication"
```

The activity was then reviewed to determine whether it represented:

* Normal password failures
* Brute-force activity
* Password spraying
* Credential stuffing
* Legitimate login after failed attempts

---

## 6. Authentication Pattern Analysis

The frequency and pattern of failed attempts were reviewed.

A high number of failures from the same source within a short period is more suspicious than isolated authentication failures.

The source was also checked against other usernames.

Example:

```text
185.XXX.XXX.42

j.smith       8 failures → SUCCESS
a.wilson      6 failures
m.patel       7 failures
r.khan        5 failures
```

If multiple accounts were targeted from the same source, the activity could indicate password spraying rather than a single-account brute-force attempt.

---

## 7. Source IP Investigation

The source IP was investigated across available telemetry.

The following were reviewed:

* IP reputation
* ASN / hosting provider
* Geographic location
* Previous activity
* Other accounts targeted
* Requests against other applications
* Known malicious indicators

Where the application was behind Cloudflare, HTTP activity was correlated with the authentication timeline.

Example:

```text
10:13:48  GET  /login
10:13:51  POST /login
10:13:54  POST /login
10:13:57  POST /login
...
10:15:03  POST /login → 200
```

A repeated authentication request pattern from the same external source supported the brute-force assessment.

---

## 8. Successful Authentication Validation

The successful login was investigated separately to determine whether it was expected.

### User and Source Validation

* Is the source IP associated with the user?
* Is it a corporate/VPN IP?
* Has the user previously logged in from this location?
* Is the device known?
* Is the browser/User-Agent expected?

### MFA Validation

Where MFA was enabled:

* Was MFA successfully completed?
* Was there an unusual MFA event?
* Was MFA changed or bypassed?
* Was an alternative/legacy authentication method used?

The successful password authentication was not treated as proof of compromise by itself. The surrounding activity was reviewed before making the final assessment.

---

## 9. Post-Authentication Investigation

Activity immediately after the successful login was reviewed for signs of account takeover.

Key areas checked:

* New sessions
* Password changes
* MFA changes
* Privilege changes
* Sensitive application access
* File downloads
* Administrative activity
* Remote access
* Cloud API activity
* Other unusual account actions

The objective was to determine whether the account was simply accessed successfully or actively used by an unauthorized party.

---

## 10. Windows Investigation

For Windows-based systems, authentication events were correlated with subsequent security activity.

Relevant events included:

```text
4624  → Successful Logon
4625  → Failed Logon
4740  → Account Lockout
4672  → Special Privileges Assigned
4728  → Account Added to Global Security Group
4732  → Account Added to Local Security Group
```

Where applicable, process creation and privileged activity were reviewed after the successful login.

The focus was on identifying activity inconsistent with the user's normal behaviour.

---

## 11. Linux Investigation

For Linux systems, SSH and authentication logs were reviewed.

Example:

```text
Failed password for user jsmith from 185.XXX.XXX.42
Failed password for user jsmith from 185.XXX.XXX.42
Accepted password for user jsmith from 185.XXX.XXX.42
```

Following the successful authentication, the investigation checked:

* `sudo` activity
* Command execution
* New processes
* File modifications
* SSH key changes
* User/group changes
* Outbound connections

---

## 12. AWS Investigation

If the affected account had AWS access, CloudTrail activity around the successful login was reviewed.

Key checks included:

* Console login
* Source IP
* User identity
* MFA status
* API activity
* IAM changes
* Access-key activity
* S3 access
* EC2 activity

A sequence such as the following would require further investigation:

```text
ConsoleLogin
     ↓
ListUsers / ListRoles
     ↓
IAM reconnaissance
     ↓
CreateAccessKey
     ↓
S3 / EC2 activity
```

Suspicious API activity immediately after an unusual login would increase the confidence of account compromise.

---

## 13. Cloudflare / WAF Investigation

For internet-facing applications, Cloudflare WAF or AWS WAF logs were reviewed to correlate the authentication activity.

Relevant fields included:

* Client IP
* Request path
* HTTP method
* User-Agent
* Response status
* WAF action
* Bot score / attack indicators
* Request volume

Example:

```text
POST /login → 401
POST /login → 401
POST /login → 401
POST /login → 401
POST /login → 200
```

This helped correlate the external traffic with the authentication events identified in the logs.

---

## 14. Endpoint Investigation

Symantec or other available endpoint telemetry was reviewed when the user's workstation was in scope.

Checks included:

* Malware detections
* Suspicious processes
* Unusual network connections
* Credential-stealing activity
* PowerShell activity
* Recently executed files
* Persistence indicators

This helped determine whether the credentials may have been obtained through a compromised endpoint rather than directly through brute-force activity.

---

## 15. Investigation Findings

Example finding:

> Multiple authentication failures were observed from the same external source, followed by a successful authentication against the affected account. The source was not consistent with the user's normal activity, and additional suspicious activity was observed after authentication.

**Assessment:** Potential account compromise.

Where sufficient evidence was available, the incident would be escalated as a **confirmed account compromise**.

---

## 16. MITRE ATT&CK Mapping

| Technique     | Description                    |
| ------------- | ------------------------------ |
| **T1110**     | Brute Force                    |
| **T1110.001** | Password Guessing              |
| **T1110.003** | Password Spraying              |
| **T1078**     | Valid Accounts                 |
| **T1078.004** | Valid Accounts: Cloud Accounts |

Only techniques supported by the observed activity should be included in the final incident record.

---

## 17. Response / Containment

Depending on the confidence and business impact:

* Disable or lock the affected account.
* Revoke active sessions.
* Reset the password.
* Validate/reset MFA.
* Revoke suspicious tokens or API keys.
* Review and remove unauthorized privilege changes.
* Block the source IP where appropriate.
* Isolate the endpoint if compromise indicators are identified.
* Review activity performed after the suspected compromise.

---

## 18. Eradication & Recovery

After containment, the investigation should confirm that no persistence or unauthorized changes remain.

Review:

* Password/MFA changes
* New accounts
* API keys
* Privilege changes
* SSH keys
* Scheduled tasks
* Suspicious processes
* Cloud IAM changes
* Application configuration

Once the account and associated systems are validated, normal access can be restored according to the organization's access-control process.

---

## 19. False Positives

Potential legitimate causes include:

* User repeatedly entering an incorrect password.
* Expired credentials.
* VPN or network changes.
* Automated application/service authentication.
* Password manager or saved credentials using an outdated password.
* Legitimate login from a new location or device.

These should be validated before classifying the event as an attack.

---

## 20. Investigation Summary

The investigation correlated authentication, network/WAF, endpoint and cloud telemetry to determine whether repeated failed logins resulted in account compromise.

The key investigation flow was:

```text
Failed Logins
     ↓
Source Analysis
     ↓
Successful Authentication
     ↓
User / Device / Location Validation
     ↓
Post-Login Activity
     ↓
Compromise Assessment
     ↓
Containment & Recovery
```

The main objective was to distinguish between a simple brute-force attempt and a successful account takeover based on supporting evidence across multiple log sources.

