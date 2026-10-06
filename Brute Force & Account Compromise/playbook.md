
# Playbook: Brute Force → Account Compromise

## 1. Alert Trigger

Multiple failed authentication attempts against the same user from the same source IP, followed by a successful authentication within a short time window.

**Threshold:** 5+ failures → successful login within 10 minutes.

---

## 2. Investigation Queries

### ELK / Kibana — KQL

**Authentication timeline**
```kql
event.category : "authentication"
and user.name : "j.smith"
and source.ip : "185.XXX.XXX.42"
````

**Failed logins**

```kql
event.category : "authentication"
and event.outcome : "failure"
and source.ip : "185.XXX.XXX.42"
```

**Successful login**

```kql
event.category : "authentication"
and event.outcome : "success"
and user.name : "j.smith"
```


### Splunk — SPL

**Authentication timeline**

```spl
index=auth user="j.smith" src_ip="185.XXX.XXX.42"
| stats count by action, user, src_ip
```

**Failed logins**

```spl
index=auth action=failure src_ip="185.XXX.XXX.42"
| stats count by user
```

**Successful login**

```spl
index=auth action=success user="j.smith"
```

---

### Wazuh

**Failed authentication**

```text
rule.groups: authentication_failed
```

**Successful authentication**

```text
rule.groups: authentication_success
```

**Source IP investigation**

```text
agent.name: <host>
AND data.srcip: 185.XXX.XXX.42
```

---

### Microsoft Sentinel / KQL

**Authentication timeline**

```kql
SigninLogs
| where UserPrincipalName == "j.smith"
| where IPAddress == "185.XXX.XXX.42"
| project TimeGenerated, UserPrincipalName, IPAddress, ResultType, Location, AppDisplayName
| order by TimeGenerated asc
```

**Failed logins**

```kql
SigninLogs
| where UserPrincipalName == "j.smith"
| where IPAddress == "185.XXX.XXX.42"
| where ResultType != 0
```

**Successful login**

```kql
SigninLogs
| where UserPrincipalName == "j.smith"
| where IPAddress == "185.XXX.XXX.42"
| where ResultType == 0
```

---

## 3. Analyst Checks

After running the queries, validate:

* Is the source IP unusual for the user?
* Were multiple accounts targeted?
* Was the successful login expected?
* Was MFA completed?
* Was suspicious activity performed after login?
* Are there related endpoint, WAF, or cloud events?

---

## 4. Decision

```text
Failed Logins
     ↓
Successful Login?
     ↓
Expected User / Source?
     ├── Yes → False Positive / Monitor
     │
     └── No
          ↓
   Suspicious Post-Login Activity?
          ├── No → Suspicious Activity
          │
          └── Yes → Potential Account Compromise
```

---

## 5. Response

For confirmed or highly suspected compromise:

* Lock/disable the account.
* Reset password.
* Validate/reset MFA.
* Revoke active sessions and suspicious tokens.
* Remove unauthorized privilege changes.
* Block the source IP where appropriate.
* Investigate the endpoint if credential theft is suspected.
* Escalate according to the incident response process.

---

## 6. Evidence to Capture

```text
Username:
Source IP:
Failed Attempts:
Successful Login:
MFA Status:
Source Location:
Post-Login Activity:
Final Assessment:
Containment Actions:
```
