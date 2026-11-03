# Technique 2: valid account used from an unusual source

| | |
| --- | --- |
| **ATT&CK** | T1078.004 (Valid Accounts: Cloud Accounts) |
| **Tactic** | Initial Access, Defense Evasion |
| **Source** | CloudTrail `ConsoleLogin`, GuardDuty managed findings |
| **Detection** | `detections/aws/02-valid-account-unusual-source.sql`, `detections/sigma/02-valid-account-unusual-source.yml` |
| **Score** | **Partial** |

## What this technique is

A genuine credential, used from somewhere it has never been used before. The
account is not compromised by a software flaw; a valid identity is simply driven
from an attacker's location. Two layers catch it: CloudTrail surfaces the sign-in
and its source, and GuardDuty raises a managed anomaly or IP-reputation finding.

## Validation action and what happened

The plan was to sign in successfully from a second network (a phone hotspot) so a
`ConsoleLogin` would appear from a new source IP, which the detection would flag.
Several sign-ins were made, from the home network and then over the hotspot,
including a fresh sign-in in a private window.

Every successful sign-in was recorded from the same source IP (the home address,
masked here), on the home network and the hotspot alike:

```
eventtime             username  sourceip                 result   mfa_used
2026-11-03T20:06:33Z  operator  <test host, IP redacted>  Success  Yes
2026-11-03T20:01:09Z  operator  <test host, IP redacted>  Success  Yes
2026-11-03T20:00:21Z  operator  <test host, IP redacted>  Success  Yes
```

The egress IP did not change when the laptop was tethered, most likely because
the laptop stayed on the home connection or a VPN normalised the public address.
A genuine new-source event therefore could not be produced benignly in the lab.

## What the data does prove

- Every successful sign-in used MFA (`mfa_used = Yes`), so the account's MFA
  enforcement is working and the no-MFA branch of the detection correctly raises
  nothing. A success with `MFAUsed = No` would be a strong, specific anomaly.
- The query that enriches each sign-in with its source IP and MFA state runs
  cleanly against the live trail, which is the data the detection depends on.

## The managed layer (GuardDuty)

GuardDuty is the reliable detection for this technique, because it learns a
baseline and flags credential use from anomalous or known-bad sources. Its
relevant findings are `UnauthorizedAccess:IAMUser/TorIPCaller` and
`MaliciousIPCaller`, a credential used from a Tor exit node or a flagged IP.

In Phase 3 a `TorIPCaller` finding was delivered end to end through EventBridge
and SNS to the inbox, so the managed detection and its alerting path for
unusual-source credential use are proven. That is the positive signal for this
technique; the CloudTrail rules above are the account-local supplement.

## Score rationale

**Partial, scored honestly.** The detection is built (new-source and no-MFA
branches in Athena, a Sigma rule for the no-MFA case) and the GuardDuty managed
layer for unusual-source credential use is proven to fire and alert. The honest
gap is that a genuine new-source `ConsoleLogin` could not be generated in the lab,
because the egress IP did not change across networks, so the CloudTrail
new-source branch is validated by logic and clean-baseline behaviour rather than
by a fired positive. In a real estate with many users and locations, both the
baseline and the anomaly would be richer and this would score as detected.
