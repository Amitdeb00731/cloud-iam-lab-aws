# Phase 4 coverage matrix

Five cloud attack techniques, each generated as a benign action against the lab's
own test identities, detected, and scored honestly. Four are detected outright;
one is partial, with the reason stated. Every row has its evidence file beside it.

| # | ATT&CK | Technique | Tactic | Primary source | Detection | Score |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | [T1110.003](https://attack.mitre.org/techniques/T1110/003/) | Password spraying / console brute force | Credential Access | CloudTrail `ConsoleLogin` | [01](01-password-spraying.md) | Detected |
| 2 | [T1078.004](https://attack.mitre.org/techniques/T1078/004/) | Valid account from an unusual source | Initial Access | CloudTrail `ConsoleLogin` + GuardDuty | [02](02-valid-account-unusual-source.md) | Partial |
| 3 | [T1098.003](https://attack.mitre.org/techniques/T1098/003/) | Admin granted outside the JIT path | Privilege Escalation | CloudTrail `AttachUserPolicy` | [03](03-admin-outside-jit.md) | Detected |
| 4 | [T1098.001](https://attack.mitre.org/techniques/T1098/001/) | New long-lived credential | Persistence | CloudTrail `CreateAccessKey` | [04](04-new-credential.md) | Detected |
| 5 | [T1530](https://attack.mitre.org/techniques/T1530/) | Data from cloud storage | Collection | CloudTrail bucket policy + S3 data event | [05](05-data-from-storage.md) | Detected |

Each detection exists as an Athena query in `detections/aws/` and a portable Sigma
rule in `detections/sigma/`, so the same logic moves to another SIEM.

## Honest scoring notes

- **Technique 2 is partial, not detected.** The detection and the GuardDuty
  managed layer are both proven (the Tor finding was delivered end to end in
  Phase 3), but a genuine new-source sign-in could not be produced in the lab
  because the egress IP did not change across networks. The CloudTrail
  new-source branch is validated by logic and clean-baseline behaviour rather
  than by a fired positive. In a real estate with many users and locations it
  would score as detected.
- **Single-account volume versus spray (Technique 1).** The detection carries
  both a failure-volume branch and a distinct-account branch, because
  single-account volume overlaps a user mistyping a password. A finding worth
  noting: AWS masks non-existent usernames as `HIDDEN_DUE_TO_SECURITY_REASONS`,
  so a spray against unknown accounts is caught on volume, and a spray against
  known accounts is caught on the distinct-account branch.
- **Known-good baselines are documented, not ignored (Technique 4).** `operator`
  holds one long-lived access key as its CLI base credential, which can do
  nothing but initiate an MFA-gated role assumption. The detection allowlists
  that baseline and alerts on any credential created beyond it.

## Detection and prevention together

Several techniques pair a detection with a Phase 2 or Phase 3 preventive control:
MFA enforcement on sign-in (Technique 2), the just-in-time role model versus a
standing grant (Technique 3), the role-session design that makes a new access key
rare (Technique 4), and Block Public Access with the bucket policy that keeps
storage closed by default (Technique 5). The lab both sees the activity and, in
most cases, would have constrained it.
