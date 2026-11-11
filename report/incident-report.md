# Security incident report

| Field | Value |
| --- | --- |
| Report reference | IR-AWS-2026-01 |
| Classification | Internal, portfolio exercise |
| Account | 963910216975 (workload) |
| Region | eu-north-1 |
| Exercise date | 2026-11-03 |
| Report date | 2026-11-05 |
| Author | Amit Kiran Deb |
| Status | Closed |

## 1. Executive summary

This report documents a controlled detection exercise in a lab AWS account,
written up as if the activity were a single intrusion. Over roughly one hour and
fifteen minutes, five attacker techniques were generated in sequence: a password
spray against the console, a valid sign-in, a direct grant of administrative
access, the creation of a long-lived access key, and the reading of a confidential
object after a change to the storage exposure.

Every stage was recorded in CloudTrail and, where relevant, by GuardDuty, and four
of the five techniques were detected outright by purpose-built Athena detections;
the fifth is partial for a reason stated in Section 5. The preventive controls
built in earlier phases, multi-factor authentication, just-in-time elevation, and
default-closed storage, constrained what the activity could achieve. No production
system, real credential, or real data was involved.

Illustrative severity, had this been a genuine intrusion in a production account:
**P2 (high)**, on the basis that administrative privilege and confidential data
were reached, offset by the preventive controls that would have limited a real
attacker and the full audit trail that made every step visible.

## 2. Scope and caveat

All activity took place in an AWS account owned and operated for this lab, against
test identities (`operator` and the three lab roles) and synthetic data only. Each
attacker action was performed benignly to generate the signal a detection should
catch, then reversed. The events, timestamps, and principals quoted below are the
real records captured during the exercise; identifiers are from the lab, and the
single source address that appears in the raw data is a home IP that has been
masked throughout the evidence.

Because the account could not use IAM Identity Center (see the IAM control
write-up), the sanctioned administrative path is `AdminJITRole`. The exercise used
that role to generate the escalation, persistence, and collection events. In a
real intrusion the signal is the same action performed by an unexpected principal;
this is noted at each stage and in the root-cause analysis.

## 3. Incident overview

A single actor is modelled as having obtained access to the `operator` identity and
then moved through the account: establishing a foothold, escalating to
administrator, planting a durable credential, and collecting confidential data. The
five stages map to five MITRE ATT&CK techniques and were run in the order an
attacker would follow.

## 4. Timeline

All times are UTC on 2026-11-03.

| Time | Stage | Recorded event | Principal |
| --- | --- | --- | --- |
| 19:23:33 to 19:28:54 | Credential access | 9 failed `ConsoleLogin` events from one source across 2 distinct accounts | Targeting `operator` |
| 20:00:21 to 20:06:33 | Initial access | 3 successful `ConsoleLogin` events, MFA used on each | `operator` |
| 20:15:05 | Privilege escalation | `AttachUserPolicy` of `AdministratorAccess` to `operator` | `AdminJITRole` session |
| 20:15:16 | Containment (undo) | `DetachUserPolicy` of `AdministratorAccess` | `AdminJITRole` session |
| 20:19:07 | Verification | `DetachUserPolicy` re-run to confirm `operator` clean | `AdminJITRole` session |
| 20:23:05 | Persistence | `CreateAccessKey` on `operator` (key `AKIA...T3HC`) | `AdminJITRole` session |
| 20:24:27 | Cleanup | `DeleteAccessKey` on `operator` | `AdminJITRole` session |
| 20:27:27 | Persistence | `CreateAccessKey` on `operator` (key `AKIA...DS7I`) | `AdminJITRole` session |
| 20:37:10 | Collection (data plane) | `GetObject` on `confidential/customer-records.txt` | `AdminJITRole` session |
| 20:38:50 | Collection (control plane) | `PutBucketPolicy` on the data bucket | `AdminJITRole` session |

The exercise window runs from 19:23:33 to 20:38:50 UTC. Both test access keys were
deleted and the administrative policy removed, so the account was returned to no
standing privilege.

## 5. Findings by stage

### Stage 1: password spraying (T1110.003, credential access)

Nine failed `ConsoleLogin` events were produced from one source in about five
minutes, across two distinct accounts, with one legitimate success in the middle of
the run. The detection fired on its failure-volume branch (threshold of five). A
notable finding: AWS masks non-existent usernames as
`HIDDEN_DUE_TO_SECURITY_REASONS`, so a spray against unknown accounts is caught on
volume and a spray against known accounts is caught on the distinct-account branch.
Evidence: [`evidence/phase4/01-password-spraying.md`](../evidence/phase4/01-password-spraying.md).

### Stage 2: valid account from an unusual source (T1078.004, initial access)

Three successful sign-ins were recorded, each with MFA used, confirming that MFA
enforcement held and that the no-MFA anomaly branch correctly raised nothing. A
genuine new-source sign-in could not be produced in the lab because the egress
address did not change across networks, so this stage is scored **partial**. The
managed layer, GuardDuty, is the reliable detection for unusual-source credential
use, and its end-to-end alerting was proven separately in Phase 3 with a
`TorIPCaller` finding delivered to the inbox. Evidence:
[`evidence/phase4/02-valid-account-unusual-source.md`](../evidence/phase4/02-valid-account-unusual-source.md).

### Stage 3: administrator granted outside the just-in-time path (T1098.003, privilege escalation)

`AdministratorAccess` was attached directly to `operator` and then removed, leaving
no standing privilege. The grant was live for about eleven seconds. The detection
isolates a direct administrative attachment from the sanctioned, time-limited
`AdminJITRole` assumption. The real-world signal is the direct grant itself, not
the identity performing it. Evidence:
[`evidence/phase4/03-admin-outside-jit.md`](../evidence/phase4/03-admin-outside-jit.md).

### Stage 4: new long-lived credential (T1098.001, persistence)

Two access keys were created on `operator` and then deleted. In an account built on
short-lived role sessions, a new long-lived key is a rare, high-signal event. The
detection flags every `CreateAccessKey` and allowlists one documented known-good
baseline: the single `operator` CLI base key, which can do nothing on its own but
start an MFA-gated role assumption. Evidence:
[`evidence/phase4/04-new-credential.md`](../evidence/phase4/04-new-credential.md).

### Stage 5: data from cloud storage (T1530, collection)

A confidential object was read, and the bucket policy was changed, within a
two-minute window. The detection correlates the control-plane change and the
data-plane read into one story: exposure changed, then confidential data read. The
read was performed by `AdminJITRole`, the one principal the confidential-prefix
policy admits, so the event could be generated; in production the trigger is a
confidential read by any other principal. Evidence:
[`evidence/phase4/05-data-from-storage.md`](../evidence/phase4/05-data-from-storage.md).

## 6. MITRE ATT&CK mapping

| Stage | Technique | ID | Tactic | Detection outcome |
| --- | --- | --- | --- | --- |
| 1 | Password spraying | T1110.003 | Credential Access | Detected |
| 2 | Valid account, unusual source | T1078.004 | Initial Access | Partial |
| 3 | Admin outside the JIT path | T1098.003 | Privilege Escalation | Detected |
| 4 | New long-lived credential | T1098.001 | Persistence | Detected |
| 5 | Data from cloud storage | T1530 | Collection | Detected |

The full matrix with evidence links is in
[`evidence/phase4/coverage-matrix.md`](../evidence/phase4/coverage-matrix.md).

## 7. Root cause analysis

The exercise is a controlled walk-through, so there is no defect to attribute.
Instead, this section records, for each stage, the preventive control that would
constrain a real attacker and whether it held.

| Stage | Preventive control | Did it hold |
| --- | --- | --- |
| 1 Spray | MFA required on every role assumption, so a guessed password alone grants nothing | Yes. Every successful sign-in used MFA. |
| 2 Valid account | MFA enforced on sign-in; GuardDuty flags anomalous or known-bad sources | MFA held. GuardDuty alerting proven in Phase 3. |
| 3 Admin grant | Just-in-time elevation (`AdminJITRole`, one-hour cap) is the only sanctioned admin path; a direct attachment is the deviation the detection catches | Yes. No identity holds standing admin; the grant was detected and reversed. |
| 4 New credential | Role-session design makes a long-lived key rare; the `require-mfa-sensitive` SCP and the MFA trust condition limit what any key can do | Partial by design. A key can be created by an admin principal, but on its own it can only start an MFA-gated assumption; creation is detected. |
| 5 Data read | S3 Block Public Access (all four settings), TLS-only policy, confidential-prefix restriction, and the optional VPC-endpoint condition, protected by the `deny-disable-security` SCP | Yes. The bucket stayed closed by default; the exposure change was a reversible toggle of a restriction, not an opening to the internet. |

The common theme is that identity is the perimeter: every stage depended on an
identity, and the controls that constrained the activity are identity and
policy controls rather than network controls.

## 8. Containment and recovery

- The administrative policy attached in Stage 3 was detached immediately and a
  follow-up check confirmed `operator` held no attached policies.
- Both access keys created in Stage 4 were deleted; a later `list-access-keys`
  returned only the recognised base credential.
- The bucket policy toggled in Stage 5 was returned to its default state
  (`enforce_vpce = false` at rest), with Block Public Access and the TLS-only
  statement unchanged throughout.
- No standing privilege, unexpected credential, or public exposure remained at the
  close of the exercise.

## 9. Recommendations

1. In a production estate, front the lab's IAM roles with IAM Identity Center or an
   external identity provider, so joiners, movers, and leavers are managed centrally
   and the base access key is no longer required.
2. Allowlist the sanctioned provisioning or infrastructure-as-code principal in the
   privilege-escalation and new-credential detections, and alert on the same action
   from any other principal.
3. Keep GuardDuty as the primary detection for unusual-source credential use, since
   it carries a learned baseline the account-local CloudTrail rules cannot.
4. Pair the spray detection with sign-in context (whether a success followed from
   the same source) to raise confidence on the single-account branch.
5. Preserve the preventive controls that held here, in particular the MFA trust
   condition, the just-in-time admin model, and default-closed storage under the
   `deny-disable-security` guardrail.

## 10. Evidence index

| Stage | Evidence |
| --- | --- |
| Coverage matrix | [`evidence/phase4/coverage-matrix.md`](../evidence/phase4/coverage-matrix.md) |
| 1 Password spraying | [`evidence/phase4/01-password-spraying.md`](../evidence/phase4/01-password-spraying.md) |
| 2 Valid account | [`evidence/phase4/02-valid-account-unusual-source.md`](../evidence/phase4/02-valid-account-unusual-source.md) |
| 3 Admin outside JIT | [`evidence/phase4/03-admin-outside-jit.md`](../evidence/phase4/03-admin-outside-jit.md) |
| 4 New credential | [`evidence/phase4/04-new-credential.md`](../evidence/phase4/04-new-credential.md) |
| 5 Data from storage | [`evidence/phase4/05-data-from-storage.md`](../evidence/phase4/05-data-from-storage.md) |
| Telemetry coverage | [`evidence/phase3/telemetry-coverage.md`](../evidence/phase3/telemetry-coverage.md) |
