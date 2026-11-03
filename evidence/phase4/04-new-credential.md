# Technique 4: a new long-lived credential

| | |
| --- | --- |
| **ATT&CK** | T1098.001 (Account Manipulation: Additional Cloud Credentials) |
| **Tactic** | Persistence |
| **Source** | CloudTrail IAM events |
| **Detection** | `detections/aws/04-new-credential.sql`, `detections/sigma/04-new-credential.yml` |
| **Score** | **Detected** |

## What this technique is

A long-lived access key keeps working after any interactive session ends, so
creating one is a common way to persist in a cloud account. In an account built
on short-lived role sessions, a new access key is a rare and high-signal event.

## Validation action

Using `AdminJITRole`, two access keys were created on the `operator` user across
the test and then deleted, modelling an attacker minting a standing credential.

## Raw events

```
eventtime             eventname        target_user  new_key_id
2026-11-03T20:27:27Z  CreateAccessKey  operator     AKIA...DS7I
2026-11-03T20:24:27Z  DeleteAccessKey  operator
2026-11-03T20:23:05Z  CreateAccessKey  operator     AKIA...T3HC
```

Initiator on every event: `arn:aws:sts::963910216975:assumed-role/AdminJITRole/terraform`.
Both test keys were then deleted (the second delete lagged in CloudTrail but was
confirmed live). A `list-access-keys` on `operator` afterwards returned only its
pre-existing credential, so the two test keys are gone.

## The known-good baseline (an important nuance)

`operator` carries one long-lived access key that is not an attack: it is the
base credential the CLI uses to authenticate as `operator` before assuming a lab
role (`scripts/assume-role.sh`). Because every lab role requires MFA in its trust
policy, that key on its own can do nothing but initiate an MFA-gated
`AssumeRole`, so it is low risk and is a deliberate part of the role-based access
model (the account could not use IAM Identity Center, so a base credential is
needed to start the role-assumption chain).

This is exactly the baseline a real detection must account for. The rule flags
every `CreateAccessKey`, and the tuning step is to allowlist the known-good
provisioning or base credential and alert on any creation beyond it. In this
exercise the two creations during the test are the anomalies the detection
catches; the pre-existing base key is the allowlisted baseline.

## Score rationale

**Detected.** Both key creations were recorded with the target user, the key id,
and the initiator, and the detection isolates a new long-lived credential against
a documented known-good baseline. The deletes confirm the test keys were cleaned
up.
