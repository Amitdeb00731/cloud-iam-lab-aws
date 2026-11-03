# Technique 3: admin granted outside the just-in-time path

| | |
| --- | --- |
| **ATT&CK** | T1098.003 (Account Manipulation: Additional Cloud Roles) |
| **Tactic** | Privilege Escalation, Persistence |
| **Source** | CloudTrail IAM events |
| **Detection** | `detections/aws/03-admin-outside-jit.sql`, `detections/sigma/03-admin-outside-jit.yml` |
| **Score** | **Detected** |

## What this technique is

The account grants administrative access temporarily, by assuming `AdminJITRole`
for a capped session. The attacker move is to give a principal standing admin
instead, by attaching an administrative policy directly. That creates privilege
that persists after any session ends, which is both an escalation and a
persistence step.

## Validation action

Using `AdminJITRole`, `AdministratorAccess` was attached directly to the
`operator` user and then detached, so no standing privilege was left behind. The
grant was live for about eleven seconds.

## Raw events

The detection query returned the grant and its undo:

```
eventtime             eventname          target_user  policy_arn
2026-11-03T20:19:07Z  DetachUserPolicy   operator     arn:aws:iam::aws:policy/AdministratorAccess
2026-11-03T20:15:16Z  DetachUserPolicy   operator     arn:aws:iam::aws:policy/AdministratorAccess
2026-11-03T20:15:05Z  AttachUserPolicy   operator     arn:aws:iam::aws:policy/AdministratorAccess
```

Initiator on every event: `arn:aws:sts::963910216975:assumed-role/AdminJITRole/terraform`.
The first detach (20:15:16) is the original undo; the second (20:19:07) was a
belt-and-braces re-run to confirm `operator` was clean. A follow-up
`list-attached-user-policies` on `operator` returned no attached policies, so the
zero-standing-privilege model is intact.

## Why this fires and the tuning that matters

The detection flags an administrative managed policy
(`AdministratorAccess`, `IAMFullAccess`, `PowerUserAccess`) attached directly to a
user, role or group, and any inline policy put. The `AttachUserPolicy` above
matches the first branch.

The important point for scoring: the initiator here is `AdminJITRole`, the one
principal in this account that can attach policies at all. That is not a false
positive. The signal is the action, granting standing admin to a user, not who
performed it. The temporary `AssumeRole` of `AdminJITRole` is the sanctioned path
and emits an STS event; a direct `AttachUserPolicy` creating durable privilege is
the deviation. In a larger estate the tuning step is to allowlist the sanctioned
provisioning or infrastructure-as-code role and alert on an attach from anything
else.

## Score rationale

**Detected.** The grant was recorded with the target principal, the exact
administrative policy, and the initiator, and the detection isolates it from the
sanctioned just-in-time path. The undo is also captured, confirming the lab was
returned to no standing privilege.
