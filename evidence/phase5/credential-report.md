# Credential report (before remediation)

**Account:** 963910216975 (workload account, "Curiosity Unlocked")
**Captured:** 2026-11-05, before any Phase 5 remediation.
**Command:**

```
aws iam get-credential-report --query Content --output text | base64 -d
```

The IAM credential report lists every account identity that can hold a
credential, with the state of its password, MFA device and access keys. It is
one of the two inputs to the access review in `access-review.md`.

## Decoded report

Two identities exist in this account: the account root user and the `operator`
IAM user. The report below is reproduced verbatim; it carries no secret
material (access key IDs, passwords and secret keys are never included in a
credential report).

```
user,arn,user_creation_time,password_enabled,password_last_used,password_last_changed,password_next_rotation,mfa_active,access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date,access_key_1_last_used_region,access_key_1_last_used_service,access_key_2_active,...
<root_account>,arn:aws:iam::963910216975:root,2026-09-15T11:56:15Z,false,no_information,N/A,not_supported,false,false,N/A,N/A,N/A,N/A,false,...
operator,arn:aws:iam::963910216975:user/operator,2026-10-29T18:18:52Z,true,2026-11-03T20:06:33Z,2026-10-29T20:00:36Z,N/A,true,true,2026-10-31T15:41:09Z,2026-11-03T20:14:00Z,eu-north-1,sts,false,...
```

## Observations

| Identity | Password | MFA | Access keys | Read |
| --- | --- | --- | --- | --- |
| root (963910216975) | none | none (`mfa_active=false`) | none | Credential-less root: no password, no MFA, no access keys. Under AWS Organizations with centralized root access this is the recommended state, stronger than root with MFA. Root actions are brokered from the management account, whose root has MFA. |
| operator | enabled | on (`mfa_active=true`) | one active key, rotated 2026-10-31, last used 2026-11-03 (eu-north-1, sts) | Sound. The single key is the known-good CLI base credential used by `scripts/assume-role.sh`; it can only initiate an MFA-gated AssumeRole and holds no standing permissions. Keep. |

The workload account root holds no credentials at all: no password, no MFA device
and no access keys. Under AWS Organizations this credential-less state is the
recommended posture, not a gap. Centralized root access is enabled, so any root
action on a member account is brokered from the management account (618790904616),
whose own root is protected by MFA (set in Phase 1). This is stronger than placing
a password and MFA back on the member root. The matching FSBP control IAM.6
(hardware MFA on root) reports no data because there are no member root credentials
to evaluate, which is the correct outcome of this design.

The `operator` user is in good order: console password with MFA, and exactly one
access key that the account owner recognises as the CLI base key. No second key,
no stale key.
