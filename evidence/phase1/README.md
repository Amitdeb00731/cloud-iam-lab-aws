# Phase 1 evidence

Evidence for the identity and access model built in Curiosity Unlocked
(963910216975). File names are suggestions; keep them descriptive. Never include
a password or an MFA secret in any screenshot or export.

| Evidence | What it shows | Suggested file |
| --- | --- | --- |
| Roles list | `ReadOnlyRole`, `ContributorRole`, `AdminJITRole` all present | `roles-list.png` |
| AdminJITRole summary | Maximum session duration set to 1 hour | `adminjit-session-1h.png` |
| Operator permissions | Single inline policy `assume-lab-roles`, no managed policies | `operator-permissions.png` |
| Operator MFA | MFA device assigned on Security credentials | `operator-mfa.png` |
| Denied state | Operator signed in, Access denied on S3 or IAM | `operator-denied.png` |
| Read-only state | After assuming `ReadOnlyRole`, S3 readable, write denied | `readonly-after-switch.png` |
| Admin state | After assuming `AdminJITRole`, admin available, 1 hour session banner | `adminjit-elevated.png` |
| Audit trail | CloudTrail Event history filtered by user name `operator`, showing `AssumeRole` for both roles | `cloudtrail-assumerole.png` and optional `cloudtrail-assumerole.csv` |
| SCP guardrail (Step 6) | A denied action outside `eu-north-1`, or an IAM policy simulator result | `scp-region-deny.png` |

Capturing the CloudTrail evidence:
- Filter on **User name = operator** to see operator's own activity: the
  first-login `ChangePassword`, the wall of `AccessDenied` before any role is
  assumed, then successful read calls (`ListBuckets`, `GetRole`) once
  `ReadOnlyRole` is active. That before-and-after is the proof the model works.
- The explicit elevation is logged as **`SwitchRole`** (event source
  `signin.amazonaws.com`), not `AssumeRole`; filter **Event name = SwitchRole**
  in **eu-north-1** to capture that line.
- Event history can lag up to about 15 minutes after the action.

**Privacy:** CloudTrail exports include a **Source IP address** column holding
your real IP. Before committing anything to a public repo, crop or redact the IP
column. Prefer a screenshot of the key rows over the raw CSV.
