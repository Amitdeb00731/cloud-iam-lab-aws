# Access review

**Account:** 963910216975 (workload account)
**Reviewer:** account owner, acting as the identity reviewer.
**Date:** 2026-11-05.
**Inputs:** `credential-report.md` (IAM credential report) and
`access-analyzer-findings.md` (IAM Access Analyzer, external access).

AWS has no single packaged access review in the way Entra ID does. The review
here is the documented, repeatable use of the credential report plus Access
Analyzer: list every identity and every path into the account, examine each, and
record a decision. This is the periodic-review control an IAM function runs, and
it ties back to the joiner, mover, leaver story in the Phase 6 report.

## 1. Human and standing identities

| Identity | Standing access | MFA | Credentials | Decision |
| --- | --- | --- | --- | --- |
| root (963910216975) | full account control | n/a (no credentials) | none | **Keep credential-less.** Root has no password, MFA or keys. Centralized root access (enabled) brokers any root action from the management account, whose root has MFA. Stronger than a local root with MFA; do not add local root credentials. |
| `operator` IAM user | none standing; one inline policy that only permits AssumeRole to the three lab roles under MFA | on | one active CLI base key (rotated 2026-10-31) | **Keep.** MFA present, least privilege holds, the single key is recognised and in active use. |

The `operator` user cannot act on any resource directly. Its only permission is
to assume `ReadOnlyRole`, `ContributorRole` or `AdminJITRole`, and even that is
gated by a condition that requires MFA on the session. Day to day it runs as the
read or contributor role; `AdminJITRole` (AdministratorAccess, one hour) is
assumed only for applies and is time bound.

## 2. Assumable roles

| Role | Permissions | Trust | Decision |
| --- | --- | --- | --- |
| `ReadOnlyRole` | ReadOnlyAccess | operator, MFA required | Keep. |
| `ContributorRole` | PowerUserAccess | operator, MFA required | Keep. Used for most Terraform work. |
| `AdminJITRole` | AdministratorAccess, max 1h session | operator, MFA required | Keep. Just-in-time elevation only; no identity holds standing admin. |

No identity holds standing `AdministratorAccess`. Admin is reached only by a
short, MFA-gated, time-limited role assumption, which is the behaviour FSBP and
CIS reward and the control a bank's IAM function expects.

## 3. External access (Access Analyzer)

Two active findings, both the AWS Organizations management account
(618790904616) assuming an AWS-managed `/managed/` role in this account. Both
reviewed and marked **intended**: expected organisation management access, not
public, already constrained by the resource control policy layer. Detail and the
raw findings are in `access-analyzer-findings.md`. No unexpected or public access
was found.

## 4. Operator base access key

The credential report shows one active key on `operator` (rotated 2026-10-31,
last used 2026-11-03). This is the CLI base credential that
`scripts/assume-role.sh` uses to authenticate before the MFA-gated AssumeRole. It
carries no standing permissions of its own; on its own it can do nothing but
start an MFA-challenged role assumption. It is recognised, in use, and kept. It
is the one long-lived key in the account, and it is acknowledged here rather than
hidden.

## Outcome

- Root user: credential-less and centrally managed through centralized root
  access, with the management account root protected by MFA. Stronger than a local
  root with MFA.
- Every other identity, role and external path reviewed with a recorded decision
  to keep.
- No standing admin, no public sharing, no stale or unexpected credential.
