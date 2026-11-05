# IAM Access Analyzer findings (external access)

**Account:** 963910216975
**Analyzer:** `cloud-iam-lab-analyzer` (account zone of trust), enabled in Phase 5.
**Captured:** 2026-11-05.
**Command:**

```
aws accessanalyzer list-findings \
  --analyzer-arn arn:aws:access-analyzer:eu-north-1:963910216975:analyzer/cloud-iam-lab-analyzer \
  --region eu-north-1
```

IAM Access Analyzer reports resources in the account that can be reached by a
principal outside the account's zone of trust. It is the second input to the
access review in `access-review.md`.

## Findings

Two active findings, both the same shape: the management account 618790904616
can assume an AWS-managed Organizations role in this account.

```json
{
  "id": "3777c9dc-a415-4ce7-9ab4-12d18d50d565",
  "principal": { "AWS": "618790904616" },
  "action": ["sts:AssumeRole"],
  "resource": "arn:aws:iam::963910216975:role/managed/AWSManagedAccountManagementAccessRole",
  "isPublic": false,
  "resourceType": "AWS::IAM::Role",
  "condition": {},
  "status": "ACTIVE",
  "resourceOwnerAccount": "963910216975",
  "resourceControlPolicyRestriction": "APPLICABLE"
}
{
  "id": "e7d0d0e4-10b9-4b89-a822-8ba643c35ed4",
  "principal": { "AWS": "618790904616" },
  "action": ["sts:AssumeRole"],
  "resource": "arn:aws:iam::963910216975:role/managed/AWSManagedAdvancedFeaturesActivationRole",
  "isPublic": false,
  "resourceType": "AWS::IAM::Role",
  "condition": {},
  "status": "ACTIVE",
  "resourceOwnerAccount": "963910216975",
  "resourceControlPolicyRestriction": "APPLICABLE"
}
```

## Review decision

**Both findings: intended. Keep, no action.**

These two roles sit under the `/managed/` path and are created and owned by AWS
Organizations, not by this build. They let the organisation management account
(618790904616) perform account management and activate organisation features in
the member account, which is expected and required behaviour for an account that
belongs to an AWS organisation. Neither is public, and both are already
constrained by the resource control policy layer (`APPLICABLE`). Removing them
would break organisation management.

The value of the finding is the review itself: the analyzer surfaced every
cross-account path into the account, each was examined, and each has a recorded
decision. No unexpected external access was found. No resource is shared
publicly.
