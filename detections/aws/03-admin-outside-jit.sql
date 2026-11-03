-- Detection: administrative policy granted directly to a principal
-- ATT&CK:    T1098.003 (Account Manipulation: Additional Cloud Roles)
-- Source:    CloudTrail IAM events (global service, us-east-1 partition)
--
-- The sanctioned path to admin in this account is a temporary sts:AssumeRole of
-- AdminJITRole. Attaching an administrative policy directly to a user, role or
-- group creates standing privilege, a different and louder action, and is the
-- attacker move this catches. Inline policy puts carry arbitrary privilege and
-- are flagged too.
--
-- Schema note: requestParameters is JSON text, read with json_extract_scalar.
-- IAM events are global, so do not filter on region (they land under us-east-1).

SELECT eventtime,
       useridentity.arn AS initiator,
       eventname,
       json_extract_scalar(requestparameters, '$.userName') AS target_user,
       json_extract_scalar(requestparameters, '$.roleName') AS target_role,
       json_extract_scalar(requestparameters, '$.policyArn') AS policy_arn
FROM cloud_iam_lab.cloudtrail_logs
WHERE "timestamp" = date_format(current_timestamp, '%Y/%m/%d')
  AND (
        ( eventname IN ('AttachUserPolicy', 'AttachRolePolicy', 'AttachGroupPolicy')
          AND json_extract_scalar(requestparameters, '$.policyArn') IN (
                'arn:aws:iam::aws:policy/AdministratorAccess',
                'arn:aws:iam::aws:policy/IAMFullAccess',
                'arn:aws:iam::aws:policy/PowerUserAccess') )
        OR eventname IN ('PutUserPolicy', 'PutRolePolicy', 'PutGroupPolicy')
      )
ORDER BY eventtime DESC;

-- Tuning: in this account only AdminJITRole can attach policies, so the signal is
-- the standing grant itself versus the temporary AssumeRole path. In a larger
-- estate, allowlist the sanctioned provisioning or IaC role and alert on an
-- attach from any other principal.
