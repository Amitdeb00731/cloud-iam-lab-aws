-- Detection: new long-lived credential created on a principal
-- ATT&CK:    T1098.001 (Account Manipulation: Additional Cloud Credentials)
-- Source:    CloudTrail IAM events (global service, us-east-1 partition)
--
-- This account is built on short-lived role sessions (AssumeRole of the lab
-- roles with MFA), so a long-lived access key, a console login profile, or a
-- service-specific credential should almost never be created. Any such event is
-- a high-signal persistence indicator.
--
-- Schema note: requestParameters and responseElements are JSON text, read with
-- json_extract_scalar. IAM events are global, so do not filter on region.

SELECT eventtime,
       useridentity.arn AS initiator,
       eventname,
       json_extract_scalar(requestparameters, '$.userName') AS target_user,
       json_extract_scalar(responseelements, '$.accessKey.accessKeyId') AS new_key_id
FROM cloud_iam_lab.cloudtrail_logs
WHERE "timestamp" = date_format(current_timestamp, '%Y/%m/%d')
  AND eventname IN ('CreateAccessKey', 'CreateLoginProfile',
                    'CreateServiceSpecificCredential')
ORDER BY eventtime DESC;

-- Tuning: if any automation legitimately rotates keys, allowlist that principal.
-- In this lab there is none, so every CreateAccessKey is worth an alert. Pair
-- with DeleteAccessKey to see whether a created key was cleaned up or left live.
