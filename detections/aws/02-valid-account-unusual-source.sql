-- Detection: valid account used from an unusual source
-- ATT&CK:    T1078.004 (Valid Accounts: Cloud Accounts)
-- Source:    CloudTrail ConsoleLogin (success), table cloud_iam_lab.cloudtrail_logs
--            GuardDuty provides the managed anomaly and IP-reputation layer.
--
-- Two CloudTrail signals for a genuine credential used in an unexpected way:
--   1. A successful console login whose (user, source IP) pair has not been seen
--      in the trailing baseline window (a first-time source for that principal).
--   2. Any successful console login where MFA was not used.
--
-- GuardDuty complements these with managed findings such as
-- UnauthorizedAccess:IAMUser/TorIPCaller and MaliciousIPCaller, which flag
-- credential use from a Tor exit node or a known-bad IP. Those findings route to
-- the security alerts SNS topic (see Phase 3), so the managed layer needs no
-- query to fire.
--
-- Schema note: responseElements and additionalEventData are JSON text, read with
-- json_extract_scalar. eventTime is a string, parsed with from_iso8601_timestamp.
--
-- Baseline caveat: in a young account the 30-day baseline is thin, so the
-- new-source branch is noisy until a baseline of normal sources accrues. The
-- no-MFA branch and the GuardDuty layer are reliable from day one.

WITH recent AS (
    SELECT eventtime,
           useridentity.username AS username,
           sourceipaddress,
           json_extract_scalar(additionaleventdata, '$.MFAUsed') AS mfa_used
    FROM cloud_iam_lab.cloudtrail_logs
    WHERE "timestamp" >= date_format(current_timestamp - interval '1' day, '%Y/%m/%d')
      AND eventname = 'ConsoleLogin'
      AND json_extract_scalar(responseelements, '$.ConsoleLogin') = 'Success'
      AND from_iso8601_timestamp(eventtime) > current_timestamp - interval '24' hour
),
baseline AS (
    SELECT DISTINCT useridentity.username AS username, sourceipaddress
    FROM cloud_iam_lab.cloudtrail_logs
    WHERE "timestamp" >= date_format(current_timestamp - interval '30' day, '%Y/%m/%d')
      AND eventname = 'ConsoleLogin'
      AND json_extract_scalar(responseelements, '$.ConsoleLogin') = 'Success'
      AND from_iso8601_timestamp(eventtime) <= current_timestamp - interval '24' hour
)
SELECT r.eventtime, r.username, r.sourceipaddress, r.mfa_used,
       CASE WHEN r.mfa_used <> 'Yes'        THEN 'no_mfa'
            WHEN b.sourceipaddress IS NULL  THEN 'new_source'
       END AS reason
FROM recent r
LEFT JOIN baseline b
       ON r.username = b.username
      AND r.sourceipaddress = b.sourceipaddress
WHERE r.mfa_used <> 'Yes'
   OR b.sourceipaddress IS NULL
ORDER BY r.eventtime DESC;
