-- Detection: password spraying / console brute force
-- ATT&CK:    T1110.003 (Brute Force: Password Spraying)
-- Source:    CloudTrail ConsoleLogin events, table cloud_iam_lab.cloudtrail_logs
--
-- Idea: one source IP accumulating many failed console sign-ins in a short
-- window, or failing against several distinct accounts. The distinct-account
-- count is the higher-confidence spray signal; single-account volume overlaps a
-- user mistyping a password, so it is lower confidence on its own.
--
-- Schema note: responseElements is stored as JSON text in this table, so the
-- sign-in result is read with json_extract_scalar, not map syntax. eventTime is
-- a string, parsed with from_iso8601_timestamp for the window filter.

SELECT sourceipaddress,
       count(*)                                  AS failed_attempts,
       count(distinct useridentity.username)     AS distinct_accounts,
       array_agg(distinct useridentity.username) AS accounts,
       min(eventtime)                            AS first_seen,
       max(eventtime)                            AS last_seen
FROM cloud_iam_lab.cloudtrail_logs
WHERE "timestamp" = date_format(current_timestamp, '%Y/%m/%d')
  AND eventname = 'ConsoleLogin'
  AND json_extract_scalar(responseelements, '$.ConsoleLogin') = 'Failure'
  AND from_iso8601_timestamp(eventtime) > current_timestamp - interval '15' minute
  -- Tuning: once a known-good egress IP is identified, exclude it, for example
  -- AND sourceipaddress <> '<corporate-egress-ip>'
GROUP BY sourceipaddress
HAVING count(*) >= 5
    OR count(distinct useridentity.username) >= 3
ORDER BY failed_attempts DESC;

-- Scheduling note: run on a 15-minute EventBridge schedule. For a run that may
-- straddle midnight UTC, widen the partition filter to cover today and yesterday:
--   AND "timestamp" IN (
--       date_format(current_timestamp, '%Y/%m/%d'),
--       date_format(current_timestamp - interval '1' day, '%Y/%m/%d'))
