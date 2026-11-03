-- Detection: data from cloud storage, exposure change plus confidential read
-- ATT&CK:    T1530 (Data from Cloud Storage)
-- Source:    CloudTrail management events (bucket policy) and S3 data events
--            (object read), table cloud_iam_lab.cloudtrail_logs
--
-- The strongest signal ties two planes together: a change to the bucket's
-- exposure (control plane) and a read of a confidential object (data plane).
-- Either alone is worth a look; the two in one window tell the whole story of a
-- misconfiguration followed by access.
--
-- Schema note: requestParameters is JSON text, read with json_extract_scalar.
-- S3 object reads are data events and can lag several minutes before they are
-- queryable, so correlate over a window of at least that long.

-- Control plane: a change to the data bucket's exposure.
SELECT eventtime,
       useridentity.arn AS caller,
       eventname,
       json_extract_scalar(requestparameters, '$.bucketName') AS bucket
FROM cloud_iam_lab.cloudtrail_logs
WHERE "timestamp" = date_format(current_timestamp, '%Y/%m/%d')
  AND eventname IN ('PutBucketPolicy', 'DeleteBucketPolicy',
                    'PutBucketPublicAccessBlock', 'PutBucketAcl')
  AND json_extract_scalar(requestparameters, '$.bucketName') = 'cloud-iam-lab-data-963910216975'
ORDER BY eventtime DESC;

-- Data plane: a read of a confidential-tier object.
SELECT eventtime,
       useridentity.arn AS caller,
       sourceipaddress,
       json_extract_scalar(requestparameters, '$.key') AS object_key
FROM cloud_iam_lab.cloudtrail_logs
WHERE "timestamp" = date_format(current_timestamp, '%Y/%m/%d')
  AND eventname = 'GetObject'
  AND json_extract_scalar(requestparameters, '$.key') LIKE 'confidential/%'
ORDER BY eventtime DESC;

-- Tuning: AdminJITRole is the only principal allowed to read the confidential
-- prefix (enforced by the bucket policy), so a confidential read by any other
-- principal, or any exposure change from an unexpected caller, is the alert. In
-- a SIEM, join the two planes on bucket and a short time window to raise a single
-- correlated alert rather than two separate ones.
