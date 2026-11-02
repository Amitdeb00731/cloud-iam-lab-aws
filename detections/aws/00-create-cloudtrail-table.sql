-- CloudTrail Athena table for the lab (Phase 3 visibility, reused by Phase 4
-- detections). Run these in the Athena query editor in eu-north-1, one statement
-- at a time, as a principal with Athena, Glue and S3 permissions (AdminJITRole).
--
-- Before the first query, set an Athena query result location once:
--   s3://cloud-iam-lab-logs-963910216975/athena-results/
--
-- The table uses partition projection on region and date, so queries that filter
-- on region and timestamp scan only that day's prefix and stay cheap. There is no
-- Glue crawler and no manual ALTER TABLE ADD PARTITION to maintain.

CREATE DATABASE IF NOT EXISTS cloud_iam_lab;

CREATE EXTERNAL TABLE IF NOT EXISTS cloud_iam_lab.cloudtrail_logs (
    eventVersion STRING,
    userIdentity STRUCT<
        type: STRING,
        principalId: STRING,
        arn: STRING,
        accountId: STRING,
        invokedBy: STRING,
        accessKeyId: STRING,
        userName: STRING,
        sessionContext: STRUCT<
            attributes: STRUCT<
                mfaAuthenticated: STRING,
                creationDate: STRING>,
            sessionIssuer: STRUCT<
                type: STRING,
                principalId: STRING,
                arn: STRING,
                accountId: STRING,
                userName: STRING>>>,
    eventTime STRING,
    eventSource STRING,
    eventName STRING,
    awsRegion STRING,
    sourceIPAddress STRING,
    userAgent STRING,
    errorCode STRING,
    errorMessage STRING,
    requestParameters STRING,
    responseElements STRING,
    additionalEventData STRING,
    requestId STRING,
    eventId STRING,
    readOnly STRING,
    resources ARRAY<STRUCT<
        arn: STRING,
        accountId: STRING,
        type: STRING>>,
    eventType STRING,
    apiVersion STRING,
    recipientAccountId STRING,
    serviceEventDetails STRING,
    sharedEventID STRING,
    vpcEndpointId STRING,
    tlsDetails STRUCT<
        tlsVersion: STRING,
        cipherSuite: STRING,
        clientProvidedHostHeader: STRING>
)
PARTITIONED BY (
    `timestamp` STRING,
    region STRING
)
ROW FORMAT SERDE 'com.amazon.emr.hive.serde.CloudTrailSerde'
STORED AS INPUTFORMAT 'com.amazon.emr.cloudtrail.CloudTrailInputFormat'
OUTPUTFORMAT 'org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat'
LOCATION 's3://cloud-iam-lab-logs-963910216975/AWSLogs/963910216975/CloudTrail/'
TBLPROPERTIES (
    'projection.enabled' = 'true',
    'projection.timestamp.type' = 'date',
    'projection.timestamp.range' = '2026/01/01,NOW',
    'projection.timestamp.format' = 'yyyy/MM/dd',
    'projection.timestamp.interval' = '1',
    'projection.timestamp.interval.unit' = 'DAYS',
    'projection.region.type' = 'enum',
    'projection.region.values' = 'eu-north-1,us-east-1,us-west-2,eu-west-1',
    'storage.location.template' = 's3://cloud-iam-lab-logs-963910216975/AWSLogs/963910216975/CloudTrail/${region}/${timestamp}'
);
