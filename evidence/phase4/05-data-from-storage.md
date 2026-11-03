# Technique 5: data from cloud storage

| | |
| --- | --- |
| **ATT&CK** | T1530 (Data from Cloud Storage) |
| **Tactic** | Collection |
| **Source** | CloudTrail management events (bucket policy) and S3 data events (object read) |
| **Detection** | `detections/aws/05-data-from-storage.sql`, `detections/sigma/05-data-from-storage.yml` |
| **Score** | **Detected** |

## What this technique is

An attacker reads data from cloud storage, often after weakening the controls
that guarded it. The strongest detection ties the two planes together: a change
to the bucket's exposure (control plane) and a read of a confidential object
(data plane), so a single alert carries the whole story.

## Validation action

Two signals were produced against the data bucket, within a two-minute window:

- Data plane: a confidential object was read with `AdminJITRole`.
- Control plane: the bucket policy was changed by toggling the VPC-endpoint
  condition through Terraform, which issues a real `PutBucketPolicy`.

## Raw events

Data plane, the confidential read (source IP masked, it is a home address):

```
eventtime             eventname  caller       sourceip                 object_key
2026-11-03T20:37:10Z  GetObject  AdminJITRole  <test host, IP redacted>  confidential/customer-records.txt
```

Control plane, the exposure change:

```
eventtime             eventname        caller       bucket
2026-11-03T20:38:50Z  PutBucketPolicy  AdminJITRole  cloud-iam-lab-data-963910216975
```

Both carry the initiator `arn:aws:sts::963910216975:assumed-role/AdminJITRole/terraform`.
The S3 data event appeared within about a minute this time; in general these can
lag several minutes, which the detection accounts for with a wide correlation
window.

## Why this fires and the tuning that matters

The bucket policy allows only `AdminJITRole` to read the `confidential/` prefix,
so in the lab the read is performed by that allowed principal to generate the
event. The real-world trigger is a confidential read by any other principal, or
an exposure change from an unexpected caller. The detection surfaces both planes
and, in a SIEM, joins them on bucket and a short time window to raise one
correlated alert: exposure changed, then confidential data read.

This is also where the preventive controls from Phase 2 matter. Block Public
Access on all four settings, the TLS-only policy, and the optional VPC-endpoint
condition stay on, protected by the `deny-disable-security` SCP, so the exposure
change in this test was a reversible toggle of a restriction rather than opening
the bucket to the world.

## Score rationale

**Detected on both planes.** The confidential object read and the bucket-policy
change were each recorded with the principal, the object or bucket, and the
source, and the detection correlates them into the T1530 story. Detection is
paired with the Phase 2 preventive controls that keep the bucket closed by
default.
