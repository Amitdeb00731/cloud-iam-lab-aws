# Architecture and workflow diagrams

A high-level view of the lab: the organisation and account topology, the identity
and access flow, the data-protection architecture, the visibility and detection
pipelines, the posture loop, and the trust boundaries the controls defend. Each
diagram is Mermaid and renders inline on GitHub, so it stays in version control
and tracks the build as it changes. The detail behind each view is in the phase
guides under [docs/](README.md) and the evidence under `evidence/`.

## 1. Organisation and account topology

Guardrails live in the management account; the access model and every lab resource
live in the workload account. Service control policies bind the `Workloads` OU, so
they constrain the workload account but never the management account.

```mermaid
flowchart TD
  subgraph MGMT["Management account 618790904616 (Cloud-Corp)"]
    ORGS["AWS Organizations<br/>org admin and payer"]
    CRA["Centralized root access<br/>MFA on management root"]
    BASE["AWS-managed baseline SCPs<br/>attached at Root"]
  end
  CUSTOM["Custom SCPs on Workloads OU<br/>deny-outside-eu-north-1<br/>deny-disable-security<br/>require-mfa-sensitive"]
  subgraph WLOU["Workloads OU"]
    subgraph MEMBER["Curiosity Unlocked 963910216975 (workload)"]
      ACCESS["Identity and access model<br/>operator plus three MFA-gated roles"]
      RES["Lab resources<br/>S3, KMS, VPC, CloudTrail, GuardDuty"]
      MROOT["Member root<br/>credential-less"]
    end
  end
  IDADM["Identity delegated admin 795804715588<br/>left as is"]

  ORGS --> WLOU
  BASE -. "inherited" .-> WLOU
  CUSTOM --> MEMBER
  CRA -. "brokers root actions" .-> MROOT
  ORGS --- IDADM
```

## 2. Identity and just-in-time elevation

The daily `operator` identity holds no power of its own. It can only request a
role, and the role answers only when the sign-in carried MFA. Administrative
access is never standing; it is assumed for a short, logged window and dropped.

```mermaid
sequenceDiagram
  actor U as operator
  participant STS as AWS STS
  participant R as Lab role
  participant CT as CloudTrail
  U->>U: Sign in with password plus MFA
  Note over U: No standing access, can only assume roles
  U->>STS: AssumeRole ReadOnly / Contributor / AdminJIT
  STS->>STS: Trust check aws:MultiFactorAuthPresent = true
  alt MFA present
    STS-->>R: Temporary credentials
    Note over R: ReadOnly reads, Contributor is power user, AdminJIT is admin for 1 hour
    R->>CT: Role actions logged
  else MFA absent
    STS-->>U: AccessDenied
  end
  U->>CT: AssumeRole events recorded, who and which role and when
```

## 3. Data-protection architecture

The bucket is reachable only by an IAM principal, over the private VPC path, with
the customer-managed key. Every other path is denied, and the failures are the
evidence (Phase 2).

```mermaid
flowchart LR
  ANON["Anonymous from internet"]
  NONTLS["Non-TLS request"]
  OFFPATH["Off-path request<br/>not via VPC endpoint"]
  PRIN["IAM principal<br/>over VPC endpoint"]

  subgraph VPC["VPC 10.20.0.0/16 (no internet gateway)"]
    VPCE["S3 gateway endpoint"]
  end
  subgraph BUCKET["S3 bucket cloud-iam-lab-data (eu-north-1)"]
    BPA["Block Public Access, all four"]
    POL["Bucket policy<br/>DenyInsecureTransport<br/>RequireVpcEndpointForObjects<br/>RestrictConfidentialPrefix"]
    PFX["Prefixes: public / internal / confidential"]
  end
  KMS["KMS customer-managed key<br/>rotation on, tight key policy"]

  ANON -->|"AccessDenied"| BPA
  NONTLS -->|"AccessDenied, SecureTransport"| POL
  OFFPATH -->|"403, aws:SourceVpce"| POL
  PRIN --> VPCE --> POL --> PFX
  KMS -->|"SSE-KMS at rest"| BUCKET
  PFX -->|"confidential: AdminJIT only"| OK["Allowed read"]
```

## 4. Visibility and telemetry pipeline

Every security-relevant signal lands in one queryable place, and a notable finding
surfaces without polling (Phase 3).

```mermaid
flowchart LR
  subgraph SRC["Signals"]
    MGMT["CloudTrail management events"]
    DATA["S3 data events, data bucket only"]
    GD["GuardDuty findings"]
  end
  TRAIL["Multi-region trail<br/>log-file validation, SSE-KMS"]
  LOGS["Log bucket cloud-iam-lab-logs<br/>locked down, trail-only policy"]
  ATHENA["Athena<br/>cloud_iam_lab.cloudtrail_logs"]
  EB["EventBridge rule"]
  SNS["SNS topic"]
  MAIL["Email inbox"]

  MGMT --> TRAIL
  DATA --> TRAIL
  TRAIL --> LOGS --> ATHENA
  GD --> EB --> SNS --> MAIL
```

## 5. Detection engineering flow

For each technique, a benign validation action produces a signal, a detection
catches it, and the result is scored honestly in the coverage matrix (Phase 4).

```mermaid
flowchart LR
  ACT["Benign validation action<br/>against a test identity"]
  LOG["CloudTrail / GuardDuty"]
  DET["Athena SQL detection<br/>plus portable Sigma rule"]
  SCORE["Scored in coverage matrix"]
  ACT --> LOG --> DET --> SCORE

  subgraph TECH["Five techniques, mapped to MITRE ATT&CK"]
    T1["T1110.003 Password spraying: Detected"]
    T2["T1078.004 Valid account, unusual source: Partial"]
    T3["T1098.003 Admin outside JIT: Detected"]
    T4["T1098.001 New credential: Detected"]
    T5["T1530 Data from storage: Detected"]
  end
  DET -.-> TECH
```

## 6. Posture and governance loop

Measure the posture, remediate the highest-weight findings as code, re-score, and
run a documented access review (Phase 5).

```mermaid
flowchart LR
  CONFIG["AWS Config<br/>resource recorder"]
  SH["Security Hub<br/>FSBP standard"]
  AA["IAM Access Analyzer<br/>plus credential report"]
  BASE["Baseline score: 53%"]
  FIX["Remediation as code<br/>remediation.tf, trail KMS"]
  AFTER["Re-scored posture<br/>projected about 71%"]
  REVIEW["Access review<br/>recorded decision per identity"]

  CONFIG --> SH --> BASE --> FIX --> AFTER
  AA --> REVIEW
  SH -. "depends on" .- CONFIG
```

## 7. Trust boundaries

What an action must cross to reach the data, and the control that guards each
boundary. An attacker who compromises a credential still meets MFA-gated
elevation, a network with no internet path to the bucket, encryption under a key
they do not control, and an audit trail that records the attempt.

```mermaid
flowchart TB
  subgraph INET["Untrusted: public internet"]
    ATTACKER["Anonymous or stolen-credential actor"]
  end
  subgraph ORGB["Organisation boundary: management account"]
    SCPZ["SCP guardrails<br/>Region, MFA, no-disable-security"]
    subgraph ACCTB["Account boundary: Curiosity Unlocked"]
      IDB["Identity boundary<br/>operator plus MFA-gated roles, no standing admin"]
      subgraph NETB["Network boundary: VPC, no internet gateway"]
        EP["S3 gateway endpoint"]
      end
      subgraph DATAB["Data boundary"]
        BKT["S3 bucket: BPA, TLS-only, prefix policy"]
        KEYB["KMS CMK, the decryption control point"]
      end
      LOGB["Audit boundary<br/>CloudTrail, Athena, GuardDuty"]
    end
  end

  ATTACKER -->|"must pass"| SCPZ
  SCPZ --> IDB
  IDB -->|"MFA plus AssumeRole"| EP
  EP --> BKT
  KEYB -->|"guards"| BKT
  IDB -. "all actions logged" .-> LOGB
```

## How to read these

The diagrams are intentionally high level: they show the control relationships,
not every resource. For the exact configuration, the Terraform in
[iac/terraform/](../iac/terraform/) is the source of truth, the phase guides give
the step-by-step build, and the console screenshots embedded in those guides and
in `evidence/` show each control as it actually appears.
