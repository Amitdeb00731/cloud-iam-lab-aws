# Cloud IAM Lab (AWS): securing an account where identity is the perimeter

> **Status: all six phases complete.** The AWS
> counterpart of the Azure Cloud IAM Lab, built stage for stage to show the same
> controls across two clouds. The plan and the six phase guides are in
> [docs/](docs/README.md); the results of each completed phase are below and in
> `evidence/`.

## The business problem

Banks run large estates on AWS, and in the cloud the perimeter is identity, not
the network. Most cloud incidents start with a credential: it is sprayed,
phished, or found over-privileged, and from there an attacker reaches data or
takes control of the account.

This project asks: **if an identity were compromised in an AWS account, would the
controls hold, and would I see it happen?**

## What this lab shows

- **Identity and access:** an account with no standing privilege, administrative
  access elevated just in time through MFA-gated IAM roles, no long-lived human
  credentials, and service control policies plus IAM conditions constraining every
  principal.
- **Data protection:** an S3 bucket reachable only by an IAM principal over a VPC
  endpoint, encrypted with a KMS customer-managed key, with a data-classification
  model.
- **Visibility:** CloudTrail centralised and queried with Athena, GuardDuty added
  for managed detections, events routed with EventBridge, and a documented
  telemetry coverage table.
- **Detection engineering:** five cloud attack techniques validated against test
  identities, each mapped to MITRE ATT&CK, with an Athena detection and a portable
  Sigma version, scored honestly.
- **Governance:** Security Hub score measured before and after, an access review
  using IAM Access Analyzer, and risk communication framed against UK operational
  resilience (PRA/FCA).

## Architecture

```mermaid
flowchart LR
  subgraph ORG["AWS Organizations + IAM roles"]
    P["Operator + lab roles<br/>admin elevated just in time"]
    ROOT["Root user<br/>credential-less, centralized root access"]
    SCP["SCPs + IAM conditions<br/>MFA, UK-only, one Region"]
  end
  subgraph ACCT["AWS account (eu-north-1)"]
    S3["S3 bucket<br/>VPC endpoint, SSE-KMS"]
    KMS["KMS<br/>customer-managed key"]
    CT["CloudTrail + Athena<br/>GuardDuty + EventBridge"]
  end
  P --> SCP --> S3
  KMS --> S3
  P -. "sign-in / API logs" .-> CT
  S3 -. "data events" .-> CT
  SH["Security Hub<br/>security score"] --> ACCT
```

A full set of system, flow, data-protection, visibility, detection, posture and
trust-boundary diagrams is in
[docs/architecture-diagrams.md](docs/architecture-diagrams.md). The plan and
rationale are in the [Build 2 on AWS guides](docs/README.md).

### Trust boundaries

What an action must cross to reach the data, and the control guarding each boundary:

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

## Results

Each completed phase is written up in its guide under `docs/`, with evidence in
`evidence/`. The Security Hub posture score moved from a 53 percent baseline to a
projected 71 percent after remediation; the exact after figure is awaiting the
service's periodic re-evaluation and is recorded in
[docs/05-posture.md](docs/05-posture.md) once captured.

| Phase | Focus | Status |
| --- | --- | --- |
| 1 | Identity and access model (IAM roles, JIT, SCP) | Complete |
| 2 | Data protection (locked S3, KMS CMK, VPC endpoint) | Complete |
| 3 | Visibility (CloudTrail, Athena, GuardDuty) | Complete |
| 4 | Simulate and detect (five techniques, Athena + Sigma) | Complete |
| 5 | Posture and access review (Security Hub before/after) | Complete |
| 6 | Report (incident report, IAM model, business report) | Complete |

## Repository layout

```
cloud-iam-lab-aws/
├─ docs/           the plan and the six phase guides
├─ iac/terraform/  the environment as code (S3, KMS, VPC, posture, remediation)
├─ detections/
│  ├─ aws/         Athena SQL and EventBridge patterns
│  └─ sigma/       portable versions of each detection
├─ config/         IAM role and policy definitions and SCPs, as JSON
├─ scripts/        repeatable, benign validation scripts
├─ evidence/       per-phase evidence, alert records, coverage matrix
├─ report/         incident report, IAM model, business report (Phase 6)
└─ lab-notes.md    engineering log: the decisions and fixes behind the build
```

## Scope and safety

Everything runs in an AWS account I own, using test identities and synthetic data
only, in a single European Region (`eu-north-1`, the Region left open by the
account's region-restriction guardrail). The detection validation runs harmless
actions against my own test identities to confirm each detection fires. No real
credentials, personal data, or production systems are involved. Cost is held with
a USD 10 budget, one Region, no EC2, and the paid services (GuardDuty, Security
Hub, Config) enabled only for the detection and posture window.

## About me

Built by **Amit Kiran Deb**, MSc graduate (results November 2026) with a
background in OT security (IEC 62443, Purdue model), aiming at cyber security and
technology risk roles in financial services.
[GitHub](https://github.com/Amitdeb00731) · [LinkedIn](https://www.linkedin.com/in/amit-deb-038b642b5/)
