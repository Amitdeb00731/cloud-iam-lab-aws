# Report

The three artefacts a security and controls function produces from this build. All
three describe a controlled exercise in a lab account, not a real breach, and every
result claim is backed by the evidence under `evidence/`.

| Document | For | What it covers |
| --- | --- | --- |
| [incident-report.md](incident-report.md) | Security and incident-response readers | The five techniques written up as one intrusion: timeline, per-stage findings, ATT&CK mapping, root cause, containment, and recommendations |
| [iam-model.md](iam-model.md) | Technology-risk and controls readers | Each control mapped to access-management expectations: provisioning, privileged access, least privilege, authentication, monitoring, and access review |
| [business-companion.md](business-companion.md) | Non-technical and risk stakeholders | One page in plain language, framed against UK operational resilience (PRA and FCA important business services and impact tolerances) |

Suggested reading order: the business summary for the headline, the IAM control
write-up for the control picture, and the incident report for the technical detail.
