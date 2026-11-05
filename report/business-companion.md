# Business summary

| Field | Value |
| --- | --- |
| Document | One-page business summary |
| Audience | Non-technical and risk stakeholders |
| Date | 2026-11-05 |
| Author | Amit Kiran Deb |

## The point, in one line

If an attacker got hold of a single cloud login, this account is built so that the
login alone achieves very little, and everything it tries is seen.

## The scenario

In the cloud, the main gate is no longer the network; it is identity. Most cloud
incidents start with one credential that is guessed, phished, or found with too
much access. To test this, the lab ran a controlled exercise that walked through
five attacker moves in order: guessing a password, signing in, granting itself
administrator rights, creating a lasting key to stay in, and reading a confidential
file. All of it ran in an account built for the lab, against test logins and
made-up data.

## What the controls did

The account is designed so that no single login carries standing power.

- A stolen password is not enough on its own, because every step up to a useful
  role requires a second factor (multi-factor authentication).
- Administrator access is never left switched on. It is borrowed for at most an
  hour and then dropped, and any attempt to grant it permanently is flagged.
- The data store is closed by default. It is not reachable from the public
  internet, it is encrypted with a key the account controls, and a guardrail
  prevents anyone from quietly turning those protections off.
- Every action is recorded and monitored, so each of the five moves was caught,
  with an alert path proven to reach an inbox.

In short, the controls either stopped or contained each move, and the account saw
all of it.

## The operational resilience view

For a bank, the question that matters is whether an important business service
would stay inside its impact tolerance, the maximum disruption the firm judges it
can absorb, if an identity were compromised. Framed against the UK regulators'
operational resilience expectations (PRA and FCA):

- **Confidentiality.** Access to sensitive data is limited to one administrative
  path and is logged, so exposure from a single compromised login is contained
  rather than open-ended.
- **Control and recovery.** Because administrator rights are temporary and every
  change is recorded, an unexpected grant or new credential stands out quickly and
  can be reversed, which shortens the time a service is at risk.
- **Visibility.** The firm would know an attempt was made. Detection and alerting
  are in place and tested, which is what keeps an incident inside tolerance rather
  than letting it run unseen.

On the evidence of this exercise, a single identity compromise in this account
would be constrained and visible, which supports keeping the impact of such an
event within a reasonable tolerance for a service that depends on it.

## Residual risks and next steps

- The lab uses cloud roles with one base login rather than a central sign-on
  system. A production setup would place a central identity provider in front, so
  staff access is joined, moved, and removed in one place.
- The security posture score improved against best practice but is a health
  measure, not a certification.
- One of the five detections depends on the cloud provider's own anomaly service,
  because a genuine unusual-location sign-in could not be staged in a
  single-location lab.

None of these changes the headline: identity is the perimeter, and this account is
built so that losing one login does not mean losing the account.
