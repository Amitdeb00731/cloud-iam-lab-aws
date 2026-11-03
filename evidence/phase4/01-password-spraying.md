# Technique 1: password spraying and console brute force

| | |
| --- | --- |
| **ATT&CK** | T1110.003 (Brute Force: Password Spraying) |
| **Tactic** | Credential Access |
| **Source** | CloudTrail `ConsoleLogin` events |
| **Detection** | `detections/aws/01-password-spraying.sql`, `detections/sigma/01-password-spraying.yml` |
| **Score** | **Detected** |

## Validation action

From a single host, a series of deliberately wrong console sign-ins was made
against the `operator` IAM user, together with a few attempts against made-up
usernames (to model an attacker guessing accounts). One legitimate sign-in
succeeded in the middle of the run. Nothing was locked out; the actions only
produce failed `ConsoleLogin` events from one source. All activity is in the lab
account against a test identity.

## Raw event

A representative failed sign-in, source IP redacted (it is a home address):

```
eventtime:     2026-11-03T19:28:03Z
awsregion:     eu-north-1
eventname:     ConsoleLogin
id_type:       IAMUser
username:      operator
sourceip:      <test host, IP redacted>
login_result:  Failure
errormessage:  Failed authentication
```

## Alert record

The detection query returned one row, so the detection fired:

```
sourceipaddress:   <test host, IP redacted>
failed_attempts:   9
distinct_accounts: 2
accounts:          [HIDDEN_DUE_TO_SECURITY_REASONS, operator]
first_seen:        2026-11-03T19:23:33Z
last_seen:         2026-11-03T19:28:54Z
```

Nine failed sign-ins from one source in roughly five minutes crosses the
five-failure threshold, so the alert is raised.

## Finding: AWS masks non-existent usernames

The attempts against made-up usernames did not appear under those names. AWS
recorded them as `HIDDEN_DUE_TO_SECURITY_REASONS`, a deliberate measure to stop
an attacker from enumerating valid accounts through the sign-in page. This has
two consequences for the detection:

- A run of `HIDDEN_DUE_TO_SECURITY_REASONS` failures from one source is itself a
  username-guessing indicator worth surfacing.
- Because every unknown username collapses into that one bucket, the
  distinct-account signal will not count a spray against unknown usernames as
  many accounts. Against unknown usernames the failure-volume branch is what
  catches the activity; the distinct-account branch catches a spray against
  usernames the attacker already knows.

## Tuning

- Single-account failure volume overlaps a legitimate user mistyping a password,
  and this run shows exactly that pattern, failures followed by a success for the
  same account. On its own it is a lower-confidence signal, so the detection
  also carries the distinct-account branch and, in production, the alert should
  be paired with context such as whether a success followed from the same source.
- Once a known-good corporate egress IP is identified, exclude it so routine
  typos from the office do not raise the alert.

## Score rationale

**Detected.** The detection fires reliably on the failure-volume branch, proven
here. The distinct-account branch covers the purer spray case against known
usernames. The honest limitation is that single-account volume is noisier than a
true multi-account spray, which is why both branches and the tuning context are
documented rather than relying on volume alone.
