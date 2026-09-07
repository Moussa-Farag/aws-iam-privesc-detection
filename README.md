# AWS IAM Privilege Escalation — Detection & Incident Response

## Summary
Deployed a deliberately vulnerable AWS IAM configuration (CloudGoat's `iam_privesc_by_rollback` scenario) and, operating as a restricted IAM user, identified and exploited a flaw allowing escalation from read-only IAM access to full administrative privileges by abusing the `iam:SetDefaultPolicyVersion` permission. Escalation was confirmed end-to-end via a before/after cross-service access test. The resulting activity was then investigated from the defender's side: retrieved from AWS CloudTrail, ingested into Splunk, and used to build and operationalize a real detection — a scheduled Splunk alert that was confirmed firing against the captured log data.

## Authorized Lab Disclaimer
All activity in this repository was performed against infrastructure I built, own, or was explicitly authorized to test (isolated VMs / a personal AWS sandbox account). No production systems, third-party assets, or real user data were accessed. Published for educational and professional-demonstration purposes only.

## Environment / Architecture
- AWS account: personal lab account, isolated from any production use, with $5/$10 monthly budget alerts configured
- Scenario: CloudGoat `iam_privesc_by_rollback`, deployed via Terraform (`evidence/02-scenario-deployed.png`)
- IAM user `raynor-cgidwg95rcdjvv`: low-privilege attacker persona, granted only `iam:Get*`, `iam:List*`, and `iam:SetDefaultPolicyVersion`
- Customer-managed IAM policy `cg-raynor-policy-cgidwg95rcdjvv`, retaining 5 historical versions
- Two local AWS CLI profiles used throughout: `default` (the `lab-admin` IAM user — builder/defender identity) and `raynor` (attacker identity), kept strictly separate
- Splunk Enterprise (local instance), with a dedicated `aws_cloudtrail` index holding reshaped CloudTrail log data

## Objective & Scope
Determine whether the IAM user Raynor could escalate from his granted read-only IAM permissions to full administrative access by abusing IAM policy version history; confirm the escalation with a working proof; and, from the defender's perspective, determine whether the activity was logged, build a detection that would catch it, and document remediation. Testing was limited to the CloudGoat-provisioned resources listed above.

## Methodology
1. Deployed the CloudGoat `iam_privesc_by_rollback` scenario via Terraform, provisioning the IAM user and policy described above (`evidence/02-scenario-deployed.png`).
2. Configured a dedicated AWS CLI profile for Raynor, kept separate from the administrative profile used to build the lab.
3. Enumerated IAM policies attached to Raynor's user via `iam:ListAttachedUserPolicies`.
4. Listed all 5 saved versions of the attached policy via `iam:ListPolicyVersions` to identify exposed version history.
5. Retrieved and reviewed the JSON document for each of the 5 policy versions individually to determine the actual permissions each one granted.
6. Established a permission baseline by attempting `ec2:DescribeInstances` under Raynor's original policy version (`v1`) — confirmed denied with `UnauthorizedOperation`.
7. Executed the privilege escalation by calling `iam:SetDefaultPolicyVersion` to set `v3` (unrestricted `Action: *` / `Resource: *`) as the active policy version.
8. Re-tested the identical `ec2:DescribeInstances` call, which succeeded — confirming successful escalation from a read-only IAM scope to full administrative access.
9. Confirmed the escalation event was automatically captured in AWS CloudTrail's default Event History, without requiring a dedicated Trail, since it is a management-plane action.
10. Retrieved Raynor's full CloudTrail activity via `aws cloudtrail lookup-events`, reshaped the nested event data with `jq` into one JSON object per line, and ingested it into a dedicated Splunk index (`aws_cloudtrail`).
11. Authored two SPL detections (`detections/aws-iam-privesc-by-rollback.spl`): a baseline search flagging any `SetDefaultPolicyVersion` call, and a correlation search grouping the recon step (`ListPolicyVersions`) and the exploit step (`SetDefaultPolicyVersion`) by actor and policy within a 10-minute window.
12. Operationalized the correlation search as a scheduled Splunk alert (cron, every 15 minutes; trigger: results > 0) and confirmed it fired correctly against the captured log data on two separate scheduled runs.

## Findings
| ID | Severity | Description | Evidence | Reference |
|----|----------|-------------|----------|-----------|
| F1 | Critical | IAM policy `cg-raynor-policy-cgidwg95rcdjvv` grants `iam:SetDefaultPolicyVersion` without restricting which historical version may be restored. Version `v3` grants unrestricted `Action: *` / `Resource: *`. A user with only read-level IAM access used this to unilaterally restore full administrative privileges, confirmed via a before/after cross-service access test (denied → succeeded on an identical `ec2:DescribeInstances` call). | `evidence/03-policy-v1-baseline.json`, `evidence/04-admin-policy-version.json`, `evidence/05-before-escalation-denied.txt`, `evidence/06-after-escalation-success.txt` | MITRE ATT&CK T1548.005 (Abuse Elevation Control Mechanism); CWE-269 (Improper Privilege Management) |
| F2 | Informational | Policy version history contained 3 additional non-exploitable versions reviewed and ruled out during analysis: `v2` (a Deny-all statement scoped to unrelated source IPs), `v4` (limited to `iam:Get*`, restricted to an expired 2017 date range), and `v5` (limited to three read-only S3 actions). | `evidence/03a-policy-versions-list.json` | — |

## Detection & Remediation

**Detection.** The `SetDefaultPolicyVersion` call was automatically captured by AWS CloudTrail's default Event History (`evidence/08-cloudtrail-privesc-event.json`). The full activity timeline for Raynor's session was retrieved via `aws cloudtrail lookup-events`, reshaped with `jq` into one JSON event per line (`evidence/07-cloudtrail-events.ndjson`), and ingested into a local Splunk instance under a dedicated `aws_cloudtrail` index.

Two SPL detections were authored (`detections/aws-iam-privesc-by-rollback.spl`):
- A baseline search flagging every `SetDefaultPolicyVersion` call for review, since the action is rare in normal operations.
- A correlation search grouping `ListPolicyVersions` (recon) and `SetDefaultPolicyVersion` (exploitation) by actor and target policy within a 10-minute window — a stronger behavioral signal than either event alone.

The correlation search was operationalized as a scheduled Splunk alert (cron, every 15 minutes; trigger condition: results > 0) and confirmed firing against real log data on two separate scheduled runs (`evidence/09-splunk-detection-results.png`, `evidence/10-splunk-alert-config.png`, `evidence/11-splunk-alert-fired.png`).

**Remediation.**
1. Remove `iam:SetDefaultPolicyVersion` from any identity without an explicit, documented need for it; where required, scope it with an IAM policy condition restricting it to specific policy ARNs.
2. Enforce a policy lifecycle process that actively deletes unused historical policy versions (`iam:DeletePolicyVersion`) rather than allowing up to 5 to accumulate indefinitely — this removes the rollback attack surface at its source.
3. Deploy the detection built here (or an equivalent) in production, alerting on any `SetDefaultPolicyVersion` call, with the correlation search as a higher-fidelity secondary signal.
4. Periodically review IAM policies and roles against least-privilege using AWS IAM Access Analyzer, rather than relying on point-in-time manual review.

**Control mapping:** MITRE ATT&CK M1026 (Privileged Account Management); NIST 800-53 AC-6 (Least Privilege); CIS AWS Foundations Benchmark §1 (Identity and Access Management).

## Lessons Learned
- IAM policy version history is an underappreciated attack surface — a permissions review that only checks the current default version misses this class of vulnerability entirely.
- AWS CloudTrail's default Event History is immediately useful for investigation without needing to provision a dedicated Trail or S3 bucket first — a fast starting point before building a full logging pipeline.
- A correlation-based detection (grouping related events by actor and resource within a time window) is a meaningfully stronger signal than alerting on a single event in isolation, at the cost of added SPL complexity.
- IAM permission changes are not always instantaneous — validating a privilege escalation end-to-end needs to account for propagation delay, not just command success or failure.
- Given more time, next steps would include a complementary detection for abnormal policy version deletion/creation activity, and forwarding logs into a dedicated CloudTrail Trail with S3 delivery for retention beyond the default 90 days.
