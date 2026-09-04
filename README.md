# aws-iam-privesc-detection# AWS IAM Privilege Escalation — Detection & Incident Response

## Summary
Deployed a deliberately vulnerable AWS IAM configuration (CloudGoat's `iam_privesc_by_rollback` scenario) and, operating as a restricted IAM user, identified and exploited a flaw allowing escalation from read-only IAM access to full administrative privileges by abusing the `iam:SetDefaultPolicyVersion` permission. Findings below are being expanded into a full incident-response writeup including detection and remediation guidance.

## Authorized Lab Disclaimer
All activity in this repository was performed against infrastructure I built, own, or was explicitly authorized to test (isolated VMs / a personal AWS sandbox account). No production systems, third-party assets, or real user data were accessed. Published for educational and professional-demonstration purposes only.

## Environment / Architecture
- AWS account: personal lab account, isolated from any production use, with $5/$10 monthly budget alerts configured
- Scenario: CloudGoat `iam_privesc_by_rollback`, deployed via Terraform
- IAM user `raynor-cgidwg95rcdjvv`: low-privilege attacker persona, granted only `iam:Get*`, `iam:List*`, and `iam:SetDefaultPolicyVersion`
- Customer-managed IAM policy `cg-raynor-policy-cgidwg95rcdjvv`, retaining 5 historical versions
- Two local AWS CLI profiles used throughout: `lab-admin` (builder/defender identity) and `raynor` (attacker identity), kept strictly separate

## Objective & Scope
Determine whether the IAM user Raynor could escalate from his granted read-only IAM permissions to full administrative access by abusing IAM policy version history, and document the technique, evidence, and eventual detection/remediation. Testing was limited to the CloudGoat-provisioned resources listed above.

## Methodology
1. Deployed the CloudGoat `iam_privesc_by_rollback` scenario via Terraform, provisioning the IAM user and policy described above (`evidence/02-scenario-deployed.png`).
2. Configured a dedicated AWS CLI profile for Raynor, kept separate from the administrative profile used to build the lab.
3. Enumerated IAM policies attached to Raynor's user via `iam:ListAttachedUserPolicies`.
4. Listed all 5 saved versions of the attached policy via `iam:ListPolicyVersions` to identify exposed version history.
5. Retrieved and reviewed the JSON document for each of the 5 policy versions individually to determine the actual permissions each one granted.

## Findings
| ID | Severity | Description | Evidence | Reference |
|----|----------|-------------|----------|-----------|
| F1 | Critical | IAM policy `cg-raynor-policy-cgidwg95rcdjvv` grants `iam:SetDefaultPolicyVersion` without restricting which historical version may be restored. Version `v3` of the policy grants unrestricted `Action: *` / `Resource: *`, allowing a user with only read-level IAM access to unilaterally restore full administrative privileges. | `evidence/03-policy-v1-baseline.json`, `evidence/04-admin-policy-version.json` | MITRE ATT&CK T1548.005 (Abuse Elevation Control Mechanism); CWE-269 (Improper Privilege Management) |
| F2 | Informational | Policy version history contained 3 additional non-exploitable versions reviewed and ruled out during analysis: `v2` (a Deny-all statement scoped to unrelated source IPs), `v4` (limited to `iam:Get*`, restricted to an expired 2017 date range), and `v5` (limited to three read-only S3 actions). | `evidence/03a-policy-versions-list.json` | — |

## Detection & Remediation
_In progress — to be completed once CloudTrail logging and detection are built out._

## Lessons Learned
_To be completed at the end of the sprint._# aws-iam-privesc-detection
