# CloudGuard — Database Design

## Entity Relationship Summary

## Entities

### User
Stores login credentials and role (admin, cloud_engineer, security_officer,
service_account). Passwords are stored as bcrypt hashes, never plaintext.

### Subscription
Represents a registered Azure subscription. Stores metadata only —
`credential_ref` points to a Kubernetes Secret / Key Vault entry; actual
credentials are never stored in this table.

### PolicyRule
Defines a compliance check: rule_type (tagging, nsg, idle_resource,
secret_expiry), resource_type, condition (JSON), severity, and whether it's
pre-approved for auto-remediation.

### Scan
One scan run against one subscription. Tracks status, resource/finding
counts, and timestamps. Created by API trigger, CLI trigger, or scheduler.

### Finding
A single detected violation — linked to the scan, subscription, and rule
that caused it. Tracks severity and status (open, pending_approval,
remediated, exception, closed).

### RemediationAction
A record of an attempted fix against a finding. Tracks status, who
triggered it, attempt count, and result. Required for every remediated or
rejected finding (BR-003, BR-008).

### Exception
An approved, time-bound exemption for a specific finding. Always has an
expiry_date (BR-004) — findings under exception are excluded from "open"
counts until expiry.

### AuditLog
Immutable, hash-chained record of every significant action (scan
started/completed, finding detected, remediation attempted,
approval granted, policy changed, user login). Each record stores a hash
of the previous record, forming a tamper-evident chain.

## Data Validation Rules

- `PolicyRule.condition` is validated against a known schema per
  `rule_type` before being saved (see `schemas.py` — `SUPPORTED_RULE_TYPES`).
- `Exception.expiry_date` must be in the future at creation time.
- `RemediationAction` is always linked to exactly one `Finding` and one
  `triggered_by` actor (user ID or "service_account").