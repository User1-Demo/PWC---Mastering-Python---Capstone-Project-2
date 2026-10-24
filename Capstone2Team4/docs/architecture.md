# CloudGuard architecture and data model

## Runtime architecture

```mermaid
flowchart LR
    Client[CLI or HTTPS client] --> API[FastAPI API]
    API --> Auth[JWT authentication and RBAC]
    API --> DB[(PostgreSQL or local SQLite)]
    API --> Dispatcher[Inline or Kubernetes Job dispatcher]
    Cron[Kubernetes CronJob] --> Dispatcher
    Dispatcher --> ScanJob[Scan worker]
    Dispatcher --> RemediationJob[Remediation worker]
    ScanJob --> Rules[Pluggable policy evaluator]
    Rules --> DB
    ScanJob --> AzureRead[Azure inventory provider]
    RemediationJob --> AzureWrite[Allowlisted Azure remediation provider]
    AzureRead --> Azure[Azure Resource Manager and Key Vault metadata]
    AzureWrite --> Azure
    AzureRead -. local tests .-> Mock[Mock Azure provider]
    AzureWrite -. local tests .-> Mock
    API --> Audit[Hash-linked audit events]
    ScanJob --> Audit
    RemediationJob --> Audit
```

In local development, scans run as FastAPI background tasks using SQLite and the deterministic mock provider. Kubernetes mode persists work records first, then dispatches separate Jobs that share the PostgreSQL database. The API service account can create Jobs but has no Azure identity. Scan and remediation workers use separate service accounts/identities so write permissions can be withheld from inventory workers. The scheduled CronJob runs `cloudguard schedule-all` and dispatches one scan Job per enabled subscription.

## Scan and approval workflows

```mermaid
sequenceDiagram
    actor Engineer
    participant API
    participant Worker
    participant Azure
    participant DB
    actor Officer
    Engineer->>API: POST /scans
    API->>DB: Save queued scan and audit event
    API->>Worker: Dispatch scan
    Worker->>Azure: Read resource inventory and secret metadata
    Worker->>DB: Save findings and scan completion
    Worker->>Worker: Apply only explicitly configured low-risk tag remediation
    Engineer->>API: POST /findings/{id}/remediate
    API->>DB: Queue high/critical action for approval
    Officer->>API: POST /findings/{id}/approve
    API->>Worker: Dispatch approved remediation Job
    Worker->>Azure: Deny the named exposed NSG rule or merge explicit tags
    Worker->>DB: Save result and append audit event
```

## Entity relationships

```mermaid
erDiagram
    USER ||--o{ AUDIT_LOG : performs
    USER ||--o{ REMEDIATION_ACTION : triggers
    USER ||--o{ FINDING_EXCEPTION : creates
    SUBSCRIPTION ||--o{ SCAN : contains
    SCAN ||--o{ FINDING : discovers
    POLICY_RULE ||--o{ FINDING : classifies
    FINDING ||--o{ REMEDIATION_ACTION : receives
    FINDING ||--o{ FINDING_EXCEPTION : may_have
    AUDIT_CHAIN_HEAD
```

The database stores subscription metadata and credential references only; no Azure client secret is stored in a Subscription row. `AuditLog.previous_hash` and `event_hash` link events, and a locked `AuditChainHead` serializes appends across PostgreSQL workers. This provides tamper detection, not independent immutable storage; export/anchor the chain outside the database for stronger audit evidence.
