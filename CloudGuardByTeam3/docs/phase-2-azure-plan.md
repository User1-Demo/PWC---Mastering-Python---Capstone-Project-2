# Phase 2 Azure integration plan
1. Authenticate locally with Azure CLI and `DefaultAzureCredential`.
2. Validate tenant and subscription identifiers without storing a secret in the database.
3. Add Resource Management, Compute, Network, Disk, and Key Vault inventory adapters.
4. Normalize Azure SDK objects into internal resource schemas.
5. Mock SDK clients in unit tests and use a sandbox subscription for integration tests.
6. Apply least-privilege read roles first; add narrowly scoped write permissions only for approved remediation.
