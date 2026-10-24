# Real Azure environment deployment

CloudGuard starts in **mock mode** and uses a local SQLite database. This prevents accidental access to or mutation of an Azure subscription while developing. Live mode is opt-in and must be configured deliberately.

## Prerequisites

- An Azure tenant and a dedicated non-production subscription for initial testing.
- Azure CLI, Docker, `kubectl`, and an AKS or test Kubernetes cluster.
- A PostgreSQL database reachable by the API and worker pods (Azure Database for PostgreSQL is recommended for a shared environment).
- An Azure identity for the API and worker jobs. Prefer AKS Workload Identity / managed identity over client secrets.

## Azure identity setup for an existing AKS cluster

These commands configure an existing cluster and a dedicated test subscription; they do not create billable Azure resources. Replace the values first, and use a sandbox subscription rather than production.

```powershell
$env:SUBSCRIPTION_ID = "<sandbox-subscription-guid>"
$env:AKS_RESOURCE_GROUP = "<aks-resource-group>"
$env:AKS_NAME = "<aks-name>"
$env:SANDBOX_RESOURCE_GROUP = "<sandbox-resource-group>"
$env:IDENTITY_RESOURCE_GROUP = "<identity-resource-group>"
$env:IDENTITY_NAME = "cloudguard-workload"

az login
az account set --subscription $env:SUBSCRIPTION_ID
az account show --output table
az aks update --resource-group $env:AKS_RESOURCE_GROUP --name $env:AKS_NAME `
  --enable-oidc-issuer --enable-workload-identity
$issuer = az aks show --resource-group $env:AKS_RESOURCE_GROUP --name $env:AKS_NAME `
  --query oidcIssuerProfile.issuerUrl --output tsv
az identity create --resource-group $env:IDENTITY_RESOURCE_GROUP --name $env:IDENTITY_NAME
$clientId = az identity show --resource-group $env:IDENTITY_RESOURCE_GROUP `
  --name $env:IDENTITY_NAME --query clientId --output tsv
$principalId = az identity show --resource-group $env:IDENTITY_RESOURCE_GROUP `
  --name $env:IDENTITY_NAME --query principalId --output tsv
az identity federated-credential create --resource-group $env:IDENTITY_RESOURCE_GROUP `
  --identity-name $env:IDENTITY_NAME --name cloudguard-aks `
  --issuer $issuer --subject "system:serviceaccount:cloudguard:cloudguard" `
  --audiences "api://AzureADTokenExchange"
az role assignment create --assignee-object-id $principalId `
  --assignee-principal-type ServicePrincipal --role Reader `
  --scope "/subscriptions/$env:SUBSCRIPTION_ID/resourceGroups/$env:SANDBOX_RESOURCE_GROUP"
az aks get-credentials --resource-group $env:AKS_RESOURCE_GROUP --name $env:AKS_NAME
```

Reader is only a starting point for inventory, and should be scoped to the smallest sandbox resource group that contains the test resources when possible. In `k8s/rbac.yaml`, add this annotation under the ServiceAccount `metadata` using the `$clientId` output:

```yaml
annotations:
  azure.workload.identity/client-id: "<managed-identity-client-id>"
```

The SRS' supported NSG action and tag writes require additional write permission. Do not grant those permissions to the scan identity. For a disposable test resource group, use the separate remediation worker identity with a custom role containing only the resource-specific actions you tested, assign it only to that resource group, and federate it to `cloudguard-remediation-worker`. Key Vault secret-property listing also needs a narrowly scoped metadata-list permission; validate the exact data-plane role/action against your vault configuration. The application never calls the API that reads secret values.

If you do not yet have an AKS cluster, follow Microsoft's current AKS Workload Identity setup guidance and check estimated cost before creating one. The Kubernetes manifests target an existing cluster; this repository does not provision AKS, networking, PostgreSQL, ACR, or Key Vault resources.

## 1. Build and test locally first

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[test,dev]"
Copy-Item .env.example .env
cloudguard create-admin
cloudguard seed-defaults
uvicorn app.main:app --reload
```

Open `http://127.0.0.1:8000/docs`, log in at `POST /api/v1/auth/login`, register a fake subscription ID, and trigger a scan. The mock provider supplies representative VM, NSG, disk, and Key Vault-secret metadata fixtures. Run `ruff check .`, `mypy app`, and `pytest --cov --cov-report=term-missing --cov-fail-under=80` before proceeding.

## 2. Configure an Azure workload identity

For AKS, enable the OIDC issuer and Workload Identity, create or select a user-assigned managed identity, and add a federated identity credential for:

- Issuer: the AKS OIDC issuer URL.
- Subject: `system:serviceaccount:cloudguard:cloudguard-scan-worker`.
- Audience: `api://AzureADTokenExchange`.

Annotate the `cloudguard` ServiceAccount in `k8s/rbac.yaml` with the identity client ID, for example:

```yaml
metadata:
  annotations:
    azure.workload.identity/client-id: "<managed-identity-client-id>"
```

The scan-worker service account is configured for the AKS Workload Identity webhook. Annotate it with the scan identity's client ID:

```powershell
kubectl annotate serviceaccount cloudguard-scan-worker -n cloudguard `
  azure.workload.identity/client-id="<scan-managed-identity-client-id>" --overwrite
```

Create a second identity and federation only if you choose to enable approved writes:

```powershell
$env:REMEDIATION_IDENTITY_NAME = "cloudguard-remediation"
az identity create --resource-group $env:IDENTITY_RESOURCE_GROUP `
  --name $env:REMEDIATION_IDENTITY_NAME
$remediationClientId = az identity show --resource-group $env:IDENTITY_RESOURCE_GROUP `
  --name $env:REMEDIATION_IDENTITY_NAME --query clientId --output tsv
az identity federated-credential create --resource-group $env:IDENTITY_RESOURCE_GROUP `
  --identity-name $env:REMEDIATION_IDENTITY_NAME --name cloudguard-remediation-aks `
  --issuer $issuer --subject "system:serviceaccount:cloudguard:cloudguard-remediation-worker" `
  --audiences "api://AzureADTokenExchange"
kubectl annotate serviceaccount cloudguard-remediation-worker -n cloudguard `
  azure.workload.identity/client-id="$remediationClientId" --overwrite
```

The API and scheduled-scan pods use `cloudguard-api` and do not receive Azure tokens. Confirm the webhook is installed and that a scan worker pod can acquire a token before enabling live scans.

## 3. Grant least privilege

Start with **Reader** at the narrowest subscription/resource-group scope for inventory. Key Vault secret expiry enumeration uses secret *metadata* only (it never reads secret values); configure the narrowest Key Vault data-plane permission that permits listing secret properties and test it against a dedicated vault.

The `required_tags` remediation calls Azure Resource Manager to update tags. The optional `nsg_open_ports` remediation changes only the matched inbound allow rule's access to `Deny`, and only after an explicit approval. Keep remediation disabled until an administrator has reviewed the target scope and permissions. Grant the remediation identity only the necessary tag-write permission and `Microsoft.Network/networkSecurityGroups/read` / `Microsoft.Network/networkSecurityGroups/write` at approved resource scopes; do not use Owner or broad Contributor. The manifests and dispatcher use separate scan and remediation worker service accounts so those permissions can be separated.

Avoid assigning permanent credentials to users or putting client secrets in source control, images, manifests, or command history. If a non-federated identity is unavoidable for a local sandbox, store its credentials in an untracked local environment file or a managed secret store and rotate them after testing.

## 4. Prepare persistent storage and secrets

Create PostgreSQL and a TLS-protected connection string. Create the namespace and the runtime Kubernetes Secret outside the repository. The secret must contain at least:

- `DATABASE_URL`: `postgresql+psycopg://...` connection string.
- `JWT_SECRET`: unique random value, at least 32 characters.
- `AZURE_PROVIDER`: `azure`.
- `WORKER_IMAGE`: the exact registry/image:tag available to the cluster.
- Optional rule/retry settings such as `DEFAULT_REQUIRED_TAGS` and `REMEDIATION_MAX_RETRIES`.

Example (use an interactive/secret-manager workflow in production; this sample is for a disposable sandbox only):

```powershell
kubectl create namespace cloudguard
kubectl create secret generic cloudguard-secrets -n cloudguard `
  --from-literal=DATABASE_URL='postgresql+psycopg://USER:PASSWORD@HOST:5432/cloudguard?sslmode=require' `
  --from-literal=JWT_SECRET='REPLACE_WITH_A_RANDOM_VALUE_AT_LEAST_32_CHARACTERS' `
  --from-literal=AZURE_PROVIDER=azure `
  --from-literal=WORKER_IMAGE='ghcr.io/ORG/cloudguard:TAG'
```

Kubernetes Secrets are base64-encoded, not encrypted by default. Enable AKS etcd encryption, restrict RBAC, and preferably sync values from Azure Key Vault with a managed secret integration.

## 5. Deploy

Build and publish the image to a registry reachable by AKS, then set `image` in `k8s/api.yaml` and `k8s/cronjob.yaml` to that immutable image tag. Apply:

```powershell
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/rbac.yaml
kubectl apply -f k8s/api.yaml
kubectl apply -f k8s/cronjob.yaml
kubectl -n cloudguard rollout status deployment/cloudguard-api
kubectl -n cloudguard logs deployment/cloudguard-api
```

For Azure Container Registry, create/use an ACR, authenticate with `az acr login`, build/tag/push the `Dockerfile` image, and attach that registry to AKS (or configure an image-pull secret). Do not use `latest` for a real deployment.

The API's Kubernetes service account can create bounded scan/remediation Jobs. Each worker receives runtime settings through the pre-created Secret and uses the same PostgreSQL database. The CronJob starts at 02:00 UTC daily; adjust its schedule for your operating window.

Expose the ClusterIP Service only through an authenticated TLS ingress or private network. Configure ingress rate limits, TLS, and a production-grade authentication/token policy before opening the API to users.

## 6. Bootstrap and validate live access

Run the admin CLI as a one-off pod/job using the same image, database Secret, and Kubernetes workload identity; do not put bootstrap passwords in a checked-in manifest. Create the initial admin, then create separate cloud-engineer and security-officer accounts through `POST /api/v1/users`. Seed the starter policies with `python -m app.cli seed-defaults`.

Register only the sandbox subscription in the API. First run scans with remediation disabled. Check the scan result, expected tag/NSG findings, and audit chain at `GET /api/v1/audit-logs/verify`. Validate Key Vault metadata access without retrieving values. Then test remediation against a disposable resource group: first a single low-risk missing-tag rule whose `tag_values` are explicit and reviewed, then (if required) one explicitly configured high-risk `nsg_open_ports` rule with `remediation_action: "deny_exposed_rules"`. High/critical remediation must be requested by a user and explicitly approved by an Admin or Security Officer.

For a local sandbox scan (not Kubernetes), sign in with Azure CLI as a deliberately scoped test identity and start the API with `AZURE_PROVIDER=azure`, `EXECUTION_MODE=inline`, and `AUTO_REMEDIATE_LOW_RISK=false`. Keep the remediation role unassigned while validating inventory. This uses the local Azure CLI credential from `DefaultAzureCredential`; do not run it from a developer account with broad subscription write access.

## 7. CI/CD staging

The CI workflow runs pytest with the 80% coverage gate on Python 3.11/3.12 and builds the container. The manual staging workflow publishes a GitHub Container Registry image and deploys it to the `cloudguard` namespace. Configure a protected GitHub `staging` environment and its `KUBECONFIG_B64` secret, ensure the cluster can pull the image, and pre-create `cloudguard-secrets` in the target cluster. Restrict who can approve/use the environment and rotate the kubeconfig.

## Important limitations before production

- The project is an educational MVP. Use Alembic migrations, managed PostgreSQL backups, HTTPS ingress, rate limiting, alerting, and formal security review before production.
- The Azure generic resource tag update API version may differ by provider/resource. Test each allowed resource type in a disposable scope and adjust/allowlist resource API versions before granting write access.
- NSG evaluation checks explicit inbound allow rules, not every effective rule after subnet/NIC association or service tags. Treat findings as review candidates, not a complete network exposure proof.
- Idle VM detection uses CPU telemetry only when `average_cpu_percent` is included in normalized inventory. The default ARM inventory provider does not query Azure Monitor metrics; extend it with scoped Azure Monitor permissions before relying on idle results.
- Audit events use a hash-linked chain in the application database. This helps detect accidental/unauthorized row edits but is not independently tamper-proof against a database administrator. Export/anchor audit hashes to immutable storage for stronger evidence.
- The MVP stores user passwords locally and issues signed bearer tokens; integrate Entra ID/OIDC and a managed identity for production user authentication.
