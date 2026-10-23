# Phase 1 architecture
Client -> FastAPI routers -> RBAC dependencies -> SQLAlchemy -> SQLite/PostgreSQL.
Phase 2 adds DefaultAzureCredential and Azure management clients behind an inventory service.
