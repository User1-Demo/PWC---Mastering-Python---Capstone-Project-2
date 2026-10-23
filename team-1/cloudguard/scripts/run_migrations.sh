#!/bin/bash
# Simple migration runner for CloudGuard.
# For MVP, we use SQLAlchemy's create_all() via init_db() instead of a full
# migration tool like Alembic. This script is a placeholder/entry point that
# teams can extend with Alembic if schema versioning becomes necessary.

set -e

echo "Running CloudGuard database initialization..."
python -c "from cloudguard.database import init_db; init_db()"
echo "Database initialized successfully."