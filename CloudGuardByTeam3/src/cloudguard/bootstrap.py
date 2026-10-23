from sqlalchemy import select
from cloudguard.core.config import settings
from cloudguard.core.security import hash_password
from cloudguard.db.base import Base
from cloudguard.db.session import SessionLocal, engine
from cloudguard.models import User, UserRole

def bootstrap() -> None:
    Base.metadata.create_all(engine)
    with SessionLocal() as db:
        existing = db.scalar(select(User).where(User.email == settings.bootstrap_admin_email))
        if not existing:
            db.add(User(email=settings.bootstrap_admin_email, full_name="CloudGuard Admin", hashed_password=hash_password(settings.bootstrap_admin_password), role=UserRole.ADMIN))
            db.commit(); print(f"Created admin: {settings.bootstrap_admin_email}")
        else: print("Admin already exists")
if __name__ == "__main__": bootstrap()
