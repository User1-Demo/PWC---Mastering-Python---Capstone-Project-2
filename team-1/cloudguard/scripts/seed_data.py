from cloudguard.database import SessionLocal, init_db
from cloudguard import models, security


def seed():
    init_db()
    db = SessionLocal()
    if not db.query(models.User).filter_by(email="admin@cloudguard.io").first():
        db.add(models.User(email="admin@cloudguard.io",
                            hashed_password=security.hash_password("Admin@123"),
                            role=models.RoleEnum.ADMIN))
    if not db.query(models.User).filter_by(email="secoff@cloudguard.io").first():
        db.add(models.User(email="secoff@cloudguard.io",
                            hashed_password=security.hash_password("SecOff@123"),
                            role=models.RoleEnum.SECURITY_OFFICER))
    db.commit()

    if not db.query(models.PolicyRule).first():
        db.add_all([
            models.PolicyRule(name="required-tags", rule_type="tagging", resource_type="vm",
                               condition={"required_tags": ["environment", "owner"]},
                               severity=models.SeverityEnum.MEDIUM, auto_remediate=True),
            models.PolicyRule(name="no-open-admin-ports", rule_type="nsg", resource_type="nsg",
                               condition={"risky_ports": ["22", "3389"], "disallow_any_source": True},
                               severity=models.SeverityEnum.HIGH, auto_remediate=False),
            models.PolicyRule(name="idle-disk-check", rule_type="idle_resource", resource_type="disk",
                               condition={}, severity=models.SeverityEnum.LOW, auto_remediate=False),
            models.PolicyRule(name="secret-expiry-check", rule_type="secret_expiry",
                               resource_type="keyvault_secret", condition={"warn_days": 30},
                               severity=models.SeverityEnum.MEDIUM, auto_remediate=False),
        ])
        db.commit()
    db.close()
    print("Seed complete.")


if __name__ == "__main__":
    seed()