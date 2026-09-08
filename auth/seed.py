from auth.security import hash_password
from common.database import SessionLocal
from common.models import UserRow

DEFAULT_USERNAME = "admin"
DEFAULT_PASSWORD = "changeme123"
WARNING_MSG = "WARNING: Default admin credentials in use. Change before any real deployment."


def seed_default_user() -> None:
    db = SessionLocal()
    try:
        if db.query(UserRow).count() > 0:
            return
        db.add(
            UserRow(
                username=DEFAULT_USERNAME,
                hashed_password=hash_password(DEFAULT_PASSWORD),
            )
        )
        db.commit()
        print(WARNING_MSG)
    finally:
        db.close()
