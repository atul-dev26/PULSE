from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
import os

_db_path = os.environ.get("DATABASE_PATH", "data/ulpf.db")
os.makedirs(os.path.dirname(_db_path), exist_ok=True)
SQLALCHEMY_DATABASE_URL = f"sqlite:///{_db_path}"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
