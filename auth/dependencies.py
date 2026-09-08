from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from auth.jwt import decode_access_token
from common.database import get_db
from common.models import UserRow

security = HTTPBearer(auto_error=False)


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(security),
    db: Session = Depends(get_db),
) -> UserRow:
    if credentials is None:
        raise HTTPException(status_code=401, detail="Not authenticated")
    username = decode_access_token(credentials.credentials)
    if username is None:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    user = db.query(UserRow).filter(UserRow.username == username).first()
    if user is None:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    return user
