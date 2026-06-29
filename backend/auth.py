import datetime
import hmac
import hashlib
import json
import base64
from typing import Optional
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from database import get_db
from models import User

# Configuration
SECRET_KEY = "TIZEN_GRC_PLATFORM_SUPER_SECRET_SECURITY_KEY"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 1440  # 24 Hours

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/auth/login")

# --- Hashing Helper (Pure Python SHA-256 Salting for portability) ---
def get_password_hash(password: str) -> str:
    """Hash a password using SHA-256 with a fixed salt."""
    salt = "TizenSecuritySalt123!"
    pw_hash = hashlib.sha256((password + salt).encode('utf-8')).hexdigest()
    return pw_hash

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify that a plain password matches the hashed password."""
    return get_password_hash(plain_password) == hashed_password


# --- JWT Token Helper (Pure Python HS256 token generator for zero external dependencies) ---
def base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode('utf-8').replace('=', '')

def base64url_decode(data: str) -> bytes:
    data += '=' * (4 - len(data) % 4)
    return base64.urlsafe_b64decode(data.encode('utf-8'))

def create_access_token(data: dict, expires_delta: Optional[datetime.timedelta] = None) -> str:
    """Generate a valid JWT token."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.datetime.utcnow() + expires_delta
    else:
        expire = datetime.datetime.utcnow() + datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({"exp": int(expire.timestamp())})
    
    header = {"alg": "HS256", "typ": "JWT"}
    header_json = json.dumps(header, separators=(',', ':')).encode('utf-8')
    payload_json = json.dumps(to_encode, separators=(',', ':')).encode('utf-8')
    
    encoded_header = base64url_encode(header_json)
    encoded_payload = base64url_encode(payload_json)
    
    signing_input = f"{encoded_header}.{encoded_payload}".encode('utf-8')
    signature = hmac.new(SECRET_KEY.encode('utf-8'), signing_input, hashlib.sha256).digest()
    encoded_signature = base64url_encode(signature)
    
    return f"{encoded_header}.{encoded_payload}.{encoded_signature}"

def decode_access_token(token: str) -> Optional[dict]:
    """Decode and verify a JWT token."""
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return None
        
        encoded_header, encoded_payload, encoded_signature = parts
        signing_input = f"{encoded_header}.{encoded_payload}".encode('utf-8')
        expected_signature = hmac.new(SECRET_KEY.encode('utf-8'), signing_input, hashlib.sha256).digest()
        
        if not hmac.compare_digest(base64url_decode(encoded_signature), expected_signature):
            return None
        
        payload = json.loads(base64url_decode(encoded_payload).decode('utf-8'))
        exp = payload.get("exp")
        if exp and datetime.datetime.utcnow().timestamp() > exp:
            return None  # Expired
            
        return payload
    except Exception:
        return None


# --- Authentication Dependency ---
def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    """FastAPI Dependency to get current authenticated user using JWT."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    payload = decode_access_token(token)
    if payload is None:
        raise credentials_exception
        
    username: str = payload.get("sub")
    if username is None:
        raise credentials_exception
        
    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise credentials_exception
        
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Inactive user")
        
    return user


# --- Role Validation Helpers ---
class RoleChecker:
    """Helper to enforce role checks on endpoints."""
    def __init__(self, allowed_roles: list):
        self.allowed_roles = allowed_roles

    def __call__(self, current_user: User = Depends(get_current_user)):
        if current_user.role not in self.allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Operation not permitted. Required roles: {self.allowed_roles}"
            )
        return current_user
