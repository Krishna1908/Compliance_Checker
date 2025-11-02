"""Authentication & RBAC routes (restricted demo)"""
from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import jwt, JWTError
from datetime import datetime, timedelta
from typing import Optional
from services.auth_service import AuthService
from services.otp_service import OTPService
from services.email_service import EmailService
import secrets
import os
 
SECRET_KEY = os.getenv("AUTH_SECRET", "dev-insecure-secret-change-me")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
 
router = APIRouter()
auth_service = AuthService()
otp_service = OTPService()
email_service = EmailService()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/token")
 
# Dynamic allowance: either env variable ALLOWED_EMAILS (comma separated, optional :role)
# or fallback to first two distinct emails seen. Limit remains 2.
def parse_env_allowed():
    raw = os.getenv("ALLOWED_EMAILS", "").strip()
    if not raw:
        return {}
    out = {}
    for part in raw.split(','):
        part = part.strip()
        if not part:
            continue
        if ':' in part:
            email, role = part.split(':', 1)
            out[email.lower()] = role or 'user'
        else:
            out[part.lower()] = 'user'
    # Cap at 2
    return dict(list(out.items())[:2])
 
ENV_ALLOWED = parse_env_allowed()
 
def current_dynamic_allowed():
    if ENV_ALLOWED:
        return ENV_ALLOWED
    # derive from existing users (limited to first two created)
    existing = [u['username'].lower() for u in auth_service.list_users()[:2]]
    roles_map = {u['username'].lower(): u['role'] for u in auth_service.list_users()[:2]}
    return {e: roles_map.get(e, 'user') for e in existing}
 
def can_accept_email(email_l: str) -> bool:
    allowed = current_dynamic_allowed()
    if ENV_ALLOWED:
        return email_l in allowed
    # dynamic: allow if already present OR less than 2 users total
    if email_l in allowed:
        return True
    return len(allowed) < 2
 
def assign_role_for(email_l: str) -> str:
    allowed = current_dynamic_allowed()
    if ENV_ALLOWED and email_l in ENV_ALLOWED:
        return ENV_ALLOWED[email_l]
    # dynamic assignment: first email becomes admin, second developer
    if len(allowed) == 0:
        return 'admin'
    if len(allowed) == 1 and email_l not in allowed:
        return 'developer'
    # existing or overflow
    return allowed.get(email_l, 'user')
 
class TokenPayload:
    def __init__(self, sub: str, role: str, exp: int):
        self.sub = sub
        self.role = role
        self.exp = exp
 
 
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
 
async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(status_code=401, detail="Could not validate credentials")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        role: str = payload.get("role")
        if username is None or role is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = auth_service.get_user(username)
    if not user:
        raise credentials_exception
    # enrich with display_name
    full_user = auth_service.get_user(username)
    display_name = full_user.get('display_name') if full_user else None
    return {"username": username, "role": role, "display_name": display_name}
 
def require_role(*allowed_roles):
    async def checker(current=Depends(get_current_user)):
        if current["role"] not in allowed_roles:
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        return current
    return checker
 
@router.post("/register")
async def register(username: str, password: str, role: str = "user", display_name: Optional[str] = None):
    try:
        safe = auth_service.create_user(username, password, role, display_name=display_name)
        return {"success": True, "user": safe}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
 
@router.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = auth_service.authenticate(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    access_token = create_access_token({"sub": user["username"], "role": user["role"]})
    return {"access_token": access_token, "token_type": "bearer", "role": user["role"], "display_name": user.get('display_name')}
 
@router.get("/me")
async def me(current=Depends(get_current_user)):
    # current already includes display_name
    return {"user": current}
 
@router.get("/users")
async def list_users(current=Depends(require_role("admin"))):
    return {"users": auth_service.list_users()}
 
@router.get("/roles")
async def list_roles(current=Depends(require_role("admin"))):
    """Return available roles and descriptions."""
    roles = {
        "admin": "System administrators with full access including user management and all configuration screens.",
        "business": "Business users who work with records & review duplicates; limited to business-focused screens.",
        "developer": "Technical users configuring schemas, rules, and pipelines (no user management).",
        "auditor": "Auditors with read-only access to compliance and reporting screens.",
        "user": "Basic users with limited access."}
    return {"roles": roles}
 
@router.post("/users/{username}/role")
async def update_role(username: str, new_role: str, current=Depends(require_role("admin"))):
    try:
        updated = auth_service.update_user_role(username.lower(), new_role)
        return {"success": True, "user": updated}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
 
@router.get("/admin/ping")
async def admin_ping(current=Depends(require_role("admin"))):
    return {"message": "admin ok"}
 
@router.get("/auditor/ping")
async def auditor_ping(current=Depends(require_role("auditor", "admin"))):
    return {"message": "auditor ok"}
 
@router.post("/otp/signup")
async def otp_signup(email: str, display_name: Optional[str] = None):
    """Explicitly register up to two emails BEFORE OTP login starts.
    Assigns roles (first admin, second developer). Creates user with random password.
    """
    email_l = email.lower().strip()
    if "@" not in email_l or "." not in email_l:
        raise HTTPException(status_code=400, detail="Invalid email format")
    # enforce capacity of two
    existing_users = [u['username'].lower() for u in auth_service.list_users()]
    if email_l in existing_users:
        return {"already": True, "email": email_l, "message": "Email already signed up"}
    if len(existing_users) >= 2:
        raise HTTPException(status_code=403, detail="Signup capacity reached (2 users).")
    role = 'admin' if len(existing_users) == 0 else 'developer'
    random_pass = secrets.token_urlsafe(16)
    try:
        user = auth_service.create_user(email_l, random_pass, role=role, display_name=display_name)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"success": True, "email": email_l, "role": role, "storage": user.get('storage_path'), "display_name": user.get('display_name')}
 
# OTP-based email login flow (requires prior signup)
@router.post("/otp/request")
async def request_otp(email: str, background: BackgroundTasks):
    email_l = email.lower().strip()
    if "@" not in email_l or "." not in email_l:
        raise HTTPException(status_code=400, detail="Invalid email format")
    if not auth_service.get_user(email_l):
        raise HTTPException(status_code=403, detail="Email not signed up. Call /api/auth/otp/signup first (limited to 2 emails).")
    otp = otp_service.generate_otp(email_l)
    background.add_task(email_service.send_otp_email, email_l, otp)
    sent = email_service.enabled
    resp = {"success": True, "email": email_l, "sent": sent, "message": "OTP dispatched" if sent else "OTP generated (dev mode)"}
    if not sent:
        resp["otp_dev"] = otp
    return resp
 
@router.post("/otp/verify")
async def verify_otp(email: str, otp: str):
    email_l = email.lower().strip()
    otp = otp.strip()
    if not auth_service.get_user(email_l):
        raise HTTPException(status_code=403, detail="Email not signed up. Call /api/auth/otp/signup first.")
    if not otp_service.verify_otp(email_l, otp):
        raise HTTPException(status_code=401, detail="Invalid or expired OTP")
    user = auth_service.get_user(email_l)
    token = create_access_token({"sub": email_l, "role": user["role"]})
    return {"access_token": token, "token_type": "bearer", "role": user["role"], "email": email_l, "display_name": user.get('display_name')}
 
@router.get("/email/status")
async def email_status(current=Depends(get_current_user)):
    """Check SMTP configuration & connectivity (admin only ideal, but allow both demo users)."""
    conn = email_service.test_connection()
    return {"enabled": email_service.enabled, "connection": conn}
 