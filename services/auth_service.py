"""Auth Service - user management and authentication logic"""
import os
import json
from typing import Optional, Dict, List, Any
from datetime import datetime
from passlib.context import CryptContext
try:
    import bcrypt  # noqa: F401
    _bcrypt_available = True
except Exception:
    _bcrypt_available = False
 
USERS_FILE = os.path.join("uploads", "users.json")
os.makedirs("uploads", exist_ok=True)
 
# Prefer bcrypt; fall back to pbkdf2_sha256 if bcrypt backend not importable
schemes = ["bcrypt", "pbkdf2_sha256"] if not _bcrypt_available else ["bcrypt", "pbkdf2_sha256"]
pwd_context = CryptContext(schemes=schemes, deprecated="auto")
if not _bcrypt_available:
    print("[AuthService] bcrypt backend not available; falling back to pbkdf2_sha256.")
 
class AuthService:
    def __init__(self):
        self.users: Dict[str, Dict] = self._load_users()
        # Apply legacy fallback display_name for previously created users (before name field existed)
        changed = False
        for uname, u in self.users.items():
            if self._apply_legacy_display_name(u):
                changed = True
        if changed:
            self._save()
 
    # --- user directory helpers ---
    def _sanitize(self, username: str) -> str:
        # keep it simple & filesystem safe
        return username.lower().replace('@', '__at__').replace('.', '_')
 
    def user_dir(self, username: str) -> str:
        return os.path.join('uploads', 'users', self._sanitize(username))
 
    def ensure_user_dir(self, username: str):
        path = self.user_dir(username)
        os.makedirs(path, exist_ok=True)
        return path
 
    def write_user_profile(self, username: str, data: Dict[str, Any]):
        path = self.ensure_user_dir(username)
        try:
            with open(os.path.join(path, 'profile.json'), 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            print(f"Failed writing profile for {username}: {e}")
 
    def _load_users(self) -> Dict[str, Dict]:
        if os.path.exists(USERS_FILE):
            try:
                with open(USERS_FILE, 'r') as f:
                    data = json.load(f)
                # ensure structure
                return data if isinstance(data, dict) else {}
            except Exception as e:
                print(f"Failed to load users.json: {e}")
        return {}
 
    def _save(self):
        try:
            with open(USERS_FILE, 'w') as f:
                json.dump(self.users, f, indent=2)
        except Exception as e:
            print(f"Failed to save users.json: {e}")
 
    def hash_password(self, password: str) -> str:
        # bcrypt only uses first 72 bytes; proactively truncate to avoid passlib errors
        if len(password) > 72:
            password = password[:72]
        try:
            return pwd_context.hash(password)
        except Exception as e:
            print(f"[AuthService] Hash error with bcrypt: {e}; retrying with pbkdf2_sha256")
            # force scheme override fallback
            return CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto").hash(password)
 
    def verify_password(self, plain: str, hashed: str) -> bool:
        try:
            return pwd_context.verify(plain, hashed)
        except Exception as e:
            print(f"[AuthService] Verify error: {e}; attempting pbkdf2_sha256")
            ctx = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")
            # If original hash was bcrypt but backend missing, this will fail; treat as False
            try:
                return ctx.verify(plain, hashed)
            except Exception:
                return False
 
    def get_user(self, username: str) -> Optional[Dict]:
        u = self.users.get(username)
        if u and self._apply_legacy_display_name(u):
            self._save()
        return u
 
    def create_user(self, username: str, password: str, role: str = "user", display_name: Optional[str] = None) -> Dict:
        if username in self.users:
            raise ValueError("Username already exists")
        # Normalize role aliases
        role_alias = {
            'business_user': 'business',
            'business': 'business',
            'dev': 'developer'
        }
        role = role_alias.get(role.lower(), role.lower())
        if role not in {"admin", "auditor", "user", "developer", "business"}:
            raise ValueError("Invalid role")
        user = {
            "username": username,
            "password_hash": self.hash_password(password),
            "role": role,
            "created_at": datetime.utcnow().isoformat(),
            "active": True,
            "last_login": None,
            "storage_path": self.user_dir(username),
            "display_name": display_name.strip() if isinstance(display_name, str) and display_name.strip() else None
        }
        # legacy fallback if no display_name provided for known email
        self._apply_legacy_display_name(user)
        self.users[username] = user
        self._save()
        # create user folder & profile snapshot (excluding password hash)
        profile_snapshot = user.copy(); profile_snapshot.pop('password_hash')
        self.write_user_profile(username, profile_snapshot)
        # hide hash in response
        safe = user.copy()
        safe.pop("password_hash")
        return safe
 
    def authenticate(self, username: str, password: str) -> Optional[Dict]:
        user = self.get_user(username)
        if not user:
            return None
        if not user.get("active", True):
            return None
        if not self.verify_password(password, user["password_hash"]):
            return None
        user["last_login"] = datetime.utcnow().isoformat()
        # ensure legacy display_name present if applicable
        self._apply_legacy_display_name(user)
        self._save()
        safe = user.copy()
        safe.pop("password_hash")
        return safe
 
    def list_users(self) -> List[Dict]:
        out = []
        for u in self.users.values():
            s = u.copy(); s.pop("password_hash", None)
            self._apply_legacy_display_name(s)
            out.append(s)
        return out
 
    def update_user_role(self, username: str, new_role: str) -> Dict:
        user = self.get_user(username)
        if not user:
            raise ValueError("User not found")
        role_alias = {
            'business_user': 'business',
            'business': 'business',
            'dev': 'developer'
        }
        new_role = role_alias.get(new_role.lower(), new_role.lower())
        if new_role not in {"admin", "auditor", "user", "developer", "business"}:
            raise ValueError("Invalid role")
        user['role'] = new_role
        self._apply_legacy_display_name(user)
        self._save()
        safe = user.copy(); safe.pop('password_hash', None)
        self._apply_legacy_display_name(safe)
        # update profile snapshot
        self.write_user_profile(username, safe)
        return safe
 
    # --- internal helpers ---
    def _apply_legacy_display_name(self, user: Dict) -> bool:
        """Assign display_name for legacy user accounts created before the name field existed.
        We support both the correct and a common misspelled email variant to be forgiving."""
        if not user:
            return False
        if user.get('display_name'):
            return False
        uname = user.get('username')
        if uname in {'tejpandu6@gmail.com', 'tejpandu6@gmial.com'}:
            user['display_name'] = 'krishna lingala'
            return True
        return False
 