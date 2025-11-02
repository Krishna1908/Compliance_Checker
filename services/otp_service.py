"""OTP Service - manages email-based one-time passwords (dev mode returns OTP in response)"""
import os, json, random, time
from typing import Dict, Optional
 
OTP_STORE_FILE = os.path.join("uploads", "otp_codes.json")
OTP_EXP_SECONDS = 300  # 5 minutes
 
os.makedirs("uploads", exist_ok=True)
 
class OTPService:
    def __init__(self):
        self._load()
 
    def _load(self):
        if os.path.exists(OTP_STORE_FILE):
            try:
                with open(OTP_STORE_FILE, 'r') as f:
                    self.store: Dict[str, Dict] = json.load(f)
            except Exception:
                self.store = {}
        else:
            self.store = {}
 
    def _save(self):
        try:
            with open(OTP_STORE_FILE, 'w') as f:
                json.dump(self.store, f, indent=2)
        except Exception as e:
            print(f"Failed saving OTP store: {e}")
 
    def generate_otp(self, email: str) -> str:
        otp = f"{random.randint(100000, 999999)}"
        self.store[email] = {"otp": otp, "ts": int(time.time())}
        self._save()
        return otp
 
    def verify_otp(self, email: str, otp: str) -> bool:
        data = self.store.get(email)
        if not data:
            return False
        if int(time.time()) - data["ts"] > OTP_EXP_SECONDS:
            return False
        return data["otp"] == otp