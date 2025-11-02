"""AI Usage Tracking Service
 
Lightweight in-memory metrics collection for AI summary generation.
Provides aggregate counts for frontend RPA assistant (usage panel).
 
NOTE: For production, replace with persistent store & add per-user scoping.
"""
 
from datetime import datetime
from threading import Lock
from typing import Optional
 
 
class AIUsageService:
    def __init__(self):
        self._lock = Lock()
        self.total_calls = 0
        self.success_calls = 0
        self.fallback_calls = 0
        self.total_prompt_tokens = 0
        self.total_completion_tokens = 0
        self.last_model = None
        self.last_call_time = None
        self.last_error = None
 
    def record_call(self, success: bool, fallback_used: bool, model: str, prompt_tokens: int = 0, completion_tokens: int = 0, error: Optional[str] = None):
        with self._lock:
            self.total_calls += 1
            if success:
                self.success_calls += 1
            if fallback_used:
                self.fallback_calls += 1
            self.total_prompt_tokens += prompt_tokens or 0
            self.total_completion_tokens += completion_tokens or 0
            self.last_model = model
            self.last_call_time = datetime.utcnow().isoformat()
            self.last_error = error
 
    def get_usage(self) -> dict:
        with self._lock:
            success_rate = (self.success_calls / self.total_calls * 100) if self.total_calls else 0.0
            fallback_rate = (self.fallback_calls / self.total_calls * 100) if self.total_calls else 0.0
            return {
                "total_calls": self.total_calls,
                "success_calls": self.success_calls,
                "fallback_calls": self.fallback_calls,
                "success_rate": round(success_rate, 2),
                "fallback_rate": round(fallback_rate, 2),
                "total_prompt_tokens": self.total_prompt_tokens,
                "total_completion_tokens": self.total_completion_tokens,
                "last_model": self.last_model,
                "last_call_time": self.last_call_time,
                "last_error": self.last_error,
            }
 
 
# Global singleton instance
ai_usage_service = AIUsageService()
 
 