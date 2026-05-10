#!/usr/bin/env python3
"""
Result Caching Layer for OSINT MCP Enterprise Gateway.
SHA256-based deduplication with TTL expiration.
"""

import hashlib
import json
import os
import time
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, Optional
from dataclasses import dataclass, asdict


CACHE_TTL_SECONDS = max(60, int(os.getenv("OSINT_CACHE_TTL_SECONDS", "3600")))
CACHE_DIR = Path(os.getenv("OSINT_CACHE_DIR", "cache"))
CACHE_ENABLED = os.getenv("OSINT_CACHE_ENABLED", "true").strip().lower() in {"1", "true", "yes"}


@dataclass
class CacheEntry:
    tool_name: str
    target: str
    result: Dict[str, Any]
    cached_at: str
    expires_at: str
    hit_count: int
    target_hash: str

    def is_expired(self) -> bool:
        try:
            expiry = datetime.fromisoformat(self.expires_at)
            return datetime.now(timezone.utc) > expiry
        except (ValueError, TypeError):
            return True

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CacheEntry":
        return cls(**data)


class OSINTCache:
    def __init__(self, cache_dir: Path = CACHE_DIR, ttl_seconds: int = CACHE_TTL_SECONDS):
        self.cache_dir = cache_dir
        self.ttl_seconds = ttl_seconds
        self._hits = 0
        self._misses = 0
        self._evictions = 0

        if CACHE_ENABLED:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            self._cleanup_expired()

    def _hash_target(self, tool_name: str, target: str) -> str:
        raw = f"{tool_name}:{target}".encode("utf-8", errors="ignore")
        return hashlib.sha256(raw).hexdigest()[:32]

    def _cache_file_path(self, target_hash: str) -> Path:
        return self.cache_dir / f"{target_hash}.json"

    def get(self, tool_name: str, target: str) -> Optional[Dict[str, Any]]:
        if not CACHE_ENABLED:
            return None

        target_hash = self._hash_target(tool_name, target)
        cache_file = self._cache_file_path(target_hash)

        if not cache_file.exists():
            self._misses += 1
            return None

        try:
            data = json.loads(cache_file.read_text(encoding="utf-8"))
            entry = CacheEntry.from_dict(data)

            if entry.is_expired():
                cache_file.unlink(missing_ok=True)
                self._evictions += 1
                self._misses += 1
                return None

            entry.hit_count += 1
            cache_file.write_text(
                json.dumps(entry.to_dict(), ensure_ascii=True),
                encoding="utf-8",
            )
            self._hits += 1
            return entry.result

        except (json.JSONDecodeError, KeyError, TypeError, OSError):
            self._misses += 1
            return None

    def set(self, tool_name: str, target: str, result: Dict[str, Any]) -> None:
        if not CACHE_ENABLED:
            return

        target_hash = self._hash_target(tool_name, target)
        now = datetime.now(timezone.utc)
        entry = CacheEntry(
            tool_name=tool_name,
            target=target,
            result=result,
            cached_at=now.isoformat(),
            expires_at=(now + timedelta(seconds=self.ttl_seconds)).isoformat(),
            hit_count=0,
            target_hash=target_hash,
        )

        cache_file = self._cache_file_path(target_hash)
        try:
            cache_file.write_text(
                json.dumps(entry.to_dict(), ensure_ascii=True),
                encoding="utf-8",
            )
        except OSError:
            pass

    def invalidate(self, tool_name: str, target: str) -> bool:
        target_hash = self._hash_target(tool_name, target)
        cache_file = self._cache_file_path(target_hash)
        if cache_file.exists():
            cache_file.unlink(missing_ok=True)
            return True
        return False

    def clear(self) -> int:
        count = 0
        for f in self.cache_dir.glob("*.json"):
            f.unlink(missing_ok=True)
            count += 1
        return count

    def _cleanup_expired(self) -> int:
        count = 0
        for f in self.cache_dir.glob("*.json"):
            try:
                data = json.loads(f.read_text(encoding="utf-8"))
                entry = CacheEntry.from_dict(data)
                if entry.is_expired():
                    f.unlink(missing_ok=True)
                    count += 1
            except (json.JSONDecodeError, KeyError, TypeError, OSError):
                f.unlink(missing_ok=True)
                count += 1
        return count

    def stats(self) -> Dict[str, Any]:
        total_requests = self._hits + self._misses
        hit_rate = (self._hits / total_requests * 100) if total_requests > 0 else 0.0
        file_count = len(list(self.cache_dir.glob("*.json"))) if self.cache_dir.exists() else 0

        return {
            "enabled": CACHE_ENABLED,
            "ttl_seconds": self.ttl_seconds,
            "cache_dir": str(self.cache_dir),
            "hits": self._hits,
            "misses": self._misses,
            "hit_rate_percent": round(hit_rate, 2),
            "evictions": self._evictions,
            "cached_entries": file_count,
        }

    def cleanup(self) -> Dict[str, int]:
        expired = self._cleanup_expired()
        return {"expired_entries_removed": expired}


osint_cache = OSINTCache()
