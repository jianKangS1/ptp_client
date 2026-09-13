"""Slave session table with ageing, capacity eviction and rate limiting (design doc §5.5)."""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Optional

from ptp_client.ptp.header import PortIdentity


@dataclass
class SlaveSession:
    port_identity: PortIdentity
    src_mac: bytes
    last_seen: float  # time.monotonic()
    delay_req_count: int = 0
    delay_resp_sent: int = 0
    delay_resp_dropped: int = 0
    _tokens: float = field(default=0.0, repr=False)
    _token_ts: float = field(default=0.0, repr=False)

    def key(self) -> tuple[bytes, int]:
        return (self.port_identity.clock_identity, self.port_identity.port_number)


class TokenBucket:
    """Simple token bucket used per-session for delay_resp_rate_limit (pps)."""

    def __init__(self, rate: float) -> None:
        self.rate = float(rate)
        self.capacity = max(1.0, float(rate))

    def allow(self, session: SlaveSession, now: float) -> bool:
        if self.rate <= 0:  # 0 = unlimited
            return True
        if session._token_ts == 0.0:
            session._tokens = self.capacity
        else:
            session._tokens = min(self.capacity, session._tokens + (now - session._token_ts) * self.rate)
        session._token_ts = now
        if session._tokens >= 1.0:
            session._tokens -= 1.0
            return True
        return False


class SessionTable:
    """Thread-safe map of PortIdentity → SlaveSession with ageing + FIFO eviction."""

    def __init__(
        self,
        *,
        max_slaves: int = 64,
        rate_limit_pps: float = 256.0,
        session_timeout_sec: float = 0.75,
    ) -> None:
        self.max_slaves = max(1, int(max_slaves))
        self.session_timeout_sec = session_timeout_sec
        self._bucket = TokenBucket(rate_limit_pps)
        self._sessions: dict[tuple[bytes, int], SlaveSession] = {}
        self._lock = threading.Lock()
        self.overflow_count = 0

    def register_or_touch(
        self, port_identity: PortIdentity, src_mac: bytes, now: Optional[float] = None
    ) -> tuple[Optional[SlaveSession], bool]:
        """Return (session, allowed). session=None when the table is full and the
        oldest session could not be evicted (overflow). allowed=False when the
        per-session rate limit rejects this Delay_Req."""
        now = now if now is not None else time.monotonic()
        key = (port_identity.clock_identity, port_identity.port_number)
        with self._lock:
            s = self._sessions.get(key)
            if s is None:
                if len(self._sessions) >= self.max_slaves:
                    self._evict_oldest(now)
                    if len(self._sessions) >= self.max_slaves:
                        self.overflow_count += 1
                        return None, False
                s = SlaveSession(port_identity=port_identity, src_mac=src_mac, last_seen=now)
                self._sessions[key] = s
            else:
                s.last_seen = now
                s.src_mac = src_mac
            s.delay_req_count += 1
            allowed = self._bucket.allow(s, now)
            if not allowed:
                s.delay_resp_dropped += 1
            return s, allowed

    def _evict_oldest(self, now: float) -> None:
        # First try aged-out sessions, then FIFO by last_seen.
        aged = [k for k, s in self._sessions.items() if now - s.last_seen > self.session_timeout_sec]
        if aged:
            for k in aged:
                del self._sessions[k]
            return
        oldest = min(self._sessions.values(), key=lambda s: s.last_seen)
        del self._sessions[oldest.key()]

    def mark_resp_sent(self, port_identity: PortIdentity) -> None:
        key = (port_identity.clock_identity, port_identity.port_number)
        with self._lock:
            s = self._sessions.get(key)
            if s is not None:
                s.delay_resp_sent += 1

    def age_out(self, now: Optional[float] = None) -> int:
        now = now if now is not None else time.monotonic()
        with self._lock:
            aged = [k for k, s in self._sessions.items() if now - s.last_seen > self.session_timeout_sec]
            for k in aged:
                del self._sessions[k]
            return len(aged)

    def snapshot(self) -> list[SlaveSession]:
        with self._lock:
            return [
                SlaveSession(
                    port_identity=s.port_identity,
                    src_mac=s.src_mac,
                    last_seen=s.last_seen,
                    delay_req_count=s.delay_req_count,
                    delay_resp_sent=s.delay_resp_sent,
                    delay_resp_dropped=s.delay_resp_dropped,
                )
                for s in self._sessions.values()
            ]

    def count(self) -> int:
        with self._lock:
            return len(self._sessions)
