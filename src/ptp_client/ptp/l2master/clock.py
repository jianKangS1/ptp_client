"""Clock source abstraction for the L2 master (software timestamping)."""

from __future__ import annotations

import time
from typing import Protocol

from ptp_client.ptp.timestamp import PTPTimestamp


class ClockSource(Protocol):
    def now_realtime_ns(self) -> int:
        """Wall-clock nanoseconds (CLOCK_REALTIME) — used for PTP timestamps."""
        ...

    def now_monotonic_ns(self) -> int:
        """Monotonic nanoseconds — used for scheduling / session ageing."""
        ...


class SystemClock:
    """Default clock source backed by the OS clock (software timestamping).

    ``time.time_ns`` maps to CLOCK_REALTIME and ``time.monotonic_ns`` to
    CLOCK_MONOTONIC on Linux; both are available on Windows as well.
    """

    def now_realtime_ns(self) -> int:
        return time.time_ns()

    def now_monotonic_ns(self) -> int:
        return time.monotonic_ns()

    def realtime_ptp_timestamp(self) -> PTPTimestamp:
        ns = self.now_realtime_ns()
        return PTPTimestamp(seconds=ns // 1_000_000_000, nanoseconds=ns % 1_000_000_000)
