"""Periodic transmission scheduling aligned to absolute time boundaries (design doc §5.3)."""

from __future__ import annotations

import math


def interval_sec(log_interval: int) -> float:
    return 2.0**log_interval


def next_boundary(now_sec: float, interval: float) -> float:
    """First multiple of ``interval`` strictly after ``now_sec``."""
    return (math.floor(now_sec / interval) + 1) * interval


class PeriodicScheduler:
    """Tracks the next absolute deadline for one message class.

    Deadlines are aligned to multiples of the interval on the CLOCK_REALTIME
    timeline (telecom requirement). If the loop wakes far too late (more than
    half an interval past the deadline), the current tick is skipped
    (``consume()`` returns it as skipped) and the deadline jumps to the next
    boundary.
    """

    def __init__(self, log_interval: int, now_sec: float) -> None:
        self.interval = interval_sec(log_interval)
        self.deadline = next_boundary(now_sec, self.interval)
        self.skipped = 0

    def due(self, now_sec: float) -> bool:
        return now_sec >= self.deadline

    def advance(self, now_sec: float) -> bool:
        """Move to the next deadline. Returns True if the current tick was skipped."""
        was_skipped = now_sec > self.deadline + self.interval / 2.0
        if was_skipped:
            self.skipped += 1
            self.deadline = next_boundary(now_sec, self.interval)
        else:
            self.deadline += self.interval
            # Catch up if we are still somehow past the new deadline.
            if self.deadline <= now_sec:
                self.deadline = next_boundary(now_sec, self.interval)
        return was_skipped

    def wait_timeout(self, now_sec: float) -> float:
        """Seconds to sleep until the deadline (>= 0)."""
        return max(0.0, self.deadline - now_sec)
