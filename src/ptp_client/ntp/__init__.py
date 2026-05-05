"""NTP/SNTP client (RFC 5905)."""

from ptp_client.ntp.client import NTPClient, NTPExchangeResult
from ptp_client.ntp.packet import NTPPacket, NTPTime, NTPVersion

__all__ = [
    "NTPClient",
    "NTPExchangeResult",
    "NTPPacket",
    "NTPTime",
    "NTPVersion",
]
