import time
from unittest.mock import MagicMock

from ptp_client.ptp.g82752_unicast import G82752UnicastSession
from ptp_client.ptp.header import PortIdentity


def test_seconds_until_renewal() -> None:
    client = MagicMock()
    client.domain_number = 44
    our = PortIdentity(b"\x00\x01\x02\x03\x04\x05\x06\x07", 1)
    session = G82752UnicastSession(
        client=client,
        our_identity=our,
        domain_number=44,
        duration_sec=300,
    )
    session._mark_contract_started()
    assert session._seconds_until_renewal() > 200.0
    session._contract_started_at = time.monotonic() - 230.0
    assert session._seconds_until_renewal() <= 0.0
