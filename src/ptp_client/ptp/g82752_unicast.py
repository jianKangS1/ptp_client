"""
ITU-T G.8275.2 unicast negotiation (clause 6.6, Annex A.3.3–A.3.5).

Implements the request-port side of IEEE 1588 unicast negotiation using Signalling
messages on the general port:

- Phase 1: REQUEST Announce only; wait GRANT; wait first unicast Announce.
- Phase 2: REQUEST Sync (+ Delay_Resp for two-way) in one Signalling with multiple TLVs.
- Renewal: re-issue REQUEST before ``durationField`` expiry (configurable margin).
- Teardown: CANCEL_UNICAST_TRANSMISSION per active message type (optional ACK wait).

This does **not** implement full BTCA / alternateTimeTransmitter filtering — only the
Signalling contract exchange. Behaviour is aligned with G.8275.2 text and common
linuxptp TLV wire format (see module :mod:`ptp_client.ptp.signaling`).
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Callable

from ptp_client.ptp.client import PTPAcrUnicastClient
from ptp_client.ptp.constants import G82752_DEFAULT_DOMAIN, MessageType
from ptp_client.ptp.header import PTPHeader, PortIdentity
from ptp_client.ptp.signaling import (
    TARGET_PORT_IDENTITY_WILDCARD,
    TLV_ACKNOWLEDGE_CANCEL_UNICAST_TRANSMISSION,
    build_cancel_unicast_tlv,
    build_request_unicast_tlv,
    build_signaling_udp_payload,
    extract_grants_from_signaling_udp,
    iter_tlvs,
)


class UnicastNegotiationError(Exception):
    pass


class UnicastDeniedError(UnicastNegotiationError):
    """Grant TLV carried durationField == 0 or repeated denials (G.8275.2 clause 6.6)."""


class UnicastNegotiationTimeout(UnicastNegotiationError):
    pass


@dataclass
class G82752NegotiationState:
    """Snapshot after successful ``negotiate()``."""

    grandmaster_port_identity: PortIdentity
    grants: dict[int, int]  # MessageType int -> granted duration seconds (>0)
    announce_log_period: int
    sync_log_period: int
    delay_resp_log_period: int | None


@dataclass
class G82752UnicastSession:
    """
    G.8275.2-style unicast contract on top of an already-started :class:`PTPAcrUnicastClient`.
    """

    client: PTPAcrUnicastClient
    our_identity: PortIdentity
    domain_number: int = G82752_DEFAULT_DOMAIN
    announce_log_period: int = 0
    sync_log_period: int = 0
    delay_resp_log_period: int = 0
    duration_sec: int = 300
    two_way: bool = True
    request_timeout: float = 5.0
    first_announce_timeout: float = 5.0
    cancel_ack_timeout: float = 0.5
    _denial_counts: dict[int, int] = field(default_factory=dict)
    _stop_renewal: threading.Event = field(default_factory=threading.Event)
    _renew_thread: threading.Thread | None = None
    state: G82752NegotiationState | None = None

    def __post_init__(self) -> None:
        if (self.client.domain_number & 0xFF) != (self.domain_number & 0xFF):
            raise ValueError(
                "G82752UnicastSession.domain_number must match PTPAcrUnicastClient.domain_number"
            )

    def _margin_seconds(self) -> float:
        """Renew well before expiry (G.8275.2 clause 6.6: margin for multiple retries)."""
        return max(10.0, float(self.duration_sec) * 0.25)

    def _sleep_retry(self) -> None:
        time.sleep(1.0)

    def _send_signaling(self, tlvs: bytes, *, target: PortIdentity | None = None) -> int:
        tgt = target if target is not None else TARGET_PORT_IDENTITY_WILDCARD
        seq = self.client.allocate_sequence_id()
        pkt = build_signaling_udp_payload(
            domain_number=self.domain_number,
            source_identity=self.our_identity,
            target_identity=tgt,
            tlvs=tlvs,
            sequence_id=seq,
        )
        self.client.send_general(pkt)
        return seq

    def _wait_signaling_grants(self, deadline: float) -> list:
        def accept(h: PTPHeader, pl: bytes, _w: float) -> bool:
            if h.domain_number != (self.domain_number & 0xFF):
                return False
            if h.message_type != int(MessageType.SIGNALING):
                return False
            return len(extract_grants_from_signaling_udp(pl)) > 0

        _h, pl, _t = self.client._pop_matching_general(accept, deadline=deadline)
        return extract_grants_from_signaling_udp(pl)

    def _bump_denial(self, mt: int) -> None:
        self._denial_counts[mt] = self._denial_counts.get(mt, 0) + 1
        if self._denial_counts[mt] >= 3:
            raise UnicastDeniedError(
                f"grant denied for message type 0x{mt:x} three times (G.8275.2 clause 6.6)"
            )

    def _expect_grants_ok(self, grants: list, expected_pt_types: list[int]) -> None:
        by_mt = {g.pt_message_type: g for g in grants}
        for mt in expected_pt_types:
            g = by_mt.get(mt)
            if g is None:
                raise UnicastNegotiationError(f"missing GRANT TLV for message type 0x{mt:x}")
            if g.duration_sec == 0:
                self._bump_denial(mt)
                raise UnicastDeniedError(f"grant denied (duration 0) for message type 0x{mt:x}")

    def _negotiate_with_retries(
        self,
        send_fn: Callable[[], None],
        expected_types: list[int],
        *,
        phase_label: str,
    ) -> list:
        last_grants: list = []
        for attempt in range(3):
            send_fn()
            try:
                deadline = time.monotonic() + self.request_timeout
                last_grants = self._wait_signaling_grants(deadline)
            except TimeoutError:
                if attempt == 2:
                    raise UnicastNegotiationTimeout(f"{phase_label}: no Signalling GRANT response") from None
                self._sleep_retry()
                continue
            try:
                self._expect_grants_ok(last_grants, expected_types)
            except UnicastDeniedError:
                if attempt == 2:
                    raise
                self._sleep_retry()
                continue
            except UnicastNegotiationError:
                if attempt == 2:
                    raise
                self._sleep_retry()
                continue
            return last_grants
        raise UnicastNegotiationTimeout(phase_label)

    def negotiate(self) -> G82752NegotiationState:
        """
        Run full negotiation: Announce first, then Sync (+ Delay_Resp if ``two_way``).

        Raises :class:`UnicastDeniedError` / :class:`UnicastNegotiationTimeout` on failure.
        """
        # Phase 1 — Announce only (G.8275.2 clause 6.6)
        tl_ann = build_request_unicast_tlv(
            pt_message_type=int(MessageType.ANNOUNCE),
            log_inter_message_period=self.announce_log_period,
            duration_sec=self.duration_sec,
        )

        def send_p1() -> None:
            self._send_signaling(tl_ann, target=TARGET_PORT_IDENTITY_WILDCARD)

        grants_p1 = self._negotiate_with_retries(
            send_p1, [int(MessageType.ANNOUNCE)], phase_label="announce phase"
        )
        ann_grant = next(g for g in grants_p1 if g.pt_message_type == int(MessageType.ANNOUNCE))

        # First unicast Announce
        def accept_ann(h: PTPHeader, pl: bytes, _w: float) -> bool:
            return h.domain_number == (self.domain_number & 0xFF) and h.message_type == int(MessageType.ANNOUNCE)

        ah: PTPHeader | None = None
        apl: bytes | None = None
        for attempt in range(3):
            try:
                ah, apl, _ = self.client._pop_matching_general(
                    accept_ann,
                    deadline=time.monotonic() + self.first_announce_timeout,
                )
                break
            except TimeoutError:
                if attempt == 2:
                    raise UnicastNegotiationTimeout(
                        "timed out waiting for first Announce after grant (3 attempts, G.8275.2 clause 6.6)"
                    ) from None
                self._sleep_retry()
        assert ah is not None and apl is not None

        gm = ah.source_identity

        # Phase 2 — remaining services in one Signalling (G.8275.2 clause 6.6)
        tlvs = build_request_unicast_tlv(
            pt_message_type=int(MessageType.SYNC),
            log_inter_message_period=self.sync_log_period,
            duration_sec=self.duration_sec,
        )
        expected = [int(MessageType.SYNC)]
        if self.two_way:
            tlvs += build_request_unicast_tlv(
                pt_message_type=int(MessageType.DELAY_RESP),
                log_inter_message_period=self.delay_resp_log_period,
                duration_sec=self.duration_sec,
            )
            expected.append(int(MessageType.DELAY_RESP))

        def send_p2() -> None:
            self._send_signaling(tlvs, target=gm)

        grants_p2 = self._negotiate_with_retries(send_p2, expected, phase_label="sync/delay phase")

        grants_map: dict[int, int] = {int(MessageType.ANNOUNCE): ann_grant.duration_sec}
        for g in grants_p2:
            if g.duration_sec > 0:
                grants_map[g.pt_message_type] = g.duration_sec

        self.state = G82752NegotiationState(
            grandmaster_port_identity=gm,
            grants=grants_map,
            announce_log_period=self.announce_log_period,
            sync_log_period=self.sync_log_period,
            delay_resp_log_period=self.delay_resp_log_period if self.two_way else None,
        )
        return self.state

    def renew_now(self, *, target: PortIdentity | None = None) -> list:
        """
        Manually renew all negotiated streams with the same rates and duration.
        Returns parsed GRANT list from the response Signalling.
        """
        if self.state is None:
            raise RuntimeError("negotiate() before renew_now()")
        tgt = target if target is not None else self.state.grandmaster_port_identity
        parts = [
            build_request_unicast_tlv(
                pt_message_type=int(MessageType.ANNOUNCE),
                log_inter_message_period=self.announce_log_period,
                duration_sec=self.duration_sec,
            ),
            build_request_unicast_tlv(
                pt_message_type=int(MessageType.SYNC),
                log_inter_message_period=self.sync_log_period,
                duration_sec=self.duration_sec,
            ),
        ]
        expected = [int(MessageType.ANNOUNCE), int(MessageType.SYNC)]
        if self.two_way:
            parts.append(
                build_request_unicast_tlv(
                    pt_message_type=int(MessageType.DELAY_RESP),
                    log_inter_message_period=self.delay_resp_log_period,
                    duration_sec=self.duration_sec,
                )
            )
            expected.append(int(MessageType.DELAY_RESP))

        def send_rn() -> None:
            self._send_signaling(b"".join(parts), target=tgt)

        return self._negotiate_with_retries(send_rn, expected, phase_label="renewal")

    def cancel_unicast(self, *, target: PortIdentity | None = None, wait_ack: bool = False) -> None:
        """Send CANCEL for Announce, Sync, and Delay_Resp (if two_way)."""
        if self.state is None:
            tgt = target or TARGET_PORT_IDENTITY_WILDCARD
        else:
            tgt = target or self.state.grandmaster_port_identity
        cancels = [
            build_cancel_unicast_tlv(pt_message_type=int(MessageType.ANNOUNCE)),
            build_cancel_unicast_tlv(pt_message_type=int(MessageType.SYNC)),
        ]
        if self.two_way:
            cancels.append(build_cancel_unicast_tlv(pt_message_type=int(MessageType.DELAY_RESP)))
        self._send_signaling(b"".join(cancels), target=tgt)
        if wait_ack and self.cancel_ack_timeout > 0:

            def accept_ack(h: PTPHeader, pl: bytes, _w: float) -> bool:
                if h.domain_number != (self.domain_number & 0xFF):
                    return False
                if h.message_type != int(MessageType.SIGNALING):
                    return False
                for typ, _ln, _v in iter_tlvs(pl, body_start=44):
                    if typ == TLV_ACKNOWLEDGE_CANCEL_UNICAST_TRANSMISSION:
                        return True
                return False

            try:
                self.client._pop_matching_general(
                    accept_ack,
                    deadline=time.monotonic() + self.cancel_ack_timeout,
                )
            except TimeoutError:
                pass

    def start_renewal_background(self) -> None:
        """Daemon thread: renew contracts before expiry (best-effort)."""
        if self.state is None:
            raise RuntimeError("negotiate() before start_renewal_background()")
        self._stop_renewal.clear()

        def loop() -> None:
            margin = self._margin_seconds()
            while not self._stop_renewal.is_set():
                time.sleep(max(1.0, self.duration_sec - margin))
                if self._stop_renewal.is_set():
                    break
                try:
                    self.renew_now()
                except UnicastNegotiationError:
                    self._sleep_retry()

        self._renew_thread = threading.Thread(target=loop, name="g82752-renew", daemon=True)
        self._renew_thread.start()

    def stop_renewal_background(self) -> None:
        self._stop_renewal.set()
        if self._renew_thread is not None:
            self._renew_thread.join(timeout=2.0)
            self._renew_thread = None
