"""
ITU-T G.8275.2 unicast negotiation (clause 6.6, Annex A.3.3–A.3.5).

Implements the request-port side of IEEE 1588 unicast negotiation using Signalling
messages on the general port:

- Phase 1: REQUEST Announce only; wait GRANT; wait first unicast Announce.
- Phase 2: REQUEST Sync (+ optional Delay_Resp only if ``negotiate_delay_resp``).
- ACR (default): Delay_Req / Delay_Resp use IEEE 1588 E2E on 319/320 — **not** Signalling.
- Renewal: re-issue REQUEST before ``durationField`` expiry (configurable margin).
- Teardown: CANCEL_UNICAST_TRANSMISSION per active message type (optional ACK wait).

Runtime uses **two threads** (plus the UDP receiver inside :class:`PTPAcrUnicastClient`):

- **Receiver** (``ptp-recv``): ingests all server datagrams into a shared buffer.
- **Manager** (``g82752-manager``): Signalling negotiate/renew, Sync wait, Delay_Req loop.

This does **not** implement full BTCA / alternateTimeTransmitter filtering — only the
Signalling contract exchange. Behaviour is aligned with G.8275.2 text and common
linuxptp TLV wire format (see module :mod:`ptp_client.ptp.signaling`).
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, TYPE_CHECKING

from ptp_client.ptp.client import PTPAcrUnicastClient

if TYPE_CHECKING:
    from ptp_client.ptp.client import PTPAcrEstimateResult
from ptp_client.ptp.constants import G82752_DEFAULT_DOMAIN, MessageType
from ptp_client.ptp.header import PTPHeader, PortIdentity
from ptp_client.ptp.signaling import (
    TARGET_PORT_IDENTITY_WILDCARD,
    TLV_ACKNOWLEDGE_CANCEL_UNICAST_TRANSMISSION,
    build_cancel_unicast_tlv,
    build_request_unicast_tlv,
    build_signaling_udp_payload,
    describe_signaling_udp,
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
class G82752AcrRunConfig:
    """Parameters for :meth:`G82752UnicastSession.start_acr`."""

    measure_acr: bool = True
    delay_spec: Mapping[str, Any] | None = None
    sync_timeout: float = 8.0
    delay_timeout: float = 8.0
    delay_request_interval_sec: float | None = None
    measure_duration_sec: int | None = None
    on_estimate: Callable[["PTPAcrEstimateResult"], None] | None = None


@dataclass
class G82752UnicastSession:
    """
    G.8275.2-style unicast contract on top of an already-started :class:`PTPAcrUnicastClient`.

    Call :meth:`start_acr` to run negotiate (+ optional measure loop) on a dedicated manager
    thread; the client receiver thread handles all inbound packets.
    """

    client: PTPAcrUnicastClient
    our_identity: PortIdentity
    domain_number: int = G82752_DEFAULT_DOMAIN
    announce_log_period: int = 0
    sync_log_period: int = 0
    duration_sec: int = 300
    # False = ACR default: Signalling only for Announce+Sync; Delay_Req is E2E (no GRANT for Delay_Resp).
    negotiate_delay_resp: bool = False
    delay_resp_log_period: int = 0
    request_timeout: float = 5.0
    first_announce_timeout: float = 5.0
    cancel_ack_timeout: float = 0.5
    _denial_counts: dict[int, int] = field(default_factory=dict)
    _stop_manager: threading.Event = field(default_factory=threading.Event)
    _manager_thread: threading.Thread | None = None
    _manager_finished: threading.Event = field(default_factory=threading.Event)
    _manager_error: BaseException | None = None
    _acr_last_estimate: Any = None
    _renewal_lock: threading.Lock = field(default_factory=threading.Lock)
    _contract_started_at: float = 0.0
    state: G82752NegotiationState | None = None

    def __post_init__(self) -> None:
        if (self.client.domain_number & 0xFF) != (self.domain_number & 0xFF):
            raise ValueError(
                "G82752UnicastSession.domain_number must match PTPAcrUnicastClient.domain_number"
            )

    def _margin_seconds(self) -> float:
        """Renew well before expiry (G.8275.2 clause 6.6: margin for multiple retries)."""
        return max(10.0, float(self.duration_sec) * 0.25)

    def _mark_contract_started(self) -> None:
        self._contract_started_at = time.monotonic()

    def _seconds_until_renewal(self) -> float:
        if self._contract_started_at <= 0.0:
            return 0.0
        renew_at = self._contract_started_at + float(self.duration_sec) - self._margin_seconds()
        return renew_at - time.monotonic()

    def _renew_if_due(self, *, force: bool = False) -> bool:
        """Re-issue Announce+Sync REQUEST when the unicast contract is near expiry or ``force``."""
        if self.state is None:
            print("[g8275 renew] skip: no negotiation state", flush=True)
            return False
        secs = self._seconds_until_renewal()
        if not force and secs > 0.0:
            return False
        print(
            f"[g8275 renew] starting renewal force={force} seconds_until_renewal={secs:.1f}",
            flush=True,
        )
        with self._renewal_lock:
            try:
                self._do_renew_now()
                self._mark_contract_started()
                print("[g8275 renew] completed OK", flush=True)
                return True
            except UnicastNegotiationError as exc:
                print(f"[g8275 renew] failed: {exc}", flush=True)
            except TimeoutError as exc:
                print(f"[g8275 renew] timeout: {exc}", flush=True)
        return False

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

    def _collect_grants_until(self, expected_types: list[int], deadline: float) -> list:
        """
        Collect GRANT TLVs for ``expected_types``, possibly from multiple Signalling messages.

        linuxptp often returns one GRANT per Signalling frame (Sync and Delay_Resp separately).
        """
        from ptp_client.ptp.signaling import ParsedGrant

        need = set(int(x) for x in expected_types)
        by_mt: dict[int, ParsedGrant] = {}

        while time.monotonic() < deadline:
            self.client._poll_event_signaling()
            progressed = False
            with self.client._general_cv:
                remove_idxs: list[int] = []
                for idx, (h, pl, _wall) in enumerate(self.client._general_buf):
                    if h.domain_number != (self.domain_number & 0xFF):
                        continue
                    if h.message_type != int(MessageType.SIGNALING):
                        continue
                    grants = extract_grants_from_signaling_udp(pl)
                    if not grants:
                        continue
                    relevant = [g for g in grants if g.pt_message_type in need]
                    if not relevant:
                        continue
                    for g in relevant:
                        if g.duration_sec == 0:
                            self._bump_denial(g.pt_message_type)
                            raise UnicastDeniedError(
                                f"grant denied (duration 0) for message type 0x{g.pt_message_type:x}"
                            )
                        by_mt[g.pt_message_type] = g
                    remove_idxs.append(idx)
                    progressed = True
                for idx in reversed(remove_idxs):
                    del self.client._general_buf[idx]
                if need.issubset(by_mt.keys()):
                    return [by_mt[mt] for mt in expected_types]

            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            if not progressed:
                with self.client._general_cv:
                    self.client._general_cv.wait(timeout=min(0.05, remaining))

        missing = [mt for mt in expected_types if mt not in by_mt]
        if by_mt:
            got = {f"0x{mt:x}": g.duration_sec for mt, g in by_mt.items()}
            print(
                f"[g8275 negotiate] partial GRANTs before timeout: got={got} missing={[f'0x{m:x}' for m in missing]}",
                flush=True,
            )
        with self.client._general_cv:
            pending = [
                describe_signaling_udp(pl)
                for _h, pl, _w in self.client._general_buf
                if _h.message_type == int(MessageType.SIGNALING)
            ]
        if pending:
            print(
                "[g8275 negotiate] timeout; buffered Signaling (no matching GRANT parsed):",
                pending[:5],
                flush=True,
            )
        raise TimeoutError("timeout collecting Signalling GRANT TLVs")

    def _wait_signaling_grants(self, deadline: float, expected_types: list[int] | None = None) -> list:
        if expected_types:
            return self._collect_grants_until(expected_types, deadline)

        def accept(h: PTPHeader, pl: bytes, _w: float) -> bool:
            if h.domain_number != (self.domain_number & 0xFF):
                return False
            if h.message_type != int(MessageType.SIGNALING):
                return False
            return len(extract_grants_from_signaling_udp(pl)) > 0

        try:
            _h, pl, _t = self.client._pop_matching_general(accept, deadline=deadline)
            return extract_grants_from_signaling_udp(pl)
        except TimeoutError:
            with self.client._general_cv:
                pending = [
                    describe_signaling_udp(pl)
                    for _h, pl, _w in self.client._general_buf
                    if _h.message_type == int(MessageType.SIGNALING)
                ]
            if pending:
                print(
                    "[g8275 negotiate] timeout; buffered Signaling (no GRANT parsed):",
                    pending[:3],
                    flush=True,
                )
            raise

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
                last_grants = self._wait_signaling_grants(deadline, expected_types)
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
            except UnicastNegotiationError as exc:
                # Should not happen when collecting with expected_types; keep for safety.
                if attempt == 2:
                    raise UnicastNegotiationTimeout(f"{phase_label}: {exc}") from exc
                self._sleep_retry()
                continue
            return last_grants
        raise UnicastNegotiationTimeout(phase_label)

    def negotiate(self) -> G82752NegotiationState:
        """
        Run full negotiation: Announce first, then Sync (Signalling).

        Delay_Req/Delay_Resp are **not** negotiated here unless ``negotiate_delay_resp`` is True.

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
                print(
                    "[g8275 negotiate] first Announce timeout; re-request Announce unicast",
                    flush=True,
                )
                send_p1()
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
        if self.negotiate_delay_resp:
            tlvs += build_request_unicast_tlv(
                pt_message_type=int(MessageType.DELAY_RESP),
                log_inter_message_period=self.delay_resp_log_period,
                duration_sec=self.duration_sec,
            )
            expected.append(int(MessageType.DELAY_RESP))

        def send_p2() -> None:
            self._send_signaling(tlvs, target=gm)

        phase2 = "sync phase" if not self.negotiate_delay_resp else "sync/delay-resp phase"
        try:
            grants_p2 = self._negotiate_with_retries(send_p2, expected, phase_label=phase2)
        except UnicastNegotiationTimeout:
            # Some masters only accept wildcard targetPortIdentity on Signalling.
            def send_p2_wildcard() -> None:
                self._send_signaling(tlvs, target=TARGET_PORT_IDENTITY_WILDCARD)

            print("[g8275 negotiate] retry sync phase with wildcard targetPortIdentity", flush=True)
            grants_p2 = self._negotiate_with_retries(
                send_p2_wildcard, expected, phase_label=f"{phase2} (wildcard target)"
            )

        grants_map: dict[int, int] = {int(MessageType.ANNOUNCE): ann_grant.duration_sec}
        for g in grants_p2:
            if g.duration_sec > 0:
                grants_map[g.pt_message_type] = g.duration_sec

        self.state = G82752NegotiationState(
            grandmaster_port_identity=gm,
            grants=grants_map,
            announce_log_period=self.announce_log_period,
            sync_log_period=self.sync_log_period,
            delay_resp_log_period=self.delay_resp_log_period if self.negotiate_delay_resp else None,
        )
        self._mark_contract_started()
        return self.state

    def measure_acr(
        self,
        *,
        delay_spec: Mapping[str, Any] | None = None,
        sync_timeout: float = 8.0,
        delay_timeout: float = 8.0,
        delay_request_interval_sec: float | None = None,
        measure_duration_sec: int | None = None,
        on_estimate: Callable[["PTPAcrEstimateResult"], None] | None = None,
    ):
        """
        After ``negotiate()``: wait Sync (+Follow_Up), send Delay_Req (E2E), wait Delay_Resp.

        When ``delay_request_interval_sec`` is set, the client sends Delay_Req at that fixed
        interval (local policy only; not written into the PTP header) until
        ``measure_duration_sec`` elapses, reusing the initial Sync sample for offset.

        When ``measure_duration_sec`` is ``None`` or ``<= 0``, periodic measurement runs until
        :meth:`stop_acr` / ``_stop_manager`` (unlimited).
        """
        import time

        from ptp_client.ptp.client import PTPAcrEstimateResult
        from ptp_client.ptp.constants import FLAG_UNICAST
        from ptp_client.ptp.delay_request import build_delay_request_spec

        if self.state is None:
            raise RuntimeError("negotiate() before measure_acr()")

        spec = build_delay_request_spec(
            delay_spec,
            domain_number=self.domain_number,
            clock_identity=self.our_identity.clock_identity,
            port_number=self.our_identity.port_number,
            default_flags=FLAG_UNICAST,
        )

        print("[g8275 acr] waiting Sync (+Follow_Up if two-step)...", flush=True)
        try:
            sync = self.client.wait_sync_sample(timeout=sync_timeout)
        except TimeoutError:
            print("[g8275 acr] Sync timeout; renewing Announce+Sync then retrying", flush=True)
            self._renew_if_due(force=True)
            sync = self.client.wait_sync_sample(timeout=sync_timeout)

        measure_limit: float | None
        if measure_duration_sec is None or int(measure_duration_sec) <= 0:
            measure_limit = None
        else:
            measure_limit = float(measure_duration_sec)
        deadline = time.monotonic() + measure_limit if measure_limit is not None else None
        loop_start = time.monotonic()
        interval = delay_request_interval_sec
        periodic = interval is not None and interval > 0.0
        limit_label = (
            "unlimited (until stop)"
            if measure_limit is None
            else f"{measure_limit:.0f}s"
        )
        print(
            "[g8275 acr] measure loop config:"
            f" measure_total={limit_label}"
            f" contract_duration_sec={self.duration_sec}"
            f" periodic={periodic} interval={interval}",
            flush=True,
        )

        def estimate_from_delay(delay) -> PTPAcrEstimateResult:
            t1 = sync.t1_master_posix_approx
            t2 = sync.t2_sync_recv_unix
            t3 = delay.t3_send_unix
            t4 = delay.t4_master_rx_posix_approx
            offset = ((t2 - t1) - (t4 - t3)) / 2.0
            mean_delay = ((t2 - t1) + (t4 - t3)) / 2.0
            return PTPAcrEstimateResult(
                sync=sync,
                delay=delay,
                offset_seconds=offset,
                mean_path_delay_seconds=mean_delay,
            )

        last: PTPAcrEstimateResult | None = None
        round_no = 0
        while not self._stop_manager.is_set():
            if round_no > 0 and not periodic:
                print("[g8275 acr] measure loop exit: non-periodic after first round", flush=True)
                break
            if deadline is not None and round_no > 0 and time.monotonic() >= deadline:
                elapsed = time.monotonic() - loop_start
                print(
                    f"[g8275 acr] measure loop exit: measure_total reached"
                    f" round={round_no} elapsed={elapsed:.1f}s limit={measure_limit:.0f}s",
                    flush=True,
                )
                break

            self._renew_if_due(force=False)

            print(f"[g8275 acr] Delay_Req exchange starting round={round_no + 1}", flush=True)
            try:
                delay = self.client.exchange_delay(spec, timeout=delay_timeout)
            except TimeoutError:
                print(
                    "[g8275 acr] Delay_Resp timeout; renewing Announce+Sync if due, continuing",
                    flush=True,
                )
                self._renew_if_due(force=True)
                if not periodic:
                    if last is None:
                        print(
                            "[g8275 acr] measure loop exit: Delay_Resp timeout, no successful exchange",
                            flush=True,
                        )
                        raise
                    print(
                        "[g8275 acr] measure loop exit: Delay_Resp timeout in non-periodic mode",
                        flush=True,
                    )
                    break
                self._sleep_until_next_or_deadline(
                    time.monotonic() + interval,
                    deadline,
                    check_renewal=True,
                )
                continue

            last = estimate_from_delay(delay)
            round_no += 1
            if on_estimate is not None:
                on_estimate(last)
            elapsed = time.monotonic() - loop_start
            print(
                "[g8275 acr] Delay_Req sent (E2E); Delay_Resp received "
                f"seq={delay.response_header.sequence_id} "
                f"round={round_no} elapsed={elapsed:.1f}s "
                f"measure_total={limit_label} "
                f"offset_seconds={last.offset_seconds:.9f} "
                f"mean_path_delay_seconds={last.mean_path_delay_seconds:.9f}",
                flush=True,
            )

            if not periodic:
                print("[g8275 acr] measure loop exit: non-periodic single exchange done", flush=True)
                break
            next_at = time.monotonic() + interval
            if deadline is not None and next_at >= deadline:
                elapsed = time.monotonic() - loop_start
                print(
                    f"[g8275 acr] measure loop exit: next Delay interval would exceed measure_total"
                    f" round={round_no} elapsed={elapsed:.1f}s limit={measure_limit:.0f}s",
                    flush=True,
                )
                break
            self._sleep_until_next_or_deadline(next_at, deadline, check_renewal=True)

        if self._stop_manager.is_set():
            print("[g8275 acr] measure loop exit: stop_manager requested", flush=True)

        elapsed = time.monotonic() - loop_start
        print(
            f"[g8275 acr] measure loop finished rounds={round_no} elapsed={elapsed:.1f}s"
            f" measure_total={limit_label}",
            flush=True,
        )
        if last is None:
            print("[g8275 acr] measure loop exit: no successful Delay exchange", flush=True)
            raise RuntimeError("measure_acr produced no Delay_Req exchange")
        return last

    def _sleep_until_next_or_deadline(
        self,
        next_at: float,
        deadline: float | None,
        *,
        check_renewal: bool,
    ) -> None:
        while not self._stop_manager.is_set() and time.monotonic() < next_at:
            if deadline is not None and time.monotonic() >= deadline:
                break
            if check_renewal:
                self._renew_if_due(force=False)
            end = next_at
            if deadline is not None:
                end = min(end, deadline)
            remaining = end - time.monotonic()
            if remaining <= 0:
                break
            time.sleep(min(0.5, remaining))
        now = time.monotonic()
        if self._stop_manager.is_set():
            print("[g8275 acr] sleep exit: stop_manager", flush=True)
        elif deadline is not None and now >= deadline:
            print("[g8275 acr] sleep exit: measure_total reached during interval wait", flush=True)
        elif now >= next_at:
            print("[g8275 acr] sleep exit: next Delay interval due", flush=True)

    def _do_renew_now(self, *, target: PortIdentity | None = None) -> list:
        """
        Manually renew all negotiated streams with the same rates and duration.
        Returns parsed GRANT list from the response Signalling.
        """
        if self.state is None:
            raise RuntimeError("negotiate() before renew_now()")
        print("[g8275 renew] sending REQUEST Announce+Sync (Signalling)", flush=True)
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
        if self.negotiate_delay_resp:
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

        try:
            grants = self._negotiate_with_retries(send_rn, expected, phase_label="renewal")
        except UnicastNegotiationTimeout:
            def send_rn_wildcard() -> None:
                self._send_signaling(b"".join(parts), target=TARGET_PORT_IDENTITY_WILDCARD)

            print("[g8275 renew] retry with wildcard targetPortIdentity", flush=True)
            grants = self._negotiate_with_retries(
                send_rn_wildcard, expected, phase_label="renewal (wildcard target)"
            )

        if self.state is not None:
            for g in grants:
                if g.duration_sec > 0:
                    self.state.grants[g.pt_message_type] = g.duration_sec
        print(
            "[g8275 renew] Announce+Sync contract renewed"
            + (" (+Delay_Resp)" if self.negotiate_delay_resp else "")
            + f" grants_sec={self.state.grants if self.state else {}}",
            flush=True,
        )
        return grants

    def renew_now(self, *, target: PortIdentity | None = None) -> list:
        """Manually renew all negotiated streams (thread-safe)."""
        with self._renewal_lock:
            grants = self._do_renew_now(target=target)
            self._mark_contract_started()
            return grants

    def cancel_unicast(self, *, target: PortIdentity | None = None, wait_ack: bool = False) -> None:
        """Send CANCEL for Announce and Sync (and Delay_Resp if ``negotiate_delay_resp``)."""
        if self.state is None:
            tgt = target or TARGET_PORT_IDENTITY_WILDCARD
        else:
            tgt = target or self.state.grandmaster_port_identity
        cancels = [
            build_cancel_unicast_tlv(pt_message_type=int(MessageType.ANNOUNCE)),
            build_cancel_unicast_tlv(pt_message_type=int(MessageType.SYNC)),
        ]
        if self.negotiate_delay_resp:
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

    def start_acr(self, config: G82752AcrRunConfig | None = None, **kwargs: Any) -> None:
        """
        Start the ACR **manager** thread (negotiate + optional measure/renew loop).

        Requires :meth:`PTPAcrUnicastClient.start` already called (receiver thread running).
        """
        if self._manager_thread is not None and self._manager_thread.is_alive():
            raise RuntimeError("ACR manager thread already running")
        cfg = config if config is not None else G82752AcrRunConfig(**kwargs)
        self._stop_manager.clear()
        self._manager_finished.clear()
        self._manager_error = None
        self._acr_last_estimate = None
        self._manager_thread = threading.Thread(
            target=self._manager_loop,
            args=(cfg,),
            name="g82752-manager",
            daemon=True,
        )
        self._manager_thread.start()
        print("[g8275 manager] thread started", flush=True)

    def _manager_loop(self, cfg: G82752AcrRunConfig) -> None:
        try:
            self.negotiate()
            if cfg.measure_acr:
                self._acr_last_estimate = self.measure_acr(
                    delay_spec=cfg.delay_spec,
                    sync_timeout=cfg.sync_timeout,
                    delay_timeout=cfg.delay_timeout,
                    delay_request_interval_sec=cfg.delay_request_interval_sec,
                    measure_duration_sec=cfg.measure_duration_sec,
                    on_estimate=cfg.on_estimate,
                )
            print("[g8275 manager] finished normally", flush=True)
        except BaseException as exc:
            self._manager_error = exc
            print(f"[g8275 manager] stopped with error: {exc!r}", flush=True)
        finally:
            print("[g8275 manager] thread exiting", flush=True)
            self._manager_finished.set()

    def wait_acr(self, timeout: float | None = None):
        """
        Block until the manager thread finishes. Re-raises any manager exception.

        Returns the last :class:`~ptp_client.ptp.client.PTPAcrEstimateResult` when
        ``measure_acr`` was enabled, else ``None``.
        """
        if self._manager_thread is None:
            raise RuntimeError("start_acr() before wait_acr()")
        if not self._manager_finished.wait(timeout):
            raise TimeoutError("ACR manager did not finish in time")
        if self._manager_error is not None:
            raise self._manager_error
        return self._acr_last_estimate

    def stop_acr(self) -> None:
        """Signal the manager thread to stop and join it."""
        self._stop_manager.set()
        if self._manager_thread is not None:
            self._manager_thread.join(timeout=10.0)
            self._manager_thread = None
