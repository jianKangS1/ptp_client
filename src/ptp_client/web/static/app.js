const $ = (id) => document.getElementById(id);

function parseFrac(s) {
  const t = String(s).trim();
  if (!t) return 0;
  if (t.startsWith("0x") || t.startsWith("0X")) return parseInt(t, 16) >>> 0;
  const n = Number(t);
  if (!Number.isFinite(n)) return 0;
  return (n >>> 0) & 0xffffffff;
}

function optionalFloat(id) {
  const v = $(id).value.trim();
  if (v === "") return null;
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
}

function buildPacketFromForm() {
  const refIdRaw = $("reference_id").value.trim();
  const packet = {
    leap_indicator: Number($("leap_indicator").value),
    version: Number($("version").value),
    mode: Number($("mode").value),
    stratum: Number($("stratum").value),
    poll: Number($("poll").value),
    precision: Number($("precision").value),
    reference_timestamp: {
      seconds: Number($("ref_ts_sec").value),
      fraction: parseFrac($("ref_ts_frac").value),
    },
    receive_timestamp: {
      seconds: Number($("recv_ts_sec").value),
      fraction: parseFrac($("recv_ts_frac").value),
    },
    transmit_timestamp: {
      seconds: Number($("xmit_ts_sec").value),
      fraction: parseFrac($("xmit_ts_frac").value),
    },
  };
  const rd = optionalFloat("root_delay_sec");
  const rdp = optionalFloat("root_dispersion_sec");
  if (rd !== null) packet.root_delay_sec = rd;
  if (rdp !== null) packet.root_dispersion_sec = rdp;
  if (refIdRaw) {
    if (/^[0-9a-fA-F]{8}$/.test(refIdRaw)) packet.reference_id_hex = refIdRaw;
    else packet.reference_id_ascii = refIdRaw;
  }
  const auto = $("origin_auto_now").checked;
  packet.origin_auto_now = auto;
  if (!auto) {
    const ou = $("origin_unix").value.trim();
    if (ou) packet.origin_unix = Number(ou);
    else {
      packet.origin_ntp = {
        seconds: Number($("origin_ntp_sec").value),
        fraction: parseFrac($("origin_ntp_frac").value),
      };
    }
  }
  return packet;
}

function applyPacketToForm(packet) {
  const p = packet || {};
  if (p.leap_indicator !== undefined) $("leap_indicator").value = p.leap_indicator;
  if (p.version !== undefined) $("version").value = p.version;
  if (p.mode !== undefined) $("mode").value = p.mode;
  if (p.stratum !== undefined) $("stratum").value = p.stratum;
  if (p.poll !== undefined) $("poll").value = p.poll;
  if (p.precision !== undefined) $("precision").value = p.precision;
  $("root_delay_sec").value = p.root_delay_sec ?? "";
  $("root_dispersion_sec").value = p.root_dispersion_sec ?? "";
  $("reference_id").value =
    p.reference_id_hex || p.reference_id_ascii || p.reference_id || "";
  const rts = p.reference_timestamp || {};
  $("ref_ts_sec").value = rts.seconds ?? 0;
  $("ref_ts_frac").value = rts.fraction ?? 0;
  const rv = p.receive_timestamp || {};
  $("recv_ts_sec").value = rv.seconds ?? 0;
  $("recv_ts_frac").value = rv.fraction ?? 0;
  const xt = p.transmit_timestamp || {};
  $("xmit_ts_sec").value = xt.seconds ?? 0;
  $("xmit_ts_frac").value = xt.fraction ?? 0;
  const auto = p.origin_auto_now !== false;
  $("origin_auto_now").checked = auto;
  $("origin_unix").value = p.origin_unix ?? "";
  const on = p.origin_ntp || {};
  $("origin_ntp_sec").value = on.seconds ?? 0;
  $("origin_ntp_frac").value = on.fraction ?? 0;
  syncOriginControls();
}

function syncOriginControls() {
  const auto = $("origin_auto_now").checked;
  $("origin_unix").disabled = auto;
  $("origin_ntp_sec").disabled = auto;
  $("origin_ntp_frac").disabled = auto;
}

let lastPcapBase64 = null;

function downloadPcap() {
  if (!lastPcapBase64) return;
  const bin = Uint8Array.from(atob(lastPcapBase64), (c) => c.charCodeAt(0));
  const blob = new Blob([bin], { type: "application/vnd.tcpdump.pcap" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `ntp-exchange-${Date.now()}.pcap`;
  a.click();
  URL.revokeObjectURL(a.href);
}

function setStatus(msg, kind) {
  const el = $("status");
  el.textContent = msg || "";
  el.className = "status" + (kind ? " " + kind : "");
}

async function sendExchange() {
  setStatus("请求中…", "");
  $("btn-dl-pcap").disabled = true;
  lastPcapBase64 = null;
  const body = {
    host: $("host").value.trim(),
    port: Number($("port").value),
    timeout: Number($("timeout").value),
    packet: buildPacketFromForm(),
  };
  try {
    const r = await fetch("/api/ntp/exchange", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const data = await r.json().catch(() => ({}));
    if (!r.ok) {
      const detail = data.detail || data.message || r.statusText;
      setStatus(`错误 ${r.status}: ${typeof detail === "string" ? detail : JSON.stringify(detail)}`, "err");
      return;
    }
    setStatus("完成", "ok");
    $("metrics").textContent = `offset=${data.offset_seconds?.toFixed(6)} s  RTT=${data.round_trip_delay_seconds?.toFixed(6)} s  |  client ${data.client?.ip}:${data.client?.port} → server ${data.server?.ip}:${data.server?.port}`;
    $("metrics").classList.remove("muted");
    $("req-hex").textContent = data.request_udp_hex || "";
    $("rsp-hex").textContent = data.response_udp_hex || "";
    $("req-json").textContent = JSON.stringify(data.request_packet, null, 2);
    $("rsp-json").textContent = JSON.stringify(data.response_packet, null, 2);
    $("pcap-preview").textContent = (data.pcap_preview_lines || []).join("\n");
    lastPcapBase64 = data.pcap_base64 || null;
    $("btn-dl-pcap").disabled = !lastPcapBase64;
  } catch (e) {
    setStatus(String(e), "err");
  }
}

$("origin_auto_now").addEventListener("change", syncOriginControls);
$("btn-send").addEventListener("click", sendExchange);
$("btn-dl-pcap").addEventListener("click", downloadPcap);

$("btn-json").addEventListener("click", () => {
  $("ta-json").value = JSON.stringify(
    {
      host: $("host").value.trim(),
      port: Number($("port").value),
      timeout: Number($("timeout").value),
      packet: buildPacketFromForm(),
    },
    null,
    2
  );
  $("dlg-json").showModal();
});

$("btn-export-json").addEventListener("click", () => {
  const blob = new Blob([JSON.stringify(buildPacketFromForm(), null, 2)], {
    type: "application/json",
  });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `ntp-packet-${Date.now()}.json`;
  a.click();
  URL.revokeObjectURL(a.href);
});

$("dlg-json").addEventListener("close", () => {
  if ($("dlg-json").returnValue !== "ok") return;
  let raw = $("ta-json").value.trim();
  if (!raw) return;
  let obj;
  try {
    obj = JSON.parse(raw);
  } catch (e) {
    setStatus("JSON 解析失败: " + e, "err");
    return;
  }
  if (obj.packet) {
    if (obj.host) $("host").value = obj.host;
    if (obj.port !== undefined) $("port").value = obj.port;
    if (obj.timeout !== undefined) $("timeout").value = obj.timeout;
    applyPacketToForm(obj.packet);
  } else {
    applyPacketToForm(obj);
  }
  setStatus("已从 JSON 载入报文字段", "ok");
});

syncOriginControls();
