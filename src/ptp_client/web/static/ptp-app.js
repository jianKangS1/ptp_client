const P = (id) => document.getElementById(id);

function parseHexInt(s) {
  const t = String(s).trim();
  if (!t) return 0;
  return parseInt(t, t.startsWith("0x") || t.startsWith("0X") ? 16 : 10);
}

function buildPtpPreviewSpec() {
  const msgType = P("ptp-msg-type").value;
  const spec = {
    message_type: msgType,
    domain_number: Number(P("ptp-domain").value),
    flags: parseHexInt(P("ptp-dr-flags").value),
    correction_field_ns: Number(P("ptp-dr-correction").value),
    sequence_id: Number(P("ptp-seq-id").value),
    log_message_interval: Number(P("ptp-log-int").value),
    clock_identity: P("ptp-clock-id").value.trim(),
    port_number: Number(P("ptp-port-num").value),
  };
  const ts = {
    seconds: Number(P("ptp-body-sec").value),
    nanoseconds: Number(P("ptp-body-ns").value),
  };
  if (msgType === "follow_up") {
    spec.precise_origin_timestamp = ts;
  } else if (msgType === "delay_resp") {
    spec.receive_timestamp = ts;
    spec.requesting_port_identity = {
      clock_identity: P("ptp-clock-id").value.trim(),
      port_number: Number(P("ptp-req-port-num").value),
    };
  } else {
    spec.origin_timestamp = ts;
  }
  return spec;
}

function buildPtpAcrBody() {
  const bind = P("ptp-bind").value.trim();
  const interval = Number(P("ptp-dr-interval").value);
  const measureRaw = Number(P("ptp-measure-duration").value);
  const body = {
    master: P("ptp-master").value.trim(),
    domain: Number(P("ptp-domain").value),
    clock_identity: P("ptp-clock-id").value.trim(),
    port_number: Number(P("ptp-port-num").value),
    announce_log: Number(P("ptp-ann-log").value),
    sync_log: Number(P("ptp-sync-log").value),
    duration_sec: Number(P("ptp-duration").value),
    sync_timeout: Number(P("ptp-sync-timeout").value),
    delay_timeout: Number(P("ptp-delay-timeout").value),
    measure_duration_sec: measureRaw > 0 ? measureRaw : null,
    delay_request: {
      flags: parseHexInt(P("ptp-dr-flags").value),
      correction_field_ns: Number(P("ptp-dr-correction").value),
      origin_timestamp: {
        seconds: Number(P("ptp-dr-origin-sec").value),
        nanoseconds: Number(P("ptp-dr-origin-ns").value),
      },
      request_interval_sec: interval > 0 ? interval : null,
    },
  };
  if (bind) {
    body.bind = bind;
  }
  return body;
}

function applyPtpConfig(obj) {
  const c = obj || {};
  if (c.master) P("ptp-master").value = c.master;
  if (c.domain !== undefined) P("ptp-domain").value = c.domain;
  if (c.bind) P("ptp-bind").value = c.bind;
  if (c.clock_identity) P("ptp-clock-id").value = c.clock_identity;
  if (c.port_number !== undefined) P("ptp-port-num").value = c.port_number;
  if (c.announce_log !== undefined) P("ptp-ann-log").value = c.announce_log;
  if (c.sync_log !== undefined) P("ptp-sync-log").value = c.sync_log;
  if (c.duration_sec !== undefined) P("ptp-duration").value = c.duration_sec;
  if (c.sync_timeout !== undefined) P("ptp-sync-timeout").value = c.sync_timeout;
  if (c.delay_timeout !== undefined) P("ptp-delay-timeout").value = c.delay_timeout;
  if (c.measure_duration_sec !== undefined) P("ptp-measure-duration").value = c.measure_duration_sec;
  const dr = c.delay_request || {};
  if (dr.flags !== undefined) P("ptp-dr-flags").value = "0x" + Number(dr.flags).toString(16);
  if (dr.correction_field_ns !== undefined) P("ptp-dr-correction").value = dr.correction_field_ns;
  const ot = dr.origin_timestamp || {};
  if (ot.seconds !== undefined) P("ptp-dr-origin-sec").value = ot.seconds;
  if (ot.nanoseconds !== undefined) P("ptp-dr-origin-ns").value = ot.nanoseconds;
  const iv = dr.request_interval_sec ?? dr.requestIntervalSec;
  if (iv !== undefined && iv !== null) P("ptp-dr-interval").value = iv;
}

function setPtpStatus(msg, kind) {
  const el = P("ptp-status");
  el.textContent = msg || "";
  el.className = "status" + (kind ? " " + kind : "");
}

let ptpLastPcap = null;
let ptpMessages = [];

/* ---- live run state (start / poll / stop) ---- */
let ptpRunId = null;
let ptpNextIndex = 0;
let ptpPollTimer = null;
let ptpAutoScroll = true;
const PTP_POLL_MS = 500;
const PTP_MAX_ROWS = 3000;

function fmtTime(unix) {
  const d = new Date(unix * 1000);
  const ms = String(d.getMilliseconds()).padStart(3, "0");
  return (
    String(d.getHours()).padStart(2, "0") + ":" +
    String(d.getMinutes()).padStart(2, "0") + ":" +
    String(d.getSeconds()).padStart(2, "0") + "." + ms
  );
}

function renderPtpStats(stats) {
  const tbody = P("ptp-stats-body");
  tbody.innerHTML = "";
  const names = Object.keys(stats || {}).sort();
  if (!names.length) {
    tbody.innerHTML = '<tr><td colspan="4" class="muted">—</td></tr>';
    return;
  }
  for (const name of names) {
    const row = stats[name];
    const tr = document.createElement("tr");
    tr.innerHTML =
      "<td>" + name + "</td><td>" + (row.tx || 0) + "</td><td>" + (row.rx || 0) + "</td><td>" + (row.total || 0) + "</td>";
    tbody.appendChild(tr);
  }
}

function selectPtpMessage(rec) {
  P("ptp-sel-hex").textContent = rec.udp_hex || "";
  P("ptp-sel-json").textContent = JSON.stringify(rec.summary, null, 2);
  document.querySelectorAll(".msg-row").forEach((el) => el.classList.remove("selected"));
  const row = document.querySelector('.msg-row[data-index="' + rec.index + '"]');
  if (row) row.classList.add("selected");
}

function appendPtpRows(messages) {
  const box = P("ptp-msg-list");
  box.classList.remove("muted");
  for (const rec of messages) {
    const name = (rec.summary && rec.summary.message_type_name) || "?";
    const seq = rec.summary && rec.summary.sequence_id != null ? rec.summary.sequence_id : "-";
    const div = document.createElement("div");
    div.className = "msg-row dir-" + rec.direction;
    div.dataset.index = String(rec.index);
    div.innerHTML =
      "<span class='c-time'>" + fmtTime(rec.wall_unix) + "</span>" +
      "<span class='c-no'>#" + rec.index + "</span>" +
      "<span class='c-dir'>" + (rec.direction === "tx" ? "→ TX" : "← RX") + "</span>" +
      "<span class='c-type'>" + name + "</span>" +
      "<span class='c-info'>seq=" + seq + " " + (rec.src || "") + " → " + (rec.dst || "") + "</span>";
    div.addEventListener("click", () => {
      ptpAutoScroll = false;
      selectPtpMessage(rec);
    });
    box.appendChild(div);
  }
  // Trim DOM if it grows too large (Wireshark-like bounded view).
  while (box.childElementCount > PTP_MAX_ROWS) box.removeChild(box.firstElementChild);
  if (ptpAutoScroll) box.scrollTop = box.scrollHeight;
}

function resetPtpMessageList() {
  ptpMessages = [];
  ptpNextIndex = 0;
  ptpAutoScroll = true;
  const box = P("ptp-msg-list");
  box.innerHTML = "";
  box.classList.add("muted");
  box.textContent = "等待报文…";
  P("ptp-sel-hex").textContent = "";
  P("ptp-sel-json").textContent = "";
}

function setPtpRunningUi(running) {
  P("ptp-btn-run").disabled = running;
  P("ptp-btn-stop").disabled = !running;
  P("ptp-btn-json").disabled = running;
  P("ptp-btn-export").disabled = running;
}

function stopPtpPolling() {
  if (ptpPollTimer) {
    clearTimeout(ptpPollTimer);
    ptpPollTimer = null;
  }
}

function applyPtpPollResult(data) {
  if (Array.isArray(data.messages) && data.messages.length) {
    if (P("ptp-msg-list").classList.contains("muted")) {
      P("ptp-msg-list").classList.remove("muted");
      P("ptp-msg-list").textContent = "";
    }
    ptpMessages = ptpMessages.concat(data.messages);
    appendPtpRows(data.messages);
  }
  if (typeof data.next_index === "number") ptpNextIndex = data.next_index;
  renderPtpStats(data.stats);
  const last = data.last_estimate;
  if (last) {
    P("ptp-metrics").textContent =
      "offset=" + last.offset_seconds?.toFixed(9) +
      " s  mean_path_delay=" + last.mean_path_delay_seconds?.toFixed(9) +
      " s  |  报文 " + ptpMessages.length + " 条";
    P("ptp-metrics").classList.remove("muted");
    P("ptp-estimates").textContent = JSON.stringify(data.estimates || [], null, 2);
  } else if (data.gm_clock_identity) {
    P("ptp-metrics").textContent =
      "GM " + data.gm_clock_identity + ":" + data.gm_port_number +
      "  报文 " + ptpMessages.length + " 条";
    P("ptp-metrics").classList.remove("muted");
  }
}

function schedulePtpPoll() {
  stopPtpPolling();
  ptpPollTimer = setTimeout(pollPtpRun, PTP_POLL_MS);
}

async function pollPtpRun() {
  if (!ptpRunId) return;
  let data;
  try {
    const r = await fetch("/api/ptp/g8275-acr/poll?run_id=" + encodeURIComponent(ptpRunId) + "&since=" + ptpNextIndex);
    if (r.status === 404) {
      setPtpStatus("运行会话已失效", "err");
      finishPtpRun();
      return;
    }
    data = await r.json().catch(() => ({}));
    if (!r.ok) {
      setPtpStatus("轮询错误 " + r.status + ": " + (data.detail || r.statusText), "err");
      schedulePtpPoll();
      return;
    }
  } catch (e) {
    setPtpStatus("轮询失败: " + e, "err");
    schedulePtpPoll();
    return;
  }

  applyPtpPollResult(data);

  if (data.status === "finished") {
    finishPtpRun();
    const stopRequested = data.error && String(data.error).indexOf("stop requested") >= 0;
    if (data.error && !stopRequested) {
      setPtpStatus("结束（有错误）: " + data.error, "err");
    } else if (data.cancel_sent) {
      setPtpStatus("已停止，CANCEL 已发送给服务器", "ok");
    } else {
      setPtpStatus("已停止", "ok");
    }
    ptpLastPcap = data.pcap_base64 || null;
    P("ptp-btn-dl-pcap").disabled = !ptpLastPcap;
    P("ptp-pcap-preview").textContent = (data.pcap_preview_lines || []).join("\n");
  } else {
    schedulePtpPoll();
  }
}

function finishPtpRun() {
  stopPtpPolling();
  ptpRunId = null;
  setPtpRunningUi(false);
}

async function previewPtpPacket() {
  setPtpStatus("构建报文中…", "");
  try {
    const r = await fetch("/api/ptp/build", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(buildPtpPreviewSpec()),
    });
    const data = await r.json().catch(() => ({}));
    if (!r.ok) {
      setPtpStatus("错误 " + r.status + ": " + (data.detail || r.statusText), "err");
      return;
    }
    P("ptp-preview-hex").textContent = data.udp_hex || "";
    P("ptp-preview-json").textContent = JSON.stringify(data.packet, null, 2);
    setPtpStatus("预览完成", "ok");
  } catch (e) {
    setPtpStatus(String(e), "err");
  }
}

async function runPtpAcr() {
  const measureRaw = Number(P("ptp-measure-duration").value);
  const hint = measureRaw > 0 ? "约 " + measureRaw + " 秒后自动结束" : "持续运行直到点击停止";
  setPtpStatus("启动 G8275 ACR（" + hint + "）…", "");
  ptpLastPcap = null;
  P("ptp-btn-dl-pcap").disabled = true;
  P("ptp-pcap-preview").textContent = "";
  P("ptp-estimates").textContent = "";
  resetPtpMessageList();
  try {
    const r = await fetch("/api/ptp/g8275-acr/start", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(buildPtpAcrBody()),
    });
    const data = await r.json().catch(() => ({}));
    if (!r.ok) {
      const detail = data.detail || r.statusText;
      setPtpStatus("错误 " + r.status + ": " + (typeof detail === "string" ? detail : JSON.stringify(detail)), "err");
      return;
    }
    ptpRunId = data.run_id;
    setPtpRunningUi(true);
    setPtpStatus("运行中（" + hint + "），每 " + PTP_POLL_MS + " ms 刷新报文…", "ok");
    schedulePtpPoll();
  } catch (e) {
    setPtpStatus(String(e), "err");
  }
}

async function stopPtpAcr() {
  if (!ptpRunId) return;
  P("ptp-btn-stop").disabled = true;
  setPtpStatus("正在停止：结束测量循环并发送 CANCEL…", "");
  try {
    const r = await fetch(
      "/api/ptp/g8275-acr/stop?run_id=" + encodeURIComponent(ptpRunId),
      { method: "POST" }
    );
    if (!r.ok && r.status !== 404) {
      const data = await r.json().catch(() => ({}));
      setPtpStatus("停止请求失败 " + r.status + ": " + (data.detail || r.statusText), "err");
      P("ptp-btn-stop").disabled = false;
    }
    // Polling loop will observe status=finished and restore the UI.
  } catch (e) {
    setPtpStatus("停止请求异常: " + e, "err");
    P("ptp-btn-stop").disabled = false;
  }
}

function downloadPtpPcap() {
  if (!ptpLastPcap) return;
  const bin = Uint8Array.from(atob(ptpLastPcap), (c) => c.charCodeAt(0));
  const blob = new Blob([bin], { type: "application/vnd.tcpdump.pcap" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "ptp-acr-" + Date.now() + ".pcap";
  a.click();
  URL.revokeObjectURL(a.href);
}

P("ptp-btn-preview").addEventListener("click", previewPtpPacket);
P("ptp-btn-run").addEventListener("click", runPtpAcr);
P("ptp-btn-stop").addEventListener("click", stopPtpAcr);
P("ptp-btn-dl-pcap").addEventListener("click", downloadPtpPcap);

P("ptp-btn-export").addEventListener("click", () => {
  const blob = new Blob([JSON.stringify(buildPtpAcrBody(), null, 2)], { type: "application/json" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "ptp-acr-config-" + Date.now() + ".json";
  a.click();
  URL.revokeObjectURL(a.href);
});

P("ptp-btn-json").addEventListener("click", () => {
  P("ptp-ta-json").value = JSON.stringify(buildPtpAcrBody(), null, 2);
  P("ptp-dlg-json").showModal();
});

P("ptp-dlg-json").addEventListener("close", () => {
  if (P("ptp-dlg-json").returnValue !== "ok") return;
  try {
    applyPtpConfig(JSON.parse(P("ptp-ta-json").value.trim()));
    setPtpStatus("已从 JSON 载入", "ok");
  } catch (e) {
    setPtpStatus("JSON 解析失败: " + e, "err");
  }
});

P("ptp-msg-type").addEventListener("change", () => {
  const t = P("ptp-msg-type").value;
  P("ptp-req-port-num").disabled = t !== "delay_resp";
});
