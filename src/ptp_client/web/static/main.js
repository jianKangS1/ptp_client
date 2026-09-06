/* 时间同步客户端实验室 — Vue 3 + Element Plus 前端
 *
 * 迁移自旧版 tabs.js / app.js / ptp-app.js（原生 DOM 操作），逻辑保持一致：
 * - NTP 页签：POST /api/ntp/exchange（单次 SNTP 查询）
 * - PTP 页签：POST /api/ptp/build（离线预览）、POST /api/ptp/g8275-acr/start、
 *   GET /api/ptp/g8275-acr/poll（类 Wireshark 实时报文列表）、POST /api/ptp/g8275-acr/stop（发 CANCEL）
 */
(function () {
  "use strict";

  function parseFrac(s) {
    const t = String(s == null ? "" : s).trim();
    if (!t) return 0;
    if (t.startsWith("0x") || t.startsWith("0X")) return parseInt(t, 16) >>> 0;
    const n = Number(t);
    if (!Number.isFinite(n)) return 0;
    return (n >>> 0) & 0xffffffff;
  }

  function parseHexInt(s) {
    const t = String(s == null ? "" : s).trim();
    if (!t) return 0;
    return parseInt(t, t.startsWith("0x") || t.startsWith("0X") ? 16 : 10);
  }

  function optFloat(v) {
    const t = String(v == null ? "" : v).trim();
    if (t === "") return null;
    const n = Number(t);
    return Number.isFinite(n) ? n : null;
  }

  function downloadBlob(bin, mime, name) {
    const blob = new Blob([bin], { type: mime });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = name;
    a.click();
    URL.revokeObjectURL(a.href);
  }

  function b64ToBytes(b64) {
    return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
  }

  const PTP_POLL_MS = 500;
  const PTP_MAX_ROWS = 3000;

  const app = Vue.createApp({
    data() {
      return {
        activeTab: "ntp",
        ntpCollapse: ["req", "rsp"],

        /* ---------------- NTP ---------------- */
        ntp: {
          host: "pool.ntp.org",
          port: 123,
          timeout: 10,
          sending: false,
          status: { msg: "", kind: "" },
          jsonDlg: false,
          jsonText: "",
          result: {
            metrics: null,
            reqHex: "",
            reqJson: "",
            rspHex: "",
            rspJson: "",
            pcapPreview: "",
            lastPcap: null,
          },
        },
        ntpForm: {
          leap_indicator: 0,
          version: 4,
          mode: 3,
          stratum: 0,
          poll: 0,
          precision: 0,
          root_delay_sec: "",
          root_dispersion_sec: "",
          reference_id: "",
          ref_ts_sec: 0,
          ref_ts_frac: "0",
          recv_ts_sec: 0,
          recv_ts_frac: "0",
          xmit_ts_sec: 0,
          xmit_ts_frac: "0",
          origin_auto_now: true,
          origin_unix: "",
          origin_ntp_sec: 0,
          origin_ntp_frac: "0",
        },

        /* ---------------- PTP ---------------- */
        ptp: {
          master: "172.19.173.58",
          domain: 44,
          bind: "172.19.160.1",
          clock_identity: "0001020304050607",
          port_number: 1,
          announce_log: 0,
          sync_log: 0,
          duration_sec: 60,
          sync_timeout: 8,
          delay_timeout: 8,
          measure_duration_sec: 0,
          dr_flags: "0x400",
          dr_correction: 0,
          dr_interval: 1,
          dr_origin_sec: 0,
          dr_origin_ns: 0,
          preview: { msg_type: "delay_req", seq: 1, log_int: -127, body_sec: 0, body_ns: 0, req_port: 1 },
          running: false,
          starting: false,
          status: { msg: "", kind: "" },
          previewHex: "",
          previewJson: "",
          messages: [],
          stats: {},
          gm: "",
          selected: null,
          autoScroll: true,
          runId: null,
          nextIndex: 0,
          pollTimer: null,
          result: { lastPcap: null, pcapPreview: "" },
          jsonDlg: false,
          jsonText: "",
        },
      };
    },

    computed: {
      ntpStatusType() {
        return this.ntp.status.kind === "ok" ? "success" : this.ntp.status.kind === "err" ? "error" : "info";
      },
      ptpStatusType() {
        return this.ptp.status.kind === "ok" ? "success" : this.ptp.status.kind === "err" ? "error" : "info";
      },
      ptpStatsRows() {
        const stats = this.ptp.stats || {};
        return Object.keys(stats)
          .sort()
          .map((name) => ({
            name,
            tx: stats[name].tx || 0,
            rx: stats[name].rx || 0,
            total: stats[name].total || 0,
          }));
      },
    },

    methods: {
      /* ================= NTP ================= */
      buildNtpPacket() {
        const f = this.ntpForm;
        const packet = {
          leap_indicator: Number(f.leap_indicator) || 0,
          version: Number(f.version) || 4,
          mode: Number(f.mode) || 3,
          stratum: Number(f.stratum) || 0,
          poll: Number(f.poll) || 0,
          precision: Number(f.precision) || 0,
          reference_timestamp: { seconds: Number(f.ref_ts_sec) || 0, fraction: parseFrac(f.ref_ts_frac) },
          receive_timestamp: { seconds: Number(f.recv_ts_sec) || 0, fraction: parseFrac(f.recv_ts_frac) },
          transmit_timestamp: { seconds: Number(f.xmit_ts_sec) || 0, fraction: parseFrac(f.xmit_ts_frac) },
        };
        const rd = optFloat(f.root_delay_sec);
        const rdp = optFloat(f.root_dispersion_sec);
        if (rd !== null) packet.root_delay_sec = rd;
        if (rdp !== null) packet.root_dispersion_sec = rdp;
        const refIdRaw = String(f.reference_id || "").trim();
        if (refIdRaw) {
          if (/^[0-9a-fA-F]{8}$/.test(refIdRaw)) packet.reference_id_hex = refIdRaw;
          else packet.reference_id_ascii = refIdRaw;
        }
        const auto = !!f.origin_auto_now;
        packet.origin_auto_now = auto;
        if (!auto) {
          const ou = String(f.origin_unix || "").trim();
          if (ou) packet.origin_unix = Number(ou);
          else
            packet.origin_ntp = {
              seconds: Number(f.origin_ntp_sec) || 0,
              fraction: parseFrac(f.origin_ntp_frac),
            };
        }
        return packet;
      },

      applyNtpPacket(packet) {
        const p = packet || {};
        const f = this.ntpForm;
        const num = (v, d) => (v === undefined ? d : v);
        if (p.leap_indicator !== undefined) f.leap_indicator = p.leap_indicator;
        if (p.version !== undefined) f.version = p.version;
        if (p.mode !== undefined) f.mode = p.mode;
        if (p.stratum !== undefined) f.stratum = p.stratum;
        if (p.poll !== undefined) f.poll = p.poll;
        if (p.precision !== undefined) f.precision = p.precision;
        f.root_delay_sec = p.root_delay_sec ?? "";
        f.root_dispersion_sec = p.root_dispersion_sec ?? "";
        f.reference_id = p.reference_id_hex || p.reference_id_ascii || p.reference_id || "";
        const rts = p.reference_timestamp || {};
        f.ref_ts_sec = num(rts.seconds, 0);
        f.ref_ts_frac = String(num(rts.fraction, 0));
        const rv = p.receive_timestamp || {};
        f.recv_ts_sec = num(rv.seconds, 0);
        f.recv_ts_frac = String(num(rv.fraction, 0));
        const xt = p.transmit_timestamp || {};
        f.xmit_ts_sec = num(xt.seconds, 0);
        f.xmit_ts_frac = String(num(xt.fraction, 0));
        f.origin_auto_now = p.origin_auto_now !== false;
        f.origin_unix = p.origin_unix ?? "";
        const on = p.origin_ntp || {};
        f.origin_ntp_sec = num(on.seconds, 0);
        f.origin_ntp_frac = String(num(on.fraction, 0));
      },

      ntpBody() {
        return {
          host: String(this.ntp.host || "").trim(),
          port: Number(this.ntp.port),
          timeout: Number(this.ntp.timeout),
          packet: this.buildNtpPacket(),
        };
      },

      async sendExchange() {
        this.ntp.sending = true;
        this.setNtpStatus("请求中…", "");
        this.ntp.result.lastPcap = null;
        try {
          const r = await fetch("/api/ntp/exchange", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(this.ntpBody()),
          });
          const data = await r.json().catch(() => ({}));
          if (!r.ok) {
            const detail = data.detail || data.message || r.statusText;
            this.setNtpStatus(`错误 ${r.status}: ${typeof detail === "string" ? detail : JSON.stringify(detail)}`, "err");
            return;
          }
          this.setNtpStatus("完成", "ok");
          this.ntp.result = {
            metrics: {
              offset: data.offset_seconds?.toFixed(6) + " s",
              rtt: data.round_trip_delay_seconds?.toFixed(6) + " s",
              route: `client ${data.client?.ip}:${data.client?.port} → server ${data.server?.ip}:${data.server?.port}`,
            },
            reqHex: data.request_udp_hex || "",
            rspHex: data.response_udp_hex || "",
            reqJson: JSON.stringify(data.request_packet, null, 2),
            rspJson: JSON.stringify(data.response_packet, null, 2),
            pcapPreview: (data.pcap_preview_lines || []).join("\n"),
            lastPcap: data.pcap_base64 || null,
          };
        } catch (e) {
          this.setNtpStatus(String(e), "err");
        } finally {
          this.ntp.sending = false;
        }
      },

      downloadNtpPcap() {
        if (!this.ntp.result.lastPcap) return;
        downloadBlob(
          b64ToBytes(this.ntp.result.lastPcap),
          "application/vnd.tcpdump.pcap",
          `ntp-exchange-${Date.now()}.pcap`
        );
      },

      openNtpJson() {
        this.ntp.jsonText = JSON.stringify(this.ntpBody(), null, 2);
        this.ntp.jsonDlg = true;
      },

      exportNtpJson() {
        downloadBlob(
          new TextEncoder().encode(JSON.stringify(this.buildNtpPacket(), null, 2)),
          "application/json",
          `ntp-packet-${Date.now()}.json`
        );
      },

      applyNtpJson() {
        let raw = String(this.ntp.jsonText || "").trim();
        if (!raw) return;
        let obj;
        try {
          obj = JSON.parse(raw);
        } catch (e) {
          this.setNtpStatus("JSON 解析失败: " + e, "err");
          return;
        }
        if (obj.packet) {
          if (obj.host) this.ntp.host = obj.host;
          if (obj.port !== undefined) this.ntp.port = obj.port;
          if (obj.timeout !== undefined) this.ntp.timeout = obj.timeout;
          this.applyNtpPacket(obj.packet);
        } else {
          this.applyNtpPacket(obj);
        }
        this.ntp.jsonDlg = false;
        this.setNtpStatus("已从 JSON 载入报文字段", "ok");
      },

      setNtpStatus(msg, kind) {
        this.ntp.status = { msg: msg || "", kind: kind || "" };
      },

      /* ================= PTP ================= */
      buildPtpPreviewSpec() {
        const pv = this.ptp.preview;
        const spec = {
          message_type: pv.msg_type,
          domain_number: Number(this.ptp.domain),
          flags: parseHexInt(this.ptp.dr_flags),
          correction_field_ns: Number(this.ptp.dr_correction) || 0,
          sequence_id: Number(pv.seq) || 0,
          log_message_interval: Number(pv.log_int),
          clock_identity: String(this.ptp.clock_identity || "").trim(),
          port_number: Number(this.ptp.port_number) || 0,
        };
        const ts = { seconds: Number(pv.body_sec) || 0, nanoseconds: Number(pv.body_ns) || 0 };
        if (pv.msg_type === "follow_up") spec.precise_origin_timestamp = ts;
        else if (pv.msg_type === "delay_resp") {
          spec.receive_timestamp = ts;
          spec.requesting_port_identity = {
            clock_identity: spec.clock_identity,
            port_number: Number(pv.req_port) || 0,
          };
        } else spec.origin_timestamp = ts;
        return spec;
      },

      buildPtpAcrBody() {
        const t = this.ptp;
        const bind = String(t.bind || "").trim();
        const interval = Number(t.dr_interval);
        const measureRaw = Number(t.measure_duration_sec);
        const body = {
          master: String(t.master || "").trim(),
          domain: Number(t.domain),
          clock_identity: String(t.clock_identity || "").trim(),
          port_number: Number(t.port_number) || 0,
          announce_log: Number(t.announce_log) || 0,
          sync_log: Number(t.sync_log) || 0,
          duration_sec: Number(t.duration_sec) || 0,
          sync_timeout: Number(t.sync_timeout),
          delay_timeout: Number(t.delay_timeout),
          measure_duration_sec: measureRaw > 0 ? measureRaw : null,
          delay_request: {
            flags: parseHexInt(t.dr_flags),
            correction_field_ns: Number(t.dr_correction) || 0,
            origin_timestamp: {
              seconds: Number(t.dr_origin_sec) || 0,
              nanoseconds: Number(t.dr_origin_ns) || 0,
            },
            request_interval_sec: interval > 0 ? interval : null,
          },
        };
        if (bind) body.bind = bind;
        return body;
      },

      applyPtpConfig(obj) {
        const c = obj || {};
        const t = this.ptp;
        if (c.master) t.master = c.master;
        if (c.domain !== undefined) t.domain = c.domain;
        if (c.bind) t.bind = c.bind;
        if (c.clock_identity) t.clock_identity = c.clock_identity;
        if (c.port_number !== undefined) t.port_number = c.port_number;
        if (c.announce_log !== undefined) t.announce_log = c.announce_log;
        if (c.sync_log !== undefined) t.sync_log = c.sync_log;
        if (c.duration_sec !== undefined) t.duration_sec = c.duration_sec;
        if (c.sync_timeout !== undefined) t.sync_timeout = c.sync_timeout;
        if (c.delay_timeout !== undefined) t.delay_timeout = c.delay_timeout;
        if (c.measure_duration_sec !== undefined) t.measure_duration_sec = c.measure_duration_sec ?? 0;
        const dr = c.delay_request || {};
        if (dr.flags !== undefined) t.dr_flags = "0x" + Number(dr.flags).toString(16);
        if (dr.correction_field_ns !== undefined) t.dr_correction = dr.correction_field_ns;
        const ot = dr.origin_timestamp || {};
        if (ot.seconds !== undefined) t.dr_origin_sec = ot.seconds;
        if (ot.nanoseconds !== undefined) t.dr_origin_ns = ot.nanoseconds;
        const iv = dr.request_interval_sec ?? dr.requestIntervalSec;
        if (iv !== undefined && iv !== null) t.dr_interval = iv;
      },

      fmtTime(unix) {
        const d = new Date(unix * 1000);
        const ms = String(d.getMilliseconds()).padStart(3, "0");
        return (
          String(d.getHours()).padStart(2, "0") + ":" +
          String(d.getMinutes()).padStart(2, "0") + ":" +
          String(d.getSeconds()).padStart(2, "0") + "." + ms
        );
      },

      msgTypeName(rec) {
        return (rec.summary && rec.summary.message_type_name) || "?";
      },

      msgInfo(rec) {
        const seq = rec.summary && rec.summary.sequence_id != null ? rec.summary.sequence_id : "-";
        return `seq=${seq} ${rec.src || ""} → ${rec.dst || ""}`;
      },

      onPtpRowClick(row) {
        this.ptp.autoScroll = false;
        this.ptp.selected = row;
      },

      resetPtpMessageList() {
        this.ptp.messages = [];
        this.ptp.nextIndex = 0;
        this.ptp.autoScroll = true;
        this.ptp.selected = null;
        this.ptp.stats = {};
        this.ptp.gm = "";
      },

      applyPtpPollResult(data) {
        if (Array.isArray(data.messages) && data.messages.length) {
          this.ptp.messages = this.ptp.messages.concat(data.messages);
          if (this.ptp.messages.length > PTP_MAX_ROWS) {
            this.ptp.messages = this.ptp.messages.slice(-PTP_MAX_ROWS);
          }
          if (this.ptp.autoScroll) {
            this.$nextTick(() => {
              const tbl = this.$refs.msgTable;
              if (tbl) tbl.setScrollTop(999999);
            });
          }
        }
        if (typeof data.next_index === "number") this.ptp.nextIndex = data.next_index;
        if (data.stats) this.ptp.stats = data.stats;
        if (data.gm_clock_identity) {
          this.ptp.gm = data.gm_clock_identity + ":" + data.gm_port_number;
        }
      },

      schedulePtpPoll() {
        this.stopPtpPolling();
        this.ptp.pollTimer = setTimeout(() => this.pollPtpRun(), PTP_POLL_MS);
      },

      stopPtpPolling() {
        if (this.ptp.pollTimer) {
          clearTimeout(this.ptp.pollTimer);
          this.ptp.pollTimer = null;
        }
      },

      async pollPtpRun() {
        if (!this.ptp.runId) return;
        let data;
        try {
          const r = await fetch(
            "/api/ptp/g8275-acr/poll?run_id=" + encodeURIComponent(this.ptp.runId) + "&since=" + this.ptp.nextIndex
          );
          if (r.status === 404) {
            this.setPtpStatus("运行会话已失效", "err");
            this.finishPtpRun();
            return;
          }
          data = await r.json().catch(() => ({}));
          if (!r.ok) {
            this.setPtpStatus("轮询错误 " + r.status + ": " + (data.detail || r.statusText), "err");
            this.schedulePtpPoll();
            return;
          }
        } catch (e) {
          this.setPtpStatus("轮询失败: " + e, "err");
          this.schedulePtpPoll();
          return;
        }

        this.applyPtpPollResult(data);

        if (data.status === "finished") {
          this.finishPtpRun();
          const stopRequested = data.error && String(data.error).indexOf("stop requested") >= 0;
          if (data.error && !stopRequested) {
            this.setPtpStatus("结束（有错误）: " + data.error, "err");
          } else if (data.cancel_sent) {
            this.setPtpStatus("已停止，CANCEL 已发送给服务器", "ok");
          } else {
            this.setPtpStatus("已停止", "ok");
          }
          this.ptp.result.lastPcap = data.pcap_base64 || null;
          this.ptp.result.pcapPreview = (data.pcap_preview_lines || []).join("\n");
        } else {
          this.schedulePtpPoll();
        }
      },

      finishPtpRun() {
        this.stopPtpPolling();
        this.ptp.runId = null;
        this.ptp.running = false;
      },

      async previewPtpPacket() {
        this.setPtpStatus("构建报文中…", "");
        try {
          const r = await fetch("/api/ptp/build", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(this.buildPtpPreviewSpec()),
          });
          const data = await r.json().catch(() => ({}));
          if (!r.ok) {
            this.setPtpStatus("错误 " + r.status + ": " + (data.detail || r.statusText), "err");
            return;
          }
          this.ptp.previewHex = data.udp_hex || "";
          this.ptp.previewJson = JSON.stringify(data.packet, null, 2);
          this.setPtpStatus("预览完成", "ok");
        } catch (e) {
          this.setPtpStatus(String(e), "err");
        }
      },

      async runPtpAcr() {
        const measureRaw = Number(this.ptp.measure_duration_sec);
        const hint = measureRaw > 0 ? "约 " + measureRaw + " 秒后自动结束" : "持续运行直到点击停止";
        this.setPtpStatus("启动 G8275 ACR（" + hint + "）…", "");
        this.ptp.starting = true;
        this.ptp.result.lastPcap = null;
        this.ptp.result.pcapPreview = "";
        this.resetPtpMessageList();
        try {
          const r = await fetch("/api/ptp/g8275-acr/start", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(this.buildPtpAcrBody()),
          });
          const data = await r.json().catch(() => ({}));
          if (!r.ok) {
            const detail = data.detail || r.statusText;
            this.setPtpStatus(
              "错误 " + r.status + ": " + (typeof detail === "string" ? detail : JSON.stringify(detail)),
              "err"
            );
            return;
          }
          this.ptp.runId = data.run_id;
          this.ptp.running = true;
          this.setPtpStatus("运行中（" + hint + "），每 " + PTP_POLL_MS + " ms 刷新报文…", "ok");
          this.schedulePtpPoll();
        } catch (e) {
          this.setPtpStatus(String(e), "err");
        } finally {
          this.ptp.starting = false;
        }
      },

      async stopPtpAcr() {
        if (!this.ptp.runId) return;
        this.setPtpStatus("正在停止：结束测量循环并发送 CANCEL…", "");
        try {
          const r = await fetch("/api/ptp/g8275-acr/stop?run_id=" + encodeURIComponent(this.ptp.runId), {
            method: "POST",
          });
          if (!r.ok && r.status !== 404) {
            const data = await r.json().catch(() => ({}));
            this.setPtpStatus("停止请求失败 " + r.status + ": " + (data.detail || r.statusText), "err");
          }
          // 轮询循环会观察到 status=finished 并恢复 UI
        } catch (e) {
          this.setPtpStatus("停止请求异常: " + e, "err");
        }
      },

      downloadPtpPcap() {
        if (!this.ptp.result.lastPcap) return;
        downloadBlob(
          b64ToBytes(this.ptp.result.lastPcap),
          "application/vnd.tcpdump.pcap",
          "ptp-acr-" + Date.now() + ".pcap"
        );
      },

      openPtpJson() {
        this.ptp.jsonText = JSON.stringify(this.buildPtpAcrBody(), null, 2);
        this.ptp.jsonDlg = true;
      },

      exportPtpJson() {
        downloadBlob(
          new TextEncoder().encode(JSON.stringify(this.buildPtpAcrBody(), null, 2)),
          "application/json",
          "ptp-acr-config-" + Date.now() + ".json"
        );
      },

      applyPtpJson() {
        try {
          this.applyPtpConfig(JSON.parse(String(this.ptp.jsonText || "").trim()));
          this.ptp.jsonDlg = false;
          this.setPtpStatus("已从 JSON 载入", "ok");
        } catch (e) {
          this.setPtpStatus("JSON 解析失败: " + e, "err");
        }
      },

      setPtpStatus(msg, kind) {
        this.ptp.status = { msg: msg || "", kind: kind || "" };
      },
    },

    beforeUnmount() {
      this.stopPtpPolling();
    },
  });

  app.use(ElementPlus, { locale: ElementPlusLocaleZhCn });
  app.mount("#app");
})();
