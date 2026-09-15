/* 时间同步客户端实验室 — Vue 3 + Element Plus 前端
 *
 * 迁移自旧版 tabs.js / app.js / ptp-app.js（原生 DOM 操作），逻辑保持一致：
 * - NTP 页签：POST /api/ntp/exchange（单次 SNTP 查询）
 * - PTP 页签：POST /api/ptp/build（离线预览）、POST /api/ptp/signaling/build
 *   （Signaling 报文按 Wireshark 字段顺序构造）、POST /api/ptp/g8275-acr/start、
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

  function hexToBytes(hex) {
    const clean = String(hex || "").replace(/[^0-9a-fA-F]/g, "");
    const a = new Uint8Array(clean.length >> 1);
    for (let i = 0; i < a.length; i++) a[i] = parseInt(clean.substr(i * 2, 2), 16);
    return a;
  }

  // 当前选中 Signaling 报文的字节缓冲（非响应式，避免 Proxy 包裹 TypedArray 影响 DataView）
  let sigBytes = null;

  const PTP_POLL_MS = 500;
  const PTP_MAX_ROWS = 3000;

  /* ---------------- Wireshark 风格 Signaling 字段树 ---------------- */
  // IEEE 1588 messageType（TLV 内高 4 bit 携带 ptpMessageType<<4）
  const PTP_MT_NAMES = {
    0x0: "Sync Message", 0x1: "Delay_Req Message", 0x2: "Pdelay_Req Message",
    0x3: "Pdelay_Resp Message", 0x8: "Follow_Up Message", 0x9: "Delay_Resp Message",
    0xa: "Pdelay_Resp_Follow_Up Message", 0xb: "Announce Message",
    0xc: "Signaling Message", 0xd: "Management Message",
  };
  const PTP_CONTROL_NAMES = {
    0x0: "Sync Message", 0x1: "Delay Request Message", 0x2: "Pdelay Request Message",
    0x3: "Pdelay Response Message", 0x4: "Follow Up Message", 0x5: "Other Message",
    0x6: "Other Message", 0x7: "Announce Message", 0x8: "Management Message",
    0x9: "Other Message", 0xa: "Signaling Message",
  };
  // Wireshark flags 位序（16 bit，MSB→LSB）
  const PTP_FLAG_BITS = [
    { bit: 15, name: "PTP_SECURITY" },
    { bit: 14, name: "PTP profile Specific 2" },
    { bit: 13, name: "PTP profile Specific 1" },
    { bit: 10, name: "PTP_UNICAST" },
    { bit: 9, name: "PTP_TWO_STEP" },
    { bit: 8, name: "PTP_ALTERNATE_MASTER" },
    { bit: 6, name: "SYNCHRONIZATION_UNCERTAIN" },
    { bit: 5, name: "FREQUENCY_TRACEABLE" },
    { bit: 4, name: "TIME_TRACEABLE" },
    { bit: 3, name: "PTP_TIMESCALE" },
    { bit: 2, name: "PTP_UTC_REASONABLE" },
    { bit: 1, name: "PTP_LI_59" },
    { bit: 0, name: "PTP_LI_61" },
  ];
  const TLV_NAMES = {
    0x0004: "Request unicast transmission TLV",
    0x0005: "Grant unicast transmission TLV",
    0x0006: "Cancel unicast transmission TLV",
    0x0007: "Acknowledge cancel unicast transmission TLV",
    0x0000: "Management TLV",
    0x0001: "Management error TLV",
    0x0003: "Organization extension TLV",
  };
  // 构造表单下拉选项（值 = 线上字段值）
  const MT_OPTIONS = [
    { value: 0, label: "Sync Message (0x0)" },
    { value: 1, label: "Delay_Req Message (0x1)" },
    { value: 2, label: "Pdelay_Req Message (0x2)" },
    { value: 3, label: "Pdelay_Resp Message (0x3)" },
    { value: 8, label: "Follow_Up Message (0x8)" },
    { value: 9, label: "Delay_Resp Message (0x9)" },
    { value: 11, label: "Announce Message (0xb)" },
    { value: 12, label: "Signaling Message (0xc)" },
    { value: 13, label: "Management Message (0xd)" },
  ];
  const TLV_TYPE_OPTIONS = [
    { value: 4, label: "Request unicast transmission (0x0004)" },
    { value: 5, label: "Grant unicast transmission (0x0005)" },
    { value: 6, label: "Cancel unicast transmission (0x0006)" },
    { value: 7, label: "Acknowledge cancel unicast transmission (0x0007)" },
  ];

  function hex4(s) { return "0x" + (s >>> 0).toString(16).padStart(4, "0"); }
  function mtName(v) { return PTP_MT_NAMES[v] || ("Unknown (0x" + (v & 0xf).toString(16) + ")"); }

  /* ---------------- Master 模式：Wireshark 报文字段格式化 ---------------- */
  const MASTER_CONTROL_NAMES = {
    0: "Sync Message (0)", 1: "Delay Request Message (1)", 2: "Follow Up Message (2)",
    3: "Delay Response Message (3)", 5: "Other Message (5)",
  };
  // clockAccuracy：Wireshark 按 1588 表映射（十进制 0-255）
  function masterAccuracyName(v) {
    const n = Number(v) & 0xff;
    if (n === 0x20) return "The time source is off-calibration to 1024 s (0x20)";
    if (n >= 0x21 && n <= 0x26) return "The time is accurate to 2^(" + (n - 30) + ") s (0x" + n.toString(16) + ")";
    if (n === 0x27) return "The time is accurate to <100 ns (0x27)";
    if (n === 0x28) return "The time is accurate to <25 ns (0x28)";
    if (n === 0x29) return "The time is accurate to <10 ns (0x29)";
    if (n === 0x2a) return "The time is accurate to <1 ns (0x2a)";
    if (n === 0x2b) return "The time is accurate to <0.1 ns (0x2b)";
    if (n === 0x2c) return "The time is accurate to <25 ps (0x2c)";
    if (n === 0x2d) return "The time is accurate to <10 ps (0x2d)";
    if (n === 0x2e) return "The time is accurate to <1 ps (0x2e)";
    if (n === 0x30) return "The time is accurate to >10 s (0x30)";
    if (n === 0x31) return "The time is accurate to >10 s (0x31)";
    return "0x" + n.toString(16);
  }
  const MASTER_TIME_SOURCE = {
    0x10: "GPS (0x10)", 0x20: "atomic clock (0x20)", 0x30: "ground station (0x30)",
    0x40: "mobility (0x40)", 0x50: "National measurement agency (0x50)",
    0x60: "private (0x60)", 0x70: "not synchronized (0x70)",
    0x80: "not for quality (0x80) - free running", 0x90: "not for quality (0x90) - 2nd generation IP",
    0xa0: "not for quality (0xa0) - 1st generation IP", 0xb0: "reserved (0xb0)", 0xff: "Unknown (0xff)",
  };
  function masterTimeSourceName(v) {
    const n = Number(v) & 0xff;
    return MASTER_TIME_SOURCE[n] || ("Unknown (0x" + n.toString(16) + ")");
  }
  function masterHex(v, width) {
    return "0x" + (Number(v) >>> 0).toString(16).padStart(width, "0");
  }
  // logMessageInterval 的秒数说明，如 -3 → "-3 (0.125000 s)"
  function masterLogInterval(v) {
    const n = Number(v);
    if (n === 0x7f || n === -128) return "0x7f (N/A)";
    const sec = Math.pow(2, n);
    return n + " (" + sec.toFixed(6) + " s)";
  }

  // 生成 Wireshark 位掩码前缀，例如 ".... .0.. .... ...."（pos 处显示实际 bit 值）
  function bitPattern(bit, value) {
    const arr = [];
    for (let i = 15; i >= 0; i--) arr.push(i === bit ? String(value) : ".");
    let out = "";
    for (let g = 0; g < 4; g++) out += arr.slice(g * 4, g * 4 + 4).join("");
    return out.slice(0, 4) + " " + out.slice(4, 8) + " " + out.slice(8, 12) + " " + out.slice(12, 16);
  }
  // 单字节内高/低 nibble 前缀，如 "0000 ...." / ".... 1100"
  function nibPattern(byte, which) {
    const hi = (byte >> 4) & 0xf;
    const lo = byte & 0xf;
    const fmt = (n, show) => (show ? n.toString(2).padStart(4, "0") : "....");
    return fmt(hi, which === "hi") + " " + fmt(lo, which === "lo");
  }

  function parseSignalingTree(bytes) {
    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const u8 = (o) => bytes[o];
    const u16 = (o) => dv.getUint16(o, false);
    const u32 = (o) => dv.getUint32(o, false);
    const i8 = (o) => dv.getInt8(o);
    const rows = [];
    const leaf = (r) => rows.push(r);

    const b0 = u8(0);
    leaf({ depth: 0, name: "majorSdoId", bits: nibPattern(b0, "hi"), display: "Unknown (" + hex1((b0 >> 4) & 0xf) + ")", edit: { kind: "nib", off: 0, shift: 4 }, model: String((b0 >> 4) & 0xf) });
    leaf({ depth: 0, name: "messageType", bits: nibPattern(b0, "lo"), display: mtName(b0 & 0xf) + " (0x" + (b0 & 0xf).toString(16) + ")", edit: { kind: "nib", off: 0, shift: 0 }, model: String(b0 & 0xf) });
    const b1 = u8(1);
    leaf({ depth: 0, name: "minorVersionPTP", bits: nibPattern(b1, "hi"), display: String((b1 >> 4) & 0xf), edit: { kind: "nib", off: 1, shift: 4 }, model: String((b1 >> 4) & 0xf) });
    leaf({ depth: 0, name: "versionPTP", bits: nibPattern(b1, "lo"), display: String(b1 & 0xf), edit: { kind: "nib", off: 1, shift: 0 }, model: String(b1 & 0xf) });
    leaf({ depth: 0, name: "messageLength", display: String(u16(2)), edit: { kind: "u16", off: 2 }, model: String(u16(2)) });
    leaf({ depth: 0, name: "domainNumber", display: String(u8(4)), edit: { kind: "u8", off: 4 }, model: String(u8(4)) });
    leaf({ depth: 0, name: "minorSdoId", display: String(u8(5)), edit: { kind: "u8", off: 5 }, model: String(u8(5)) });
    const flags = u16(6);
    leaf({ depth: 0, name: "flags", display: hex4(flags) + flagSummary(flags), edit: { kind: "u16", off: 6 }, model: hex4(flags) });
    for (const fb of PTP_FLAG_BITS) {
      const v = (flags >> fb.bit) & 1;
      leaf({ depth: 1, name: fb.name, bits: bitPattern(fb.bit, v), display: v ? "True" : "False" });
    }
    const corrRaw = dv.getBigInt64(8, false);
    const corrNs = Number(corrRaw) / 65536;
    leaf({ depth: 0, name: "correctionField", display: corrNs.toFixed(6) + " nanoseconds", edit: { kind: "ns", off: 8 }, model: String(corrNs) });
    leaf({ depth: 1, name: "correctionNs", display: Math.trunc(corrNs) + " nanoseconds" });
    leaf({ depth: 1, name: "correctionSubNs", display: ((corrRaw & 0xffffn) / 65536).toFixed(6) + " nanoseconds" });
    leaf({ depth: 0, name: "messageTypeSpecific", display: String(u32(16)), edit: { kind: "u32", off: 16 }, model: String(u32(16)) });
    leaf({ depth: 0, name: "ClockIdentity", display: "0x" + hexSlice(bytes, 20, 8), edit: { kind: "hex", off: 20, len: 8 }, model: hexSlice(bytes, 20, 8) });
    leaf({ depth: 0, name: "SourcePortID", display: String(u16(28)), edit: { kind: "u16", off: 28 }, model: String(u16(28)) });
    leaf({ depth: 0, name: "sequenceId", display: String(u16(30)), edit: { kind: "u16", off: 30 }, model: String(u16(30)) });
    leaf({ depth: 0, name: "controlField", display: (PTP_CONTROL_NAMES[u8(32)] || "Other Message") + " (" + u8(32) + ")", edit: { kind: "u8", off: 32 }, model: String(u8(32)) });
    leaf({ depth: 0, name: "logMessageInterval", display: String(i8(33)), edit: { kind: "i8", off: 33 }, model: String(i8(33)) });
    leaf({ depth: 0, name: "targetPortIdentity", display: "0x" + hexSlice(bytes, 34, 8), edit: { kind: "hex", off: 34, len: 8 }, model: hexSlice(bytes, 34, 8) });
    leaf({ depth: 0, name: "targetPortId", display: String(u16(42)), edit: { kind: "u16", off: 42 }, model: String(u16(42)) });

    // TLV 区（从 44 起）
    let off = 44;
    let tlvIdx = 0;
    while (off + 4 <= bytes.length) {
      const typ = u16(off);
      const ln = u16(off + 2);
      const voff = off + 4;
      if (voff + ln > bytes.length) break;
      const label = TLV_NAMES[typ] || ("Unknown TLV (0x" + typ.toString(16) + ")");
      leaf({ depth: 0, name: label, group: true, gname: "tlv" + tlvIdx });
      leaf({ depth: 1, name: "tlvType", display: label.replace(/ TLV$/, "") + " (" + hex4(typ) + ")" });
      leaf({ depth: 1, name: "lengthField", display: String(ln) });
      if ((typ === 0x0004 || typ === 0x0005) && ln >= 6) {
        const mt = (u8(voff) >> 4) & 0xf;
        leaf({ depth: 1, name: "messageType", bits: nibPattern(u8(voff), "hi"), display: mtName(mt) + " (0x" + mt.toString(16) + ")", edit: { kind: "nib", off: voff, shift: 4 }, model: String(mt) });
        leaf({ depth: 1, name: "logInterMessagePeriod", display: String(i8(voff + 1)), edit: { kind: "i8", off: voff + 1 }, model: String(i8(voff + 1)) });
        leaf({ depth: 1, name: "durationField", display: u32(voff + 2) + " seconds", edit: { kind: "u32", off: voff + 2 }, model: String(u32(voff + 2)) });
        if (typ === 0x0005 && ln >= 8) {
          leaf({ depth: 1, name: "reserved", display: String(u8(voff + 6)), edit: { kind: "u8", off: voff + 6 }, model: String(u8(voff + 6)) });
          leaf({ depth: 1, name: "flags", display: hex1(u8(voff + 7)), edit: { kind: "u8", off: voff + 7 }, model: String(u8(voff + 7)) });
        }
      } else if ((typ === 0x0006 || typ === 0x0007) && ln >= 2) {
        const mt = (u8(voff) >> 4) & 0xf;
        leaf({ depth: 1, name: "messageType", bits: nibPattern(u8(voff), "hi"), display: mtName(mt) + " (0x" + mt.toString(16) + ")", edit: { kind: "nib", off: voff, shift: 4 }, model: String(mt) });
        leaf({ depth: 1, name: "reserved", display: String(u8(voff + 1)), edit: { kind: "u8", off: voff + 1 }, model: String(u8(voff + 1)) });
      } else {
        leaf({ depth: 1, name: "value", display: hexSlice(bytes, voff, ln) });
      }
      off = voff + ln;
      tlvIdx++;
    }
    return rows;
  }

  function hex1(n) { return "0x" + (n & 0xf).toString(16); }
  function hexSlice(bytes, off, len) {
    let s = "";
    for (let i = 0; i < len; i++) s += (bytes[off + i] & 0xff).toString(16).padStart(2, "0");
    return s;
  }
  function flagSummary(flags) {
    const on = PTP_FLAG_BITS.filter((f) => (flags >> f.bit) & 1).map((f) => f.name);
    return on.length ? ", " + on.join(", ") : "";
  }

  // 解析用户输入（支持 0x 前缀 / 十进制），非法返回 null
  function parseEditValue(str) {
    const t = String(str == null ? "" : str).trim();
    if (!t) return null;
    const n = parseHexInt(t);
    return Number.isFinite(n) ? n : null;
  }

  // 将用户输入写回字节数组；成功返回 true
  function applySigEdit(bytes, edit, str) {
    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    if (edit.kind === "hex") {
      const clean = String(str == null ? "" : str).replace(/[^0-9a-fA-F]/g, "");
      if (!clean) return false;
      for (let i = 0; i < edit.len; i++) {
        const pair = clean.substr(i * 2, 2);
        bytes[edit.off + i] = pair ? parseInt(pair, 16) & 0xff : 0;
      }
      return true;
    }
    if (edit.kind === "ns") {
      const t = String(str == null ? "" : str).trim();
      const n = Number(t);
      if (!Number.isFinite(n)) return false;
      dv.setBigInt64(edit.off, BigInt(Math.round(n * 65536)), false);
      return true;
    }
    const v = parseEditValue(str);
    if (v === null) return false;
    if (edit.kind === "nib") {
      const shift = edit.shift;
      bytes[edit.off] = (bytes[edit.off] & ~(0xf << shift)) | ((v & 0xf) << shift);
    } else if (edit.kind === "u8") {
      bytes[edit.off] = v & 0xff;
    } else if (edit.kind === "i8") {
      dv.setInt8(edit.off, v);
    } else if (edit.kind === "u16") {
      dv.setUint16(edit.off, v & 0xffff, false);
    } else if (edit.kind === "u32") {
      dv.setUint32(edit.off, v >>> 0, false);
    } else {
      return false;
    }
    return true;
  }

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
          bind: "172.19.160.1",
          /* Signaling 报文构造（字段顺序与 Wireshark 一致） */
          sigBuild: {
            major_sdo_id: 0,
            message_type: 12,
            minor_version_ptp: 0,
            version_ptp: 2,
            domain_number: 44,
            minor_sdo_id: 0,
            flags: "0x0400",
            correction_field_ns: 0,
            message_type_specific: 0,
            clock_identity: "0001020304050607",
            source_port_id: 1,
            sequence_id: 2,
            control_field: 5,
            log_message_interval: 127,
            target_clock_identity: "00155dfffe1e3baf",
            target_port_id: 1,
            tlv_type: 4,
            tlv_message_type: 0,
            log_inter_message_period: 0,
            duration_sec: 60,
            master_ip: "172.19.173.58",
            client_ip: "172.19.160.1",
            src_port: 320,
            dst_port: 320,
            collapse: ["ptp", "tlv"],
          },
          sigHex: "",
          sigFrameHex: "",
          sigJson: "",
          sigBuilding: false,
          /* Delay_Req 报文构造（字段顺序与 Wireshark 一致） */
          drBuild: {
            version_ptp: 2,
            domain_number: 44,
            minor_sdo_id: 0,
            flags: "0x0400",
            correction_field_ns: 0,
            clock_identity: "0001020304050607",
            source_port_id: 1,
            sequence_id: 1,
            control_field: 1,
            log_message_interval: 0,
            origin_sec: 0,
            origin_ns: 0,
            master_ip: "172.19.173.58",
            client_ip: "172.19.160.1",
            src_port: 319,
            dst_port: 319,
            collapse: ["ptp", "body"],
          },
          drHex: "",
          drFrameHex: "",
          drJson: "",
          drBuilding: false,
          running: false,
          starting: false,
          status: { msg: "", kind: "" },
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
          /* Wireshark 风格字段树（当前仅 Signaling 报文） */
          sig: { rows: [], collapse: ["sig"] },
          /* 异常模式（故障注入） */
          fault: { mode: "fault_delay_req", interval: 1 },
        },

        /* ---------------- L2 Master（G.8275.1 / 1588v2） ---------------- */
        master: {
          running: false,
          starting: false,
          applying: false,
          status: { msg: "", kind: "" },
          interfaces: [],
          srcMac: "",
          treeCollapse: ["announce", "sync", "followup", "delayresp"],
          cfg: {
            profile: "g82751",
            interface: "",
            domainNumber: 43,
            clockIdentity: "0001020304050607",
            portNumber: 1,
            /* Announce */
            priority1: 128,
            priority2: 128,
            clockClass: 6,
            clockAccuracy: 49,
            offsetScaledLogVariance: 65535,
            timeSource: 72,
            currentUtcOffset: 0,
            logAnnounceInterval: -3,
            /* Sync / Follow_Up */
            logSyncInterval: -4,
            /* flagField（16 bit，线上原值；bit9=twoStep、bit10=unicast 语义位） */
            announceFlags: 0x0038,
            syncFlags: 0x0200,
            followUpFlags: 0x0200,
            delayRespFlags: 0x0000,
            /* L2 封装 */
            transportSpecific: 0,
            vlanId: null,
            vlanPcp: 6,
            dstMac: "01-1B-19-00-00-00",
            /* 通用头联动：开=四类报文共享头字段；关=逐报文独立覆盖 */
            headerLink: true,
            msgOverrides: { announce: {}, sync: {}, followup: {}, delayresp: {} },
          },
          stats: null,
          slaves: [],
          messages: [],
          selected: null,
          nextIndex: 0,
          eventSource: null,
          frameBuffer: [],
          frameFlushTimer: null,
          autoScroll: true,
        },

        /* 构造表单下拉选项（供模板使用） */
        sigMtOptions: MT_OPTIONS,
        sigTlvOptions: TLV_TYPE_OPTIONS,
      };
    },

    computed: {
      ntpStatusType() {
        return this.ntp.status.kind === "ok" ? "success" : this.ntp.status.kind === "err" ? "error" : "info";
      },
      ptpStatusType() {
        return this.ptp.status.kind === "ok" ? "success" : this.ptp.status.kind === "err" ? "error" : "info";
      },
      masterStatusType() {
        return this.master.status.kind === "ok" ? "success" : this.master.status.kind === "err" ? "error" : "info";
      },
      /* 四类报文的 Wireshark 字段树（顺序与 Wireshark 解析一致；可编辑项直接绑定 master.cfg） */
      masterTrees() {
        const c = this.master.cfg;
        const srcMac = this.master.srcMac || "（启动后由网卡决定）";
        const N = (v) => Number(v) || 0;
        const RO = (name, display, bits, depth) => ({ name, type: "ro", display: String(display), bits: bits || "", depth: depth || 0 });
        const ED = (name, model, bits, width) => ({
          name, model, bits: bits || "", width: width || "150px",
          type: "ed", edit: true, display: this.getMasterField(model),
        });
        // flags 位掩码子行（遍历全部标准位）；每一位都可点击切换对应报文 flags 整数
        const flagRows = (flags, field) =>
          PTP_FLAG_BITS.map((fb) => ({
            bits: bitPattern(fb.bit, (flags >> fb.bit) & 1),
            name: fb.name,
            type: "toggle",
            toggleField: field,
            toggleBit: fb.bit,
            display: (flags >> fb.bit) & 1 ? "True" : "False",
            depth: 1,
          }));
        const flagHex = (flags) => {
          const names = PTP_FLAG_BITS.filter((fb) => (flags >> fb.bit) & 1).map((fb) => fb.name);
          return "0x" + (flags & 0xffff).toString(16).padStart(4, "0") + (names.length ? ", " + names.join(", ") : "");
        };
        // 生效值：联动开启时取共享 cfg，关闭时取该报文覆盖（缺省回退共享值）
        const eff = (msgKey, field) => {
          if (c.headerLink) return c[field];
          const ov = c.msgOverrides[msgKey] || {};
          return ov[field] !== undefined ? ov[field] : c[field];
        };
        // 可编辑行的 model：联动开启→共享键；关闭→"ov:报文:字段"（get/set 解析）
        const hf = (msgKey, field) => (c.headerLink ? field : "ov:" + msgKey + ":" + field);
        const hexCi = (v) => (String(v || "").trim().replace(/[^0-9a-fA-F]/g, "").toLowerCase()) || "auto";
        // Ethernet II（含可选 802.1Q）头部行
        const ethernetRows = (msgKey) => {
          const rows = [
            { name: "Ethernet II", type: "grp" },
            RO("Source", srcMac),
            ED("Destination", hf(msgKey, "dstMac"), "", "220px"),
          ];
          const v = eff(msgKey, "vlanId");
          if (v !== null && v !== "" && v !== undefined) {
            rows.push({ name: "802.1Q Virtual LAN", type: "grp" });
            rows.push({ bits: "...0 0000 0000 ....", name: "PRI", model: hf(msgKey, "vlanPcp"), width: "110px" });
            rows.push(RO("CFI", 0, ".... .... .... 1111"));
            rows.push({ bits: ".... .... 1111 1111", name: "ID", model: hf(msgKey, "vlanId"), width: "110px" });
          }
          rows.push(RO("Type", "0x88f7 (PTP over Ethernet)"));
          rows.push({ name: "Precision Time Protocol (IEEE1588)", type: "grp" });
          return rows;
        };
        // 公共 PTP 头行，字段顺序与 Wireshark「Precision Time Protocol」树完全一致
        const header = (opts) => {
          const ts = N(eff(opts.msgKey, "transportSpecific"));
          const b0 = ((ts & 0xf) << 4) | (opts.mt & 0xf);
          return [
            { bits: nibPattern(b0, "hi"), name: "majorSdoId", model: hf(opts.msgKey, "transportSpecific"), width: "130px" },
            RO("messageType", mtName(opts.mt) + " (0x" + (opts.mt & 0xf).toString(16) + ")", nibPattern(b0, "lo")),
            RO("minorVersionPTP", 0, "0000 ...."),
            RO("versionPTP", 2, ".... 0010"),
            RO("messageLength", opts.len),
            ED("domainNumber", hf(opts.msgKey, "domainNumber"), "", "130px"),
            RO("minorSdoId", 0),
            RO("flags", flagHex(opts.flags)),
          ]
            .concat(flagRows(opts.flags, opts.flagsField))
            .concat([
              RO("correctionField", "0.000000 nanoseconds"),
              RO("messageTypeSpecific", 0),
              ED("ClockIdentity", hf(opts.msgKey, "clockIdentity"), "", "220px"),
              ED("SourcePortID", hf(opts.msgKey, "portNumber"), "", "130px"),
              RO("sequenceId", "（发送时自增）"),
              RO("controlField", MASTER_CONTROL_NAMES[opts.ctrl] || String(opts.ctrl)),
            ])
            .concat(
              opts.logModel
                ? [
                    ED("logMessageInterval", opts.logModel, "", "130px"),
                    { type: "note", display: masterLogInterval(c[opts.logModel]), depth: 1 },
                  ]
                : [RO("logMessageInterval", opts.logDisplay)]
            );
        };

        const announce = {
          title: "Announce（0xb）· 64 bytes",
          name: "announce",
          rows: ethernetRows("announce")
            .concat(header({ msgKey: "announce", mt: 0xb, ctrl: 5, logModel: "logAnnounceInterval", flags: c.announceFlags, flagsField: "announceFlags", len: 64 }))
            .concat([
              RO("originTimestamp (seconds)", "（发送时填充）"),
              RO("originTimestamp (nanoseconds)", ""),
              ED("originCurrentUTCOffset", "currentUtcOffset", "", "130px"),
              RO("reserved", "00"),
              ED("priority1", "priority1", "", "130px"),
              ED("grandmasterClockClass", "clockClass", "", "130px"),
              ED("grandmasterClockAccuracy", "clockAccuracy", "", "130px"),
              { type: "note", display: masterAccuracyName(c.clockAccuracy), depth: 1 },
              ED("grandmasterClockVariance", "offsetScaledLogVariance", "", "150px"),
              ED("priority2", "priority2", "", "130px"),
              RO("grandmasterClockIdentity", "0x" + hexCi(eff("announce", "clockIdentity"))),
              RO("localStepsRemoved", 0),
              ED("TimeSource", "timeSource", "", "130px"),
              { type: "note", display: masterTimeSourceName(c.timeSource), depth: 1 },
            ]),
        };
        const sync = {
          title: "Sync（0x0）· 44 bytes",
          name: "sync",
          rows: ethernetRows("sync")
            .concat(
              header({ msgKey: "sync", mt: 0x0, ctrl: 0, logModel: "logSyncInterval", flags: c.syncFlags, flagsField: "syncFlags", len: 44 })
            )
            .concat([
              RO("originTimestamp (seconds)", "t1（发送时填充）"),
              RO("originTimestamp (nanoseconds)", ""),
            ]),
        };
        const followup = {
          title: "Follow_Up（0x8）· 44 bytes",
          name: "followup",
          rows: ethernetRows("followup")
            .concat(header({ msgKey: "followup", mt: 0x8, ctrl: 2, logModel: "logSyncInterval", flags: c.followUpFlags, flagsField: "followUpFlags", len: 44 }))
            .concat([
              RO("preciseOriginTimestamp (seconds)", "t1 精确值（发送时填充）"),
              RO("preciseOriginTimestamp (nanoseconds)", ""),
            ]),
        };
        const delayresp = {
          title: "Delay_Resp（0x9）· 54 bytes",
          name: "delayresp",
          rows: ethernetRows("delayresp")
            .concat(
              header({ msgKey: "delayresp", mt: 0x9, ctrl: 3, logDisplay: "0x7f (N/A)", flags: c.delayRespFlags, flagsField: "delayRespFlags", len: 54 })
            )
            .concat([
              RO("receiveTimestamp (seconds)", "t2（收到 Delay_Req 时填充）"),
              RO("receiveTimestamp (nanoseconds)", ""),
              RO("requestingPortIdentity.clockIdentity", "（回显 Slave）"),
              RO("requestingPortIdentity.portNumber", ""),
            ]),
        };
        return [announce, sync, followup, delayresp];
      },
      masterStatRows() {
        const s = this.master.stats;
        if (!s) return [];
        const labels = [
          ["announce_sent", "Announce TX"], ["sync_sent", "Sync TX"], ["follow_up_sent", "Follow_Up TX"],
          ["delay_req_recv", "Delay_Req RX"], ["delay_resp_sent", "Delay_Resp TX"],
          ["delay_resp_dropped", "Resp 丢弃", true], ["tx_errors", "TX 错误", true],
          ["rx_other_domain", "异域丢弃", false], ["rx_parse_errors", "解析错误", true],
          ["session_overflow", "会话溢出", true], ["resp_queue_full", "队列满", true],
        ];
        return labels.map(([k, label, bad]) => ({ label, value: s[k] || 0, bad: !!bad && (s[k] || 0) > 0 }));
      },
      /* 报文列表只渲染最近 200 条，避免 DOM 节点过多导致卡顿 */
      masterVisibleMessages() {
        const msgs = this.master.messages;
        return msgs.length > 200 ? msgs.slice(-200) : msgs;
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
      /* 将扁平字段行按 TLV 分组（group 行收集后续 depth-1 子行） */
      sigTree() {
        const items = [];
        for (const r of this.ptp.sig.rows) {
          if (r.group) items.push({ row: r, children: [] });
          else if (r.depth > 0 && items.length && items[items.length - 1].children)
            items[items.length - 1].children.push(r);
          else items.push({ row: r, children: null });
        }
        return items;
      },
      /* Signaling 构造表单：flags 的 Wireshark 位展开 */
      sigBuildFlagBits() {
        const flags = parseHexInt(this.ptp.sigBuild.flags) || 0;
        return PTP_FLAG_BITS.map((fb) => ({
          bit: fb.bit,
          name: fb.name,
          bits: bitPattern(fb.bit, (flags >> fb.bit) & 1),
          on: !!((flags >> fb.bit) & 1),
        }));
      },
      sigTlvTitle() {
        return TLV_NAMES[Number(this.ptp.sigBuild.tlv_type)] || "TLV";
      },
      /* 构造表单：nibble 位掩码前缀（随输入实时变化） */
      sigBuildBits() {
        const s = this.ptp.sigBuild;
        const b0 = ((Number(s.major_sdo_id) & 0xf) << 4) | (Number(s.message_type) & 0xf);
        const b1 = ((Number(s.minor_version_ptp) & 0xf) << 4) | (Number(s.version_ptp) & 0xf);
        const tb = (Number(s.tlv_message_type) & 0xf) << 4;
        return {
          majorSdoId: nibPattern(b0, "hi"),
          messageType: nibPattern(b0, "lo"),
          minorVersionPTP: nibPattern(b1, "hi"),
          versionPTP: nibPattern(b1, "lo"),
          tlvMessageType: nibPattern(tb, "hi"),
        };
      },
      /* correctionField 的 Wireshark 子行（整数 ns / 小数 subNs） */
      sigBuildCorrection() {
        const ns = Number(this.ptp.sigBuild.correction_field_ns) || 0;
        const raw = BigInt(Math.round(ns * 65536));
        return {
          display: ns.toFixed(6) + " nanoseconds",
          ns: Math.trunc(ns) + " nanoseconds",
          subNs: (Number(raw & 0xffffn) / 65536).toFixed(6) + " nanoseconds",
        };
      },
      /* messageLength / TLV lengthField 为派生只读值 */
      sigBuildTlvValueLen() {
        const t = Number(this.ptp.sigBuild.tlv_type);
        return t === 5 ? 8 : t === 6 || t === 7 ? 2 : 6;
      },
      sigBuildMessageLength() {
        return 34 + 10 + 4 + this.sigBuildTlvValueLen;
      },

      /* ---------------- Delay_Req 构造表单派生值 ---------------- */
      drBuildFlagBits() {
        const flags = parseHexInt(this.ptp.drBuild.flags) || 0;
        return PTP_FLAG_BITS.map((fb) => ({
          bit: fb.bit,
          name: fb.name,
          bits: bitPattern(fb.bit, (flags >> fb.bit) & 1),
          on: !!((flags >> fb.bit) & 1),
        }));
      },
      drBuildBits() {
        const b1 = Number(this.ptp.drBuild.version_ptp) & 0xf;
        return { versionPTP: nibPattern(b1, "lo") };
      },
      drBuildCorrection() {
        const ns = Number(this.ptp.drBuild.correction_field_ns) || 0;
        const raw = BigInt(Math.round(ns * 65536));
        return {
          ns: Math.trunc(ns) + " nanoseconds",
          subNs: (Number(raw & 0xffffn) / 65536).toFixed(6) + " nanoseconds",
        };
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
      buildPtpAcrBody() {
        const t = this.ptp;
        const sig = t.sigBuild;
        const dr = t.drBuild;
        const bind = String(t.bind || "").trim();
        // 发包率：Delay_Req 的 logMessageInterval → 2^n 秒
        const logInt = Number(dr.log_message_interval) || 0;
        const interval = Math.pow(2, Math.max(-7, Math.min(7, logInt)));
        const body = {
          master: String(t.master || "").trim(),
          domain: Number(dr.domain_number) || 0,
          clock_identity: String(dr.clock_identity || "").trim(),
          port_number: Number(dr.source_port_id) || 0,
          announce_log: 0,
          sync_log: Number(sig.log_inter_message_period) || 0,
          duration_sec: Number(sig.duration_sec) || 0,
          sync_timeout: 8,
          delay_timeout: 8,
          measure_duration_sec: null,
          delay_request: {
            flags: parseHexInt(dr.flags) & 0xffff,
            // 表单值按 ns 解释，与预览组包一致：线上 int64 = ns * 2^16
            correction_field_ns: Math.round((Number(dr.correction_field_ns) || 0) * 65536),
            origin_timestamp: {
              seconds: Number(dr.origin_sec) || 0,
              nanoseconds: Number(dr.origin_ns) || 0,
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
        if (c.bind) t.bind = c.bind;
        const dr = t.drBuild;
        const sig = t.sigBuild;
        if (c.domain !== undefined) dr.domain_number = c.domain;
        if (c.clock_identity) dr.clock_identity = c.clock_identity;
        if (c.port_number !== undefined) dr.source_port_id = c.port_number;
        if (c.sync_log !== undefined) sig.log_inter_message_period = c.sync_log;
        if (c.duration_sec !== undefined) sig.duration_sec = c.duration_sec;
        const drc = c.delay_request || {};
        if (drc.flags !== undefined) dr.flags = "0x" + Number(drc.flags).toString(16);
        if (drc.correction_field_ns !== undefined) dr.correction_field_ns = Number(drc.correction_field_ns) / 65536;
        const ot = drc.origin_timestamp || {};
        if (ot.seconds !== undefined) dr.origin_sec = ot.seconds;
        if (ot.nanoseconds !== undefined) dr.origin_ns = ot.nanoseconds;
        const iv = drc.request_interval_sec ?? drc.requestIntervalSec;
        if (iv !== undefined && iv !== null && iv > 0) dr.log_message_interval = Math.round(Math.log2(iv));
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
        this.buildSigTree(row);
      },

      /* ---- Wireshark 风格 Signaling 字段树 ---- */
      isSignaling(rec) {
        return !!(rec && rec.summary && rec.summary.message_type_name === "SIGNALING");
      },

      buildSigTree(row) {
        sigBytes = null;
        if (!this.isSignaling(row)) {
          this.ptp.sig.rows = [];
          this.ptp.sig.collapse = ["sig"];
          return;
        }
        sigBytes = hexToBytes(row.udp_hex);
        if (sigBytes.length < 44) {
          this.ptp.sig.rows = [];
          this.ptp.sig.collapse = ["sig"];
          return;
        }
        this.refreshSigTree(true);
      },

      refreshSigTree(openAll) {
        const rows = parseSignalingTree(sigBytes);
        this.ptp.sig.rows = rows;
        if (openAll) {
          const open = ["sig"];
          for (const r of rows) if (r.group) open.push(r.gname);
          this.ptp.sig.collapse = open;
        } else {
          const groups = new Set(rows.filter((r) => r.group).map((r) => r.gname));
          this.ptp.sig.collapse = this.ptp.sig.collapse.filter((n) => n === "sig" || groups.has(n));
          if (!this.ptp.sig.collapse.includes("sig")) this.ptp.sig.collapse = ["sig", ...this.ptp.sig.collapse];
        }
      },

      onSigFieldEdit(row, value) {
        if (!sigBytes || !row.edit) return;
        if (!applySigEdit(sigBytes, row.edit, value)) {
          this.setPtpStatus("字段 “" + row.name + "” 输入无效，未修改", "err");
          return;
        }
        // 同步 hex 显示与结构体
        const hex = Array.from(sigBytes, (b) => b.toString(16).padStart(2, "0")).join("");
        if (this.ptp.selected) this.ptp.selected.udp_hex = hex;
        this.refreshSigTree(false);
        this.setPtpStatus("已修改字段 “" + row.name + "”（仅影响本地显示，不会重发）", "ok");
      },

      resetSigTree() {
        sigBytes = null;
        this.ptp.sig.rows = [];
        this.ptp.sig.collapse = [];
      },

      resetPtpMessageList() {
        this.ptp.messages = [];
        this.ptp.nextIndex = 0;
        this.ptp.autoScroll = true;
        this.ptp.selected = null;
        this.ptp.stats = {};
        this.ptp.gm = "";
        this.resetSigTree();
      },

      applyPtpPollResult(data) {
        if (Array.isArray(data.messages) && data.messages.length) {
          this.ptp.messages = this.ptp.messages.concat(data.messages);
          if (this.ptp.messages.length > PTP_MAX_ROWS) {
            this.ptp.messages = this.ptp.messages.slice(-PTP_MAX_ROWS);
          }
          if (this.ptp.autoScroll) {
            this.$nextTick(() => {
              const tbl = this.$refs.msgTable || this.$refs.faultMsgTable;
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

      async buildPtpDelayReq() {
        this.ptp.drBuilding = true;
        this.setPtpStatus("构建 Delay_Req 报文中…", "");
        try {
          const r = await fetch("/api/ptp/delay_req/build", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(this.buildDrSpec()),
          });
          const data = await r.json().catch(() => ({}));
          if (!r.ok) {
            const detail = data.detail || data.message || r.statusText;
            this.setPtpStatus("错误 " + r.status + ": " + (typeof detail === "string" ? detail : JSON.stringify(detail)), "err");
            return;
          }
          this.ptp.drHex = data.udp_hex || "";
          this.ptp.drFrameHex = data.frame_hex || "";
          this.ptp.drJson = JSON.stringify(data.packet, null, 2);
          this.setPtpStatus("Delay_Req 报文构造完成", "ok");
        } catch (e) {
          this.setPtpStatus(String(e), "err");
        } finally {
          this.ptp.drBuilding = false;
        }
      },

      /* Delay_Req 报文构造：字段顺序与 Wireshark 一致 */
      buildDrSpec() {
        const s = this.ptp.drBuild;
        return {
          version_ptp: Number(s.version_ptp) & 0xf,
          domain_number: Number(s.domain_number) & 0xff,
          minor_sdo_id: Number(s.minor_sdo_id) & 0xf,
          flags: parseHexInt(s.flags) & 0xffff,
          correction_field_ns: Number(s.correction_field_ns) || 0,
          clock_identity: String(s.clock_identity || "").trim(),
          source_port_id: Number(s.source_port_id) || 0,
          sequence_id: Number(s.sequence_id) || 0,
          control_field: Number(s.control_field) || 0,
          log_message_interval: Number(s.log_message_interval),
          origin_sec: Number(s.origin_sec) || 0,
          origin_ns: Number(s.origin_ns) || 0,
          master_ip: String(s.master_ip || "").trim(),
          client_ip: String(s.client_ip || "").trim(),
          src_port: Number(s.src_port) || 319,
          dst_port: Number(s.dst_port) || 319,
        };
      },

      /* Signaling 报文构造：字段顺序与 Wireshark 完全一致 */
      buildSigSpec() {
        const s = this.ptp.sigBuild;
        return {
          major_sdo_id: Number(s.major_sdo_id) & 0xf,
          message_type: Number(s.message_type) & 0xf,
          minor_version_ptp: Number(s.minor_version_ptp) & 0xf,
          version_ptp: Number(s.version_ptp) & 0xf,
          domain_number: Number(s.domain_number) & 0xff,
          minor_sdo_id: Number(s.minor_sdo_id) & 0xf,
          flags: parseHexInt(s.flags) & 0xffff,
          correction_field_ns: Number(s.correction_field_ns) || 0,
          message_type_specific: Number(s.message_type_specific) || 0,
          clock_identity: String(s.clock_identity || "").trim(),
          source_port_id: Number(s.source_port_id) || 0,
          sequence_id: Number(s.sequence_id) || 0,
          control_field: Number(s.control_field) || 0,
          log_message_interval: Number(s.log_message_interval),
          target_clock_identity: String(s.target_clock_identity || "").trim(),
          target_port_id: Number(s.target_port_id) || 0,
          tlv_type: parseHexInt(s.tlv_type) & 0xffff,
          tlv_message_type: Number(s.tlv_message_type) & 0xf,
          log_inter_message_period: Number(s.log_inter_message_period),
          duration_sec: Number(s.duration_sec) || 0,
          master_ip: String(s.master_ip || "").trim(),
          client_ip: String(s.client_ip || "").trim(),
          src_port: Number(s.src_port) || 320,
          dst_port: Number(s.dst_port) || 320,
        };
      },

      async buildPtpSignaling() {
        this.ptp.sigBuilding = true;
        this.setPtpStatus("构建 Signaling 报文中…", "");
        try {
          const r = await fetch("/api/ptp/signaling/build", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(this.buildSigSpec()),
          });
          const data = await r.json().catch(() => ({}));
          if (!r.ok) {
            const detail = data.detail || data.message || r.statusText;
            this.setPtpStatus("错误 " + r.status + ": " + (typeof detail === "string" ? detail : JSON.stringify(detail)), "err");
            return;
          }
          this.ptp.sigHex = data.udp_hex || "";
          this.ptp.sigFrameHex = data.frame_hex || "";
          this.ptp.sigJson = JSON.stringify(data.packet, null, 2);
          this.setPtpStatus("Signaling 报文构造完成", "ok");
        } catch (e) {
          this.setPtpStatus(String(e), "err");
        } finally {
          this.ptp.sigBuilding = false;
        }
      },

      // flags 位勾选：改回写十六进制字符串
      toggleSigFlag(bit, on) {
        let flags = parseHexInt(this.ptp.sigBuild.flags) || 0;
        flags = on ? flags | (1 << bit) : flags & ~(1 << bit);
        this.ptp.sigBuild.flags = "0x" + (flags & 0xffff).toString(16).padStart(4, "0");
      },

      toggleDrFlag(bit, on) {
        let flags = parseHexInt(this.ptp.drBuild.flags) || 0;
        flags = on ? flags | (1 << bit) : flags & ~(1 << bit);
        this.ptp.drBuild.flags = "0x" + (flags & 0xffff).toString(16).padStart(4, "0");
      },

      async runPtpAcr() {
        const hint = "持续运行直到点击停止";
        this.setPtpStatus("启动 G8275 ATR（" + hint + "）…", "");
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

      /* 故障模式一：不建链发送 Delay_Req（参数取自 Delay_Req 组包表单） */
      buildFaultBody() {
        const t = this.ptp;
        const dr = t.drBuild;
        const bind = String(t.bind || "").trim();
        const body = {
          master: String(t.master || "").trim(),
          domain: Number(dr.domain_number) || 0,
          clock_identity: String(dr.clock_identity || "").trim(),
          port_number: Number(dr.source_port_id) || 0,
          delay_request_interval_sec: Number(t.fault.interval) || 1,
          delay_request: {
            version_ptp: Number(dr.version_ptp) & 0xf,
            minor_sdo_id: Number(dr.minor_sdo_id) & 0xf,
            flags: parseHexInt(dr.flags) & 0xffff,
            correction_field_ns: Math.round((Number(dr.correction_field_ns) || 0) * 65536),
            sequence_id: Number(dr.sequence_id) || 0,
            control_field: Number(dr.control_field) || 0,
            log_message_interval: Number(dr.log_message_interval),
            origin_timestamp: {
              seconds: Number(dr.origin_sec) || 0,
              nanoseconds: Number(dr.origin_ns) || 0,
            },
          },
        };
        if (bind) body.bind = bind;
        return body;
      },

      async runPtpFault() {
        this.setPtpStatus("启动故障模式：不建链发送 Delay_Req…", "");
        this.ptp.starting = true;
        this.ptp.result.lastPcap = null;
        this.ptp.result.pcapPreview = "";
        this.resetPtpMessageList();
        try {
          const r = await fetch("/api/ptp/fault/delay-req/start", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(this.buildFaultBody()),
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
          this.setPtpStatus("故障模式运行中，每 " + PTP_POLL_MS + " ms 刷新报文…", "ok");
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

      /* ================= L2 Master（G.8275.1 / 1588v2） ================= */

      setMasterStatus(msg, kind) {
        this.master.status = { msg: msg || "", kind: kind || "" };
      },

      async loadMasterInterfaces() {
        try {
          const r = await fetch("/api/ptp/l2-master/interfaces");
          if (r.ok) {
            const data = await r.json().catch(() => ({ interfaces: [] }));
            this.master.interfaces = (data.interfaces || []).filter((i) => i.name);
            if (!this.master.cfg.interface && this.master.interfaces.length) {
              // 默认选 Hyper-V Virtual Ethernet Adapter（联调网卡），否则第一项
              const pref = this.master.interfaces.find((i) =>
                /hyper-v/i.test(i.description || i.name || ""));
              this.master.cfg.interface = (pref || this.master.interfaces[0]).name;
            }
          }
        } catch (e) {
          /* Npcap 缺失等：用户仍可手动输入网卡名 */
        }
      },

      onMasterProfileChange(profile) {
        const c = this.master.cfg;
        if (profile === "g82751") {
          c.domainNumber = 43;
          c.logAnnounceInterval = -3;
          c.logSyncInterval = -4;
        } else {
          c.domainNumber = 0;
          c.logAnnounceInterval = 0;
          c.logSyncInterval = 0;
        }
      },

      /* Wireshark 树字段的读取 / 写回（可编辑行以 model=cfg 键名标识；
         "ov:报文:字段" 表示联动关闭时该报文的独立覆盖值） */
      getMasterField(key) {
        let v;
        if (key.startsWith("ov:")) {
          const [, msg, field] = key.split(":");
          const ov = this.master.cfg.msgOverrides[msg] || {};
          v = ov[field] !== undefined ? ov[field] : this.master.cfg[field];
        } else {
          v = this.master.cfg[key];
        }
        return v === null || v === undefined ? "" : String(v);
      },
      /* sig-field 提交：把编辑后的值写回 cfg（仅失焦/回车时触发，避免高频重算） */
      onMasterFieldEdit(row, text) {
        this.setMasterField(row.model, text);
      },
      setMasterField(key, text) {
        const c = this.master.cfg;
        let target = c;
        if (key.startsWith("ov:")) {
          const [, msg, field] = key.split(":");
          if (!c.msgOverrides[msg]) c.msgOverrides[msg] = {};
          target = c.msgOverrides[msg];
          key = field;
        }
        const t = String(text == null ? "" : text).trim();
        if (key === "clockIdentity") {
          target.clockIdentity = t.replace(/[^0-9a-fA-F]/g, "").toLowerCase();
          return;
        }
        if (key === "dstMac") {
          target.dstMac = t;
          return;
        }
        if (key === "vlanId") {
          if (t === "") {
            target.vlanId = null;
            return;
          }
          const n = Number(t);
          target.vlanId = Number.isFinite(n) ? Math.trunc(n) : t;
          return;
        }
        if (t === "") {
          target[key] = "";
          return;
        }
        const n = Number(t);
        target[key] = Number.isFinite(n) ? Math.trunc(n) : t;
      },
      /* 启动前对 Wireshark 树里的可编辑字段做范围校验，返回错误信息或 null */
      validateMasterFields() {
        const c = this.master.cfg;
        const range = {
          domainNumber: [0, 255, "domainNumber"],
          portNumber: [1, 65535, "SourcePortID"],
          transportSpecific: [0, 15, "majorSdoId/transportSpecific"],
          vlanPcp: [0, 7, "VLAN PRI"],
          currentUtcOffset: [0, 65535, "originCurrentUTCOffset"],
          priority1: [0, 255, "priority1"],
          priority2: [0, 255, "priority2"],
          clockClass: [0, 255, "grandmasterClockClass"],
          clockAccuracy: [0, 255, "grandmasterClockAccuracy"],
          offsetScaledLogVariance: [0, 65535, "grandmasterClockVariance"],
          timeSource: [0, 255, "TimeSource"],
          logAnnounceInterval: [-128, 127, "Announce logMessageInterval"],
          logSyncInterval: [-128, 127, "Sync logMessageInterval"],
        };
        const ci = String(c.clockIdentity || "").trim();
        if (ci && !/^[0-9a-fA-F]{1,16}$/.test(ci)) return "clockIdentity 必须是 1-16 个十六进制字符（或留空由网卡派生）";
        if (c.vlanId !== null && c.vlanId !== "" && !(Number.isInteger(Number(c.vlanId)) && Number(c.vlanId) >= 1 && Number(c.vlanId) <= 4095)) {
          return "VLAN ID 必须为 1-4095 的整数（留空表示不打 VLAN tag）";
        }
        for (const [k, [lo, hi, label]] of Object.entries(range)) {
          const v = c[k];
          if (v === "" || v === null || v === undefined) return label + " 不能为空";
          const n = Number(v);
          if (!Number.isFinite(n) || n < lo || n > hi) return label + " 超出范围 " + lo + ".." + hi;
        }
        // 联动关闭时逐报文校验独立覆盖值（仅校验显式设置的字段）
        if (!c.headerLink) {
          const ovRange = {
            domainNumber: [0, 255, "domainNumber"],
            portNumber: [1, 65535, "SourcePortID"],
            transportSpecific: [0, 15, "majorSdoId/transportSpecific"],
            vlanPcp: [0, 7, "VLAN PRI"],
          };
          for (const [msg, ov] of Object.entries(c.msgOverrides)) {
            for (const [k, [lo, hi, label]] of Object.entries(ovRange)) {
              if (ov[k] === undefined) continue;
              const v = ov[k];
              if (v === "" || v === null) return msg + " " + label + " 不能为空";
              const n = Number(v);
              if (!Number.isFinite(n) || n < lo || n > hi) return msg + " " + label + " 超出范围 " + lo + ".." + hi;
            }
            if (ov.vlanId !== undefined && ov.vlanId !== null && ov.vlanId !== "") {
              if (!(Number.isInteger(Number(ov.vlanId)) && Number(ov.vlanId) >= 1 && Number(ov.vlanId) <= 4095))
                return msg + " VLAN ID 必须为 1-4095（留空表示不打 tag）";
            }
            if (ov.clockIdentity !== undefined && ov.clockIdentity !== ""
              && !/^[0-9a-fA-F]{1,16}$/.test(String(ov.clockIdentity).trim()))
              return msg + " clockIdentity 必须是 1-16 个十六进制字符";
          }
        }
        return null;
      },
      toggleMasterFlag(field, bit) {
        if (!field || typeof bit !== "number") return;
        const cur = Number(this.master.cfg[field]) || 0;
        this.master.cfg[field] = (cur ^ (1 << bit)) & 0xffff;
      },

      /* 报文字段（运行期可改）→ 请求体；网卡 / 协议子项不在此列 */
      buildMasterPatch() {
        const c = this.master.cfg;
        const body = {
          domainNumber: Number(c.domainNumber),
          portNumber: Number(c.portNumber) || 1,
          priority1: Number(c.priority1),
          priority2: Number(c.priority2),
          clockClass: Number(c.clockClass),
          clockAccuracy: Number(c.clockAccuracy),
          offsetScaledLogVariance: Number(c.offsetScaledLogVariance),
          timeSource: Number(c.timeSource),
          currentUtcOffset: Number(c.currentUtcOffset),
          logAnnounceInterval: Number(c.logAnnounceInterval),
          logSyncInterval: Number(c.logSyncInterval),
          transportSpecific: Number(c.transportSpecific),
          vlanPcp: Number(c.vlanPcp),
          // flagField 原值（16 bit）；twoStep / delayRespUnicast 由语义位派生
          announceFlags: Number(c.announceFlags) & 0xffff,
          syncFlags: Number(c.syncFlags) & 0xffff,
          followUpFlags: Number(c.followUpFlags) & 0xffff,
          delayRespFlags: Number(c.delayRespFlags) & 0xffff,
          twoStep: !!((Number(c.syncFlags) >> 9) & 1),
          delayRespUnicast: !!((Number(c.delayRespFlags) >> 10) & 1),
          headerLink: !!c.headerLink,
        };
        // 联动关闭时下发逐报文覆盖（仅显式设置的字段）
        if (!c.headerLink) {
          const ovOut = {};
          for (const [msg, ov] of Object.entries(c.msgOverrides)) {
            const one = {};
            if (ov.domainNumber !== undefined) one.domainNumber = Number(ov.domainNumber);
            if (ov.portNumber !== undefined) one.portNumber = Number(ov.portNumber);
            if (ov.transportSpecific !== undefined) one.transportSpecific = Number(ov.transportSpecific);
            if (ov.vlanPcp !== undefined) one.vlanPcp = Number(ov.vlanPcp);
            if (ov.vlanId !== undefined) one.vlanId = ov.vlanId === null || ov.vlanId === "" ? null : Number(ov.vlanId);
            if (ov.clockIdentity !== undefined && String(ov.clockIdentity).trim()) one.clockIdentity = String(ov.clockIdentity).trim();
            if (ov.dstMac !== undefined && String(ov.dstMac).trim()) one.dstMac = String(ov.dstMac).trim();
            if (Object.keys(one).length) ovOut[msg] = one;
          }
          body.messageOverrides = ovOut;
        }
        const ci = String(c.clockIdentity || "").trim();
        if (ci) body.clockIdentity = ci;
        const mac = String(c.dstMac || "").trim();
        if (mac) body.dstMac = mac;
        // vlanId 始终显式携带：null 表示运行期取消 VLAN tag
        body.vlanId = c.vlanId === null || c.vlanId === "" || Number.isNaN(Number(c.vlanId)) ? null : Number(c.vlanId);
        return body;
      },

      async applyMasterChanges() {
        const invalid = this.validateMasterFields();
        if (invalid) {
          this.setMasterStatus("字段校验失败：" + invalid, "err");
          return;
        }
        this.master.applying = true;
        try {
          const r = await fetch("/api/ptp/l2-master/update", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(this.buildMasterPatch()),
          });
          const data = await r.json().catch(() => ({}));
          if (!r.ok) {
            const detail = data.detail || r.statusText;
            this.setMasterStatus("应用失败 " + r.status + ": " + (typeof detail === "string" ? detail : JSON.stringify(detail)), "err");
            return;
          }
          this.setMasterStatus("报文字段已应用，下一个报文即生效", "ok");
        } catch (e) {
          this.setMasterStatus("应用异常: " + e, "err");
        } finally {
          this.master.applying = false;
        }
      },

      buildMasterBody() {
        const c = this.master.cfg;
        const body = Object.assign(
          {
            interface: String(c.interface || "").trim(),
            profile: c.profile,
          },
          this.buildMasterPatch()
        );
        if (body.vlanId === null) delete body.vlanId;
        return body;
      },

      async runMaster() {
        if (!String(this.master.cfg.interface || "").trim()) {
          this.setMasterStatus("请先选择或输入网卡接口", "err");
          return;
        }
        const invalid = this.validateMasterFields();
        if (invalid) {
          this.setMasterStatus("字段校验失败：" + invalid, "err");
          return;
        }
        this.setMasterStatus("启动 L2 Master…", "");
        this.master.starting = true;
        this.resetMasterMessages();
        try {
          const r = await fetch("/api/ptp/l2-master/start", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(this.buildMasterBody()),
          });
          const data = await r.json().catch(() => ({}));
          if (!r.ok) {
            const detail = data.detail || r.statusText;
            this.setMasterStatus("错误 " + r.status + ": " + (typeof detail === "string" ? detail : JSON.stringify(detail)), "err");
            return;
          }
          this.master.runId = data.run_id;
          this.master.running = true;
          this.master.srcMac = data.src_mac || "";
          this.setMasterStatus(
            "Master 运行中（" + (data.config.profile || "") + "，源 MAC " + (data.src_mac || "?") + "），SSE 实时推送",
            "ok"
          );
          this.startMasterEventStream();
        } catch (e) {
          this.setMasterStatus(String(e), "err");
        } finally {
          this.master.starting = false;
        }
      },

      async stopMaster() {
        this.setMasterStatus("正在停止 Master…", "");
        try {
          const r = await fetch("/api/ptp/l2-master/stop", { method: "POST" });
          if (!r.ok) {
            const data = await r.json().catch(() => ({}));
            this.setMasterStatus("停止失败 " + r.status + ": " + (data.detail || r.statusText), "err");
            return;
          }
          this.finishMasterRun();
          this.setMasterStatus("Master 已停止", "ok");
        } catch (e) {
          this.setMasterStatus("停止异常: " + e, "err");
        }
      },

      /* ---- SSE 观察者模式：服务端推送帧与统计，替代 500ms 轮询 ---- */
      startMasterEventStream() {
        this.stopMasterEventStream();
        if (typeof EventSource === "undefined") {
          this.setMasterStatus("浏览器不支持 SSE，回退轮询", "err");
          return;
        }
        const es = new EventSource("/api/ptp/l2-master/events");
        this.master.eventSource = es;

        es.addEventListener("stats", (ev) => {
          try {
            const data = JSON.parse(ev.data);
            this.applyMasterStats(data);
          } catch (e) { /* ignore malformed payload */ }
        });

        es.addEventListener("frame", (ev) => {
          try {
            const frame = JSON.parse(ev.data);
            this.bufferMasterFrame(frame);
          } catch (e) { /* ignore malformed payload */ }
        });

        es.addEventListener("stopped", () => {
          this.finishMasterRun();
          this.setMasterStatus("Master 已停止", "ok");
        });

        es.onerror = () => {
          // EventSource auto-reconnects; only surface when the run is over.
          if (!this.master.running) {
            this.stopMasterEventStream();
          }
        };
      },

      stopMasterEventStream() {
        if (this.master.frameFlushTimer) {
          clearTimeout(this.master.frameFlushTimer);
          this.master.frameFlushTimer = null;
        }
        this.master.frameBuffer = [];
        if (this.master.eventSource) {
          try { this.master.eventSource.close(); } catch (e) { /* noop */ }
          this.master.eventSource = null;
        }
      },

      /* ---- SSE 帧批量缓冲：100ms 内的帧合并为一次 DOM 更新 ---- */
      bufferMasterFrame(frame) {
        this.master.frameBuffer.push(frame);
        if (this.master.frameFlushTimer) return;
        this.master.frameFlushTimer = setTimeout(() => this.flushMasterFrameBuffer(), 100);
      },

      flushMasterFrameBuffer() {
        this.master.frameFlushTimer = null;
        const buf = this.master.frameBuffer;
        if (!buf.length) return;
        this.master.frameBuffer = [];
        const msgs = this.master.messages;
        for (const f of buf) {
          msgs.push(f);
          if (typeof f.index === "number") this.master.nextIndex = f.index + 1;
        }
        if (msgs.length > PTP_MAX_ROWS) {
          msgs.splice(0, msgs.length - PTP_MAX_ROWS);
        }
        if (this.master.autoScroll) {
          this.$nextTick(() => {
            const tbl = this.$refs.masterMsgTable;
            if (tbl) tbl.setScrollTop(999999);
          });
        }
      },

      applyMasterStats(data) {
        if (data.stats) this.master.stats = data.stats;
        if (Array.isArray(data.slaves)) this.master.slaves = data.slaves;
      },

      resetMasterMessages() {
        this.master.messages = [];
        this.master.nextIndex = 0;
        this.master.autoScroll = true;
        this.master.selected = null;
        this.master.slaves = [];
        this.master.stats = null;
      },

      finishMasterRun() {
        this.stopMasterEventStream();
        this.master.runId = null;
        this.master.running = false;
      },

      onMasterRowClick(row) {
        this.master.autoScroll = false;
        this.master.selected = row;
      },

      masterMsgInfo(rec) {
        const s = rec.summary || {};
        const seq = s.sequence_id != null ? s.sequence_id : "-";
        const b = s.body || {};
        let extra = "";
        if (s.message_type_name === "ANNOUNCE" && b.grandmaster_identity) {
          extra = `GM=${b.grandmaster_identity} class=${b.grandmaster_clock_quality ? b.grandmaster_clock_quality.clock_class : "-"}`;
        } else if (b.origin_timestamp) {
          extra = `t=${b.origin_timestamp.seconds}.${String(b.origin_timestamp.nanoseconds).padStart(9, "0")}`;
        } else if (b.precise_origin_timestamp) {
          extra = `precise=${b.precise_origin_timestamp.seconds}`;
        } else if (b.receive_timestamp) {
          extra = `t2=${b.receive_timestamp.seconds}.${String(b.receive_timestamp.nanoseconds).padStart(9, "0")}`;
        }
        const peer = rec.peer_mac ? (rec.direction === "tx" ? "→ " : "← ") + rec.peer_mac : "";
        return `seq=${seq} ${extra} ${peer}`.trim();
      },
    },

    mounted() {
      this.loadMasterInterfaces();
    },

    beforeUnmount() {
      this.stopPtpPolling();
      this.stopMasterEventStream();
    },
  });

  // 构造表单行：label + 可选位掩码前缀 + 输入控件（text / select / 只读）
  app.component("sig-edit", {
    props: {
      label: String,
      bits: String,
      modelValue: null,
      type: { default: "text" },
      options: Array,
      depth: { default: 0 },
      width: { default: "220px" },
    },
    emits: ["update:modelValue"],
    template: `
      <div class="sig-row" :class="{ 'sig-row-sub': depth > 0 }">
        <span class="sig-bits" v-if="bits">{{ bits }}</span>
        <span class="sig-name">{{ label }}:</span>
        <el-select v-if="type === 'select'" :model-value="modelValue" size="small" :style="{ width: width }"
          @update:model-value="$emit('update:modelValue', $event)">
          <el-option v-for="o in options" :key="o.value" :label="o.label" :value="o.value"></el-option>
        </el-select>
        <span v-else-if="type === 'ro'" class="sig-val">{{ modelValue }}</span>
        <el-input v-else :model-value="modelValue" size="small" :style="{ width: width }"
          @update:model-value="$emit('update:modelValue', $event)"></el-input>
      </div>`,
  });

  // 可编辑字段行：点击值 → 输入框，回车/失焦提交，Esc 取消
  app.component("sig-field", {
    props: { row: Object },
    emits: ["edit"],
    data() {
      return { editing: false, text: "" };
    },
    methods: {
      start() {
        if (!this.row.edit) return;
        this.text = this.row.display == null ? "" : String(this.row.display);
        this.editing = true;
        this.$nextTick(() => {
          const inp = this.$refs.inp;
          if (inp) { inp.focus(); inp.select(); }
        });
      },
      commit() {
        if (!this.editing) return;
        this.editing = false;
        this.$emit("edit", this.row, this.text);
      },
      cancel() {
        this.editing = false;
      },
    },
    template: `
      <div class="sig-row" :class="{ 'sig-row-sub': row.depth > 0 }">
        <span class="sig-bits" v-if="row.bits">{{ row.bits }}</span>
        <span class="sig-name">{{ row.name }}:</span>
        <input v-if="row.edit && editing" ref="inp" class="sig-edit" v-model="text"
          @keyup.enter="commit" @keyup.esc="cancel" @blur="commit" />
        <span v-else class="sig-val" :class="{ 'sig-editable': !!row.edit }"
          :title="row.edit ? '点击修改' : ''" @click="start">{{ row.display }}</span>
      </div>`,
  });

  app.use(ElementPlus, { locale: ElementPlusLocaleZhCn });
  app.mount("#app");
})();
