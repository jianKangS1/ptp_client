/* Web「Master 模式」页前端按钮逻辑测试（node 沙箱，无需浏览器）。
 *
 * 加载真实的 src/ptp_client/web/static/main.js（桩掉 Vue/ElementPlus/fetch/
 * 定时器），取出 Vue 应用配置对象，在纯 JS 环境里驱动页面方法，验证：
 *   - 协议子项单选切换时的参数联动
 *   - 启动 / 停止按钮的 fetch 调用与状态机
 *   - 每一个表单字段经 buildMasterBody 的映射（用户修改 → 请求体）
 *   - 网卡列表加载与自动选择、轮询渲染、报文信息列
 */
"use strict";

const fs = require("fs");
const path = require("path");
const vm = require("vm");

const failures = [];
function check(name, cond) {
  console.log((cond ? "PASS" : "FAIL") + " - " + name);
  if (!cond) failures.push(name);
}
function eq(name, actual, expected) {
  const ok = JSON.stringify(actual) === JSON.stringify(expected);
  if (!ok) console.log(`       got=${JSON.stringify(actual)} want=${JSON.stringify(expected)}`);
  check(name, ok);
}
async function mustReject(name, p) {
  let threw = false;
  try {
    await p;
  } catch (e) {
    threw = true;
  }
  check(name, threw);
}

const src = fs.readFileSync(
  path.join(__dirname, "..", "src", "ptp_client", "web", "static", "main.js"),
  "utf8"
);

let appOptions = null;
const fetchCalls = [];
let pendingTimers = [];
let startFail = false;

const appStub = {
  component() {
    return this;
  },
  use() {
    return this;
  },
  mount() {},
};

const sandbox = {
  console,
  Vue: {
    createApp(opts) {
      appOptions = opts;
      return appStub;
    },
  },
  ElementPlus: {},
  ElementPlusLocaleZhCn: {},
  setTimeout(fn) {
    const id = pendingTimers.length + 1;
    pendingTimers.push({ id, fn });
    return id;
  },
  clearTimeout(id) {
    pendingTimers = pendingTimers.filter((t) => t.id !== id);
  },
};
sandbox.fetch = async (url, opts) => {
  fetchCalls.push({ url: String(url), opts: opts || {} });
  const json = async () => body;
  if (url.includes("/interfaces")) {
    var body = {
      interfaces: [
        { name: "eth9", description: "Linux eth9" },
        {
          name: "Hyper-V Virtual Ethernet Adapter",
          description: "Hyper-V Virtual Ethernet Adapter",
          mac: "00:15:5d:95:ec:41",
        },
      ],
    };
    return { ok: true, status: 200, json };
  }
  if (url.includes("/start")) {
    if (startFail) {
      body = { detail: "simulated failure" };
      return { ok: false, status: 400, statusText: "Bad Request", json };
    }
    const reqBody = JSON.parse((opts && opts.body) || "{}");
    body = {
      run_id: "run123",
      config: { profile: "g82751" },
      src_mac: "00:15:5d:95:ec:41",
      transport: reqBody.offline ? "virtual" : "live",
    };
    return { ok: true, status: 200, json };
  }
  if (url.includes("/stop")) {
    body = { stopping: true };
    return { ok: true, status: 200, json };
  }
  if (url.includes("/poll")) {
    body = { status: "stopped" };
    return { ok: true, status: 200, json };
  }
  body = {};
  return { ok: true, status: 200, json };
};
vm.createContext(sandbox);
vm.runInContext(src, sandbox, { filename: "main.js" });

if (!appOptions) {
  console.error("FAIL - main.js 未调用 Vue.createApp");
  process.exit(1);
}

function makeInstance() {
  const inst = appOptions.data();
  for (const [k, fn] of Object.entries(appOptions.computed || {})) {
    Object.defineProperty(inst, k, { get: fn, configurable: true });
  }
  Object.assign(inst, appOptions.methods);
  inst.$refs = {};
  inst.$nextTick = (fn) => fn && fn();
  return inst;
}
function lastCall() {
  return fetchCalls[fetchCalls.length - 1];
}

async function main() {
  /* ---------- 默认值（G.8275.1 子项） ---------- */
  let t = makeInstance();
  eq("默认子项 g82751", t.master.cfg.profile, "g82751");
  eq("默认 domain 43", t.master.cfg.domainNumber, 43);
  eq("默认 logAnnounce -3", t.master.cfg.logAnnounceInterval, -3);
  eq("默认 logSync -4", t.master.cfg.logSyncInterval, -4);
  eq("默认 Sync flags 含 twoStep(bit9)", (t.master.cfg.syncFlags >> 9) & 1, 1);
  eq("默认 Delay_Resp flags 不含 unicast(bit10)", (t.master.cfg.delayRespFlags >> 10) & 1, 0);
  eq("默认 Announce flags = 0x0038", t.master.cfg.announceFlags, 0x0038);

  /* ---------- 协议子项单选按钮联动 ---------- */
  t.onMasterProfileChange("1588v2");
  eq("切 1588v2 → domain 0", t.master.cfg.domainNumber, 0);
  eq("切 1588v2 → announce 0", t.master.cfg.logAnnounceInterval, 0);
  eq("切 1588v2 → sync 0", t.master.cfg.logSyncInterval, 0);
  t.onMasterProfileChange("g82751");
  eq("切回 g82751 → domain 43", t.master.cfg.domainNumber, 43);
  eq("切回 g82751 → announce -3", t.master.cfg.logAnnounceInterval, -3);
  eq("切回 g82751 → sync -4", t.master.cfg.logSyncInterval, -4);

  /* ---------- 全部表单字段 → buildMasterBody 映射 ---------- */
  t = makeInstance();
  Object.assign(t.master.cfg, {
    interface: "Hyper-V Virtual Ethernet Adapter",
    profile: "g82751",
    domainNumber: 25,
    clockIdentity: "aabbccddeeff0099",
    portNumber: 7,
    priority1: 201,
    priority2: 99,
    clockClass: 8,
    clockAccuracy: 0x21,
    offsetScaledLogVariance: 0x4321,
    timeSource: 0x90,
    currentUtcOffset: 37,
    logAnnounceInterval: -2,
    logSyncInterval: -6,
    announceFlags: 0x0038,
    syncFlags: 0x0000,
    followUpFlags: 0x0200,
    delayRespFlags: 0x0400,
    transportSpecific: 3,
    vlanId: null,
    vlanPcp: 5,
    dstMac: "01-0C-CD-01-00-66",
  });
  let body = t.buildMasterBody();
  const expected = {
    interface: "Hyper-V Virtual Ethernet Adapter",
    profile: "g82751",
    domainNumber: 25,
    clockIdentity: "aabbccddeeff0099",
    portNumber: 7,
    priority1: 201,
    priority2: 99,
    clockClass: 8,
    clockAccuracy: 0x21,
    offsetScaledLogVariance: 0x4321,
    timeSource: 0x90,
    currentUtcOffset: 37,
    logAnnounceInterval: -2,
    logSyncInterval: -6,
    announceFlags: 0x0038,
    syncFlags: 0x0000,
    followUpFlags: 0x0200,
    delayRespFlags: 0x0400,
    twoStep: false,
    delayRespUnicast: true,
    transportSpecific: 3,
    vlanPcp: 5,
    dstMac: "01-0C-CD-01-00-66",
  };
  for (const [k, v] of Object.entries(expected)) eq("字段注入 " + k, body[k], v);
  check("空 VLAN 不带入启动请求", !("vlanId" in body));
  check("启动请求不再含 offline", !("offline" in body));
  check("启动请求不再含行为参数", !("announceReceiptTimeout" in body) && !("followUpGapMs" in body)
    && !("maxSlaves" in body) && !("delayRespRateLimit" in body));

  t.master.cfg.vlanId = 33;
  body = t.buildMasterBody();
  eq("有 VLAN 时带入 vlanId", body.vlanId, 33);

  // 留空字段（clockIdentity / dstMac）不传，交给后端/网卡默认值
  t.master.cfg.clockIdentity = "";
  t.master.cfg.dstMac = "";
  t.master.cfg.vlanId = null;
  body = t.buildMasterBody();
  check("clockIdentity 留空省略", !("clockIdentity" in body));
  check("dstMac 留空省略", !("dstMac" in body));

  /* ---------- 启动按钮：未选网卡时报错且不发请求 ---------- */
  t = makeInstance();
  t.master.cfg.interface = "   ";
  const before = fetchCalls.length;
  await t.runMaster();
  eq("空网卡不调用后端", fetchCalls.length, before);
  eq("空网卡状态为 err", t.master.status.kind, "err");
  eq("空网卡保持停止", t.master.running, false);

  /* ---------- 启动按钮：正常路径 ---------- */
  t = makeInstance();
  t.master.cfg.interface = "Hyper-V Virtual Ethernet Adapter";
  t.master.cfg.clockClass = 52;
  await t.runMaster();
  const call = lastCall();
  check("启动请求打到 /start", call.url.endsWith("/api/ptp/l2-master/start"));
  eq("启动方法 POST", call.opts.method, "POST");
  const sent = JSON.parse(call.opts.body);
  eq("启动请求携带用户修改的 clockClass", sent.clockClass, 52);
  eq("启动成功 → running", t.master.running, true);
  eq("启动成功 → runId", t.master.runId, "run123");
  eq("启动成功 → 状态 ok", t.master.status.kind, "ok");
  check("启动成功 → 已调度轮询", pendingTimers.length > 0);

  /* ---------- 运行中修改报文属性 →「应用修改」按钮 ---------- */
  const updCallCount = fetchCalls.length;
  t.master.cfg.priority1 = 201;
  t.master.cfg.vlanId = 100;
  await t.applyMasterChanges();
  const ucall = lastCall();
  check("应用请求打到 /update", ucall.url.endsWith("/api/ptp/l2-master/update"));
  eq("应用方法 POST", ucall.opts.method, "POST");
  const patch = JSON.parse(ucall.opts.body);
  eq("应用请求携带新 priority1", patch.priority1, 201);
  eq("应用请求携带 vlanId", patch.vlanId, 100);
  check("应用请求不含网卡/子项", !("interface" in patch) && !("profile" in patch));
  check("应用请求不含行为参数", !("maxSlaves" in patch) && !("delayRespRateLimit" in patch));
  eq("应用成功 → 状态 ok", t.master.status.kind, "ok");
  check("应用成功提示下一个报文生效", t.master.status.msg.includes("下一个报文"));
  eq("应用后 running 不变", t.master.running, true);
  check("应用不重启轮询（无新 start 请求）", fetchCalls.slice(updCallCount).every((c) => !c.url.includes("/start")));

  // vlanId 留空 → 显式携带 null（运行期取消 VLAN tag）
  t.master.cfg.vlanId = null;
  await t.applyMasterChanges();
  eq("vlanId 留空显式传 null", JSON.parse(lastCall().opts.body).vlanId, null);

  // 字段非法 → 应用按钮不发请求
  const callsBeforeApply = fetchCalls.length;
  t.master.cfg.clockClass = 999;
  await t.applyMasterChanges();
  eq("字段非法 → 应用不发请求", fetchCalls.length, callsBeforeApply);
  check("字段非法 → 应用提示校验失败", t.master.status.msg.includes("字段校验失败"));
  t.master.cfg.clockClass = 6;

  /* ---------- 通用头联动开关 ---------- */
  const tl = makeInstance();
  tl.master.cfg.interface = "Hyper-V Virtual Ethernet Adapter";
  check("默认联动开启", tl.master.cfg.headerLink, true);
  // 开启：树内头字段 model 为共享键（无 ov: 前缀）
  let annDomain = tl.masterTrees[0].rows.find((r) => r.name === "domainNumber");
  eq("联动开 → domainNumber 绑定共享键", annDomain.model, "domainNumber");
  // 关闭后 Sync 的 domainNumber 绑定覆盖键
  tl.master.cfg.headerLink = false;
  annDomain = tl.masterTrees[0].rows.find((r) => r.name === "domainNumber");
  const syncDomain = tl.masterTrees[1].rows.find((r) => r.name === "domainNumber");
  eq("联动关 → Announce domainNumber 绑定覆盖键", annDomain.model, "ov:announce:domainNumber");
  eq("联动关 → Sync domainNumber 绑定覆盖键", syncDomain.model, "ov:sync:domainNumber");
  // 覆盖缺省时读取共享值
  tl.master.cfg.domainNumber = 43;
  eq("覆盖缺省 → 读取共享值", tl.getMasterField("ov:sync:domainNumber"), "43");
  // 写覆盖值不影响共享 cfg
  tl.setMasterField("ov:sync:domainNumber", "41");
  eq("写覆盖值 → 独立生效", tl.master.cfg.msgOverrides.sync.domainNumber, 41);
  eq("写覆盖值 → 不改共享 cfg", tl.master.cfg.domainNumber, 43);
  eq("覆盖后读取覆盖值", tl.getMasterField("ov:sync:domainNumber"), "41");
  // buildMasterPatch 关闭联动时下发 headerLink + messageOverrides
  const lp = tl.buildMasterPatch();
  eq("patch 携带 headerLink=false", lp.headerLink, false);
  eq("patch 携带 sync 覆盖 domain", lp.messageOverrides.sync.domainNumber, 41);
  check("未设置的报文不下发覆盖", lp.messageOverrides.announce === undefined);
  // 重新开启联动 → model 回到共享键、patch 不带 messageOverrides
  tl.master.cfg.headerLink = true;
  annDomain = tl.masterTrees[0].rows.find((r) => r.name === "domainNumber");
  eq("联动重开 → 回到共享键", annDomain.model, "domainNumber");
  const lp2 = tl.buildMasterPatch();
  eq("联动开 → patch headerLink=true", lp2.headerLink, true);
  check("联动开 → patch 无 messageOverrides", !("messageOverrides" in lp2));
  // 覆盖值非法 → 校验拦截
  tl.master.cfg.headerLink = false;
  tl.setMasterField("ov:sync:domainNumber", "999");
  check("覆盖值越界 → 校验失败", String(tl.validateMasterFields()).includes("domainNumber"));
  tl.master.cfg.headerLink = true;

  await t.stopMaster();

  /* ---------- 启动按钮：后端 400 时回显错误 ---------- */
  startFail = true;
  const t2 = makeInstance();
  t2.master.cfg.interface = "x";
  await t2.runMaster();
  eq("启动失败保持停止", t2.master.running, false);
  eq("启动失败状态 err", t2.master.status.kind, "err");
  check("启动失败提示含后端 detail", t2.master.status.msg.includes("simulated failure"));
  startFail = false;

  /* ---------- 停止按钮 ---------- */
  await t.stopMaster();
  const stopCall = lastCall();
  check("停止请求打到 /stop", stopCall.url.endsWith("/api/ptp/l2-master/stop"));
  eq("停止方法 POST", stopCall.opts.method, "POST");
  eq("停止后 running=false", t.master.running, false);
  eq("停止后 runId 清空", t.master.runId, null);
  eq("停止状态 ok", t.master.status.kind, "ok");

  /* ---------- 网卡列表按钮（mounted 自动加载） ---------- */
  t = makeInstance();
  await t.loadMasterInterfaces();
  eq("网卡列表加载 2 项", t.master.interfaces.length, 2);
  eq("自动选中 Hyper-V 网卡", t.master.cfg.interface, "Hyper-V Virtual Ethernet Adapter");

  /* ---------- 轮询渲染：计数器 / Slave 表 / 报文列表 ---------- */
  t = makeInstance();
  t.applyMasterPoll({
    status: "running",
    state: "ACTIVE",
    stats: { state: "ACTIVE", announce_sent: 3, delay_resp_sent: 1 },
    slaves: [{ clock_identity: "aabbccddeeff0001", port_number: 1, delay_req_count: 2 }],
    messages: [
      { index: 0, direction: "tx", summary: { message_type_name: "ANNOUNCE", sequence_id: 1, body: null } },
      { index: 1, direction: "rx", summary: { message_type_name: "DELAY_REQ", sequence_id: 9, body: null } },
    ],
    next_index: 2,
  });
  eq("计数器渲染", t.master.stats.state, "ACTIVE");
  eq("Slave 会话渲染", t.master.slaves.length, 1);
  eq("报文列表追加", t.master.messages.length, 2);
  eq("nextIndex 推进", t.master.nextIndex, 2);
  t.applyMasterPoll({
    status: "running",
    state: "ACTIVE",
    stats: {},
    slaves: [],
    messages: [{ index: 2, direction: "tx", summary: { message_type_name: "DELAY_RESP", sequence_id: 9, body: null } }],
    next_index: 3,
  });
  eq("增量轮询追加不覆盖", t.master.messages.length, 3);
  check("computed masterStatRows 有标签", t.masterStatRows.some((r) => /Announce/.test(r.label)));
  check("异常计数行标记 bad", t.masterStatRows.find((r) => /TX 错误/.test(r.label)).bad === false);

  /* ---------- 轮询到 stopped 自动收尾 ---------- */
  t = makeInstance();
  t.master.running = true;
  t.master.runId = "xyz";
  await t.pollMaster();
  eq("stopped 轮询 → running=false", t.master.running, false);
  eq("stopped 轮询 → runId=null", t.master.runId, null);

  /* ---------- 行点击 / 信息列 ---------- */
  t = makeInstance();
  const row = { index: 4, direction: "tx", peer_mac: "01:1b:19:00:00:00",
    summary: { sequence_id: 55, message_type_name: "ANNOUNCE",
      body: { grandmaster_identity: "0001020304050607", grandmaster_clock_quality: { clock_class: 6 } } } };
  const info = t.masterMsgInfo(row);
  check("Announce 信息含 GM", info.includes("GM=0001020304050607") && info.includes("seq=55") && info.includes("01:1b"));
  const respInfo = t.masterMsgInfo({ direction: "tx", peer_mac: "0c:a3:e2:b1:c0:d4",
    summary: { sequence_id: 8, message_type_name: "DELAY_RESP",
      body: { receive_timestamp: { seconds: 1760000000, nanoseconds: 123000000 } } } });
  check("Delay_Resp 信息含 t2", /t2=1760000000\.123000000/.test(respInfo) && respInfo.includes("0c:a3"));
  t.onMasterRowClick(row);
  eq("行点击选中报文", t.master.selected.index, 4);
  eq("行点击关闭自动滚动", t.master.autoScroll, false);

  /* ---------- Wireshark 顺序报文字段树 ---------- */
  t = makeInstance();
  const trees = t.masterTrees;
  eq("四类报文树", trees.map((x) => x.name), ["announce", "sync", "followup", "delayresp"]);
  check("树标题含报文类型与长度", /Announce（0xb）· 64 bytes/.test(trees[0].title)
    && /Sync（0x0）· 44 bytes/.test(trees[1].title)
    && /Follow_Up（0x8）· 44 bytes/.test(trees[2].title)
    && /Delay_Resp（0x9）· 54 bytes/.test(trees[3].title));

  // Announce 树：字段顺序必须与 Wireshark 解析一致（排除 flags 位展开与派生说明行）
  const wireNames = (tree) => tree.rows.filter((r) => r.depth !== 1).map((r) => r.name);
  eq("Announce 字段顺序 = Wireshark", wireNames(trees[0]), [
    "Ethernet II", "Source", "Destination", "Type", "Precision Time Protocol (IEEE1588)",
    "majorSdoId", "messageType", "minorVersionPTP", "versionPTP", "messageLength",
    "domainNumber", "minorSdoId", "flags",
    "correctionField", "messageTypeSpecific", "ClockIdentity", "SourcePortID", "sequenceId",
    "controlField", "logMessageInterval",
    "originTimestamp (seconds)", "originTimestamp (nanoseconds)", "originCurrentUTCOffset", "reserved",
    "priority1", "grandmasterClockClass", "grandmasterClockAccuracy", "grandmasterClockVariance",
    "priority2", "grandmasterClockIdentity", "localStepsRemoved", "TimeSource",
  ]);

  // 树内直接编辑：可编辑字段集合（有输入框、可改的项）
  eq("Announce 树可编辑字段", trees[0].rows.filter((r) => r.model).map((r) => r.model), [
    "dstMac", "transportSpecific", "domainNumber", "clockIdentity", "portNumber",
    "logAnnounceInterval", "currentUtcOffset", "priority1", "clockClass", "clockAccuracy",
    "offsetScaledLogVariance", "priority2", "timeSource",
  ]);

  const rowOf = (tree, name) => tree.rows.find((r) => r.name === name);
  eq("messageType 只读展示", rowOf(trees[0], "messageType").display, "Announce Message (0xb)");
  eq("messageLength 只读展示", rowOf(trees[0], "messageLength").display, "64");
  eq("controlField 只读展示", rowOf(trees[0], "controlField").display, "Other Message (5)");
  eq("flags 十六进制与位名（顺序同 Wireshark）", rowOf(trees[0], "flags").display,
    "0x0038, FREQUENCY_TRACEABLE, TIME_TRACEABLE, PTP_TIMESCALE");
  const flagNames = trees[0].rows.filter((r) => r.depth === 1 && r.name).map((r) => r.name);
  eq("flags 位展开顺序（MSB→LSB）", flagNames.slice(0, 4),
    ["PTP_SECURITY", "PTP profile Specific 2", "PTP profile Specific 1", "PTP_UNICAST"]);
  check("flags 含全部标准位", flagNames.length === 13 && flagNames.includes("SYNCHRONIZATION_UNCERTAIN")
    && flagNames.includes("PTP_LI_61"));
  const notes = trees[0].rows.filter((r) => r.type === "note").map((r) => r.display);
  check("logMessageInterval 派生说明 -3 → 0.125 s", notes.includes("-3 (0.125000 s)"));
  check("clockAccuracy 派生说明 49 → >10 s", notes.some((d) => /0x31/.test(d) && /10 s/.test(d)));
  check("TimeSource 派生说明 72 → 0x48", notes.some((d) => /0x48/.test(d)));
  eq("grandmasterClockIdentity 跟随 clockIdentity", rowOf(trees[0], "grandmasterClockIdentity").display,
    "0x0001020304050607");

  // VLAN：默认不打 tag；设置后出现 802.1Q 分组（PRI/ID 可编辑，CFI 只读）
  check("默认无 VLAN 分组", !trees[0].rows.some((r) => r.name === "802.1Q Virtual LAN"));
  t.master.cfg.vlanId = 100;
  t.master.cfg.vlanPcp = 5;
  const vt = wireNames(t.masterTrees[0]);
  const vi = vt.indexOf("802.1Q Virtual LAN");
  check("VLAN 分组顺序 PRI/CFI/ID 在 Type 之前", vi > 0 && vt[vi + 1] === "PRI" && vt[vi + 2] === "CFI"
    && vt[vi + 3] === "ID" && vt[vi + 4] === "Type");
  eq("VLAN 可编辑字段位置", t.masterTrees[0].rows.filter((r) => r.model).map((r) => r.model).slice(0, 4),
    ["dstMac", "vlanPcp", "vlanId", "transportSpecific"]);
  eq("VLAN PRI 绑定当前值", t.getMasterField(rowOf(t.masterTrees[0], "PRI").model), "5");
  eq("VLAN ID 绑定当前值", t.getMasterField(rowOf(t.masterTrees[0], "ID").model), "100");
  t.master.cfg.vlanId = null;

  // 其余三类报文的 messageType / controlField / 专有字段
  eq("Sync messageType", rowOf(trees[1], "messageType").display, "Sync Message (0x0)");
  eq("Sync controlField", rowOf(trees[1], "controlField").display, "Sync Message (0)");
  eq("Follow_Up messageType", rowOf(trees[2], "messageType").display, "Follow_Up Message (0x8)");
  eq("Follow_Up controlField", rowOf(trees[2], "controlField").display, "Follow Up Message (2)");
  eq("Delay_Resp messageType", rowOf(trees[3], "messageType").display, "Delay_Resp Message (0x9)");
  eq("Delay_Resp controlField", rowOf(trees[3], "controlField").display, "Delay Response Message (3)");
  eq("Delay_Resp logMessageInterval 只读 N/A", rowOf(trees[3], "logMessageInterval").display, "0x7f (N/A)");
  check("Delay_Resp 含 receiveTimestamp / requestingPortIdentity",
    ["receiveTimestamp (seconds)", "receiveTimestamp (nanoseconds)",
      "requestingPortIdentity.clockIdentity", "requestingPortIdentity.portNumber"]
      .every((n) => trees[3].rows.some((r) => r.name === n)));
  check("Sync 含 originTimestamp 且不含 Announce 专有字段",
    rowOf(trees[1], "originTimestamp (seconds)") !== undefined && rowOf(trees[1], "priority1") === undefined);

  /* ---------- flags 逐位点击切换（每报文 flagField 16 bit 整数） ---------- */
  const syncTwoStepRow = (syncFlags) => {
    const inst = makeInstance();
    inst.master.cfg.syncFlags = syncFlags;
    return inst.masterTrees[1].rows.find((r) => r.name === "PTP_TWO_STEP");
  };
  eq("syncFlags bit9=1 → PTP_TWO_STEP True", syncTwoStepRow(0x0200).display, "True");
  eq("syncFlags bit9=0 → PTP_TWO_STEP False", syncTwoStepRow(0x0000).display, "False");
  eq("TWO_STEP 行绑定 syncFlags", syncTwoStepRow(0x0200).toggleField, "syncFlags");
  eq("TWO_STEP 行携带位号 9", syncTwoStepRow(0x0200).toggleBit, 9);
  const drUnicastRow = (flags) => {
    const inst = makeInstance();
    inst.master.cfg.delayRespFlags = flags;
    return inst.masterTrees[3].rows.find((r) => r.name === "PTP_UNICAST");
  };
  eq("delayRespFlags bit10=1 → PTP_UNICAST True", drUnicastRow(0x0400).display, "True");
  eq("delayRespFlags bit10=0 → PTP_UNICAST False", drUnicastRow(0x0000).display, "False");
  eq("UNICAST 行绑定 delayRespFlags", drUnicastRow(0x0400).toggleField, "delayRespFlags");
  // 所有报文的所有 flags 位都可点击切换
  check("四类报文全部 flags 位均为 toggle",
    t.masterTrees.every((tr) => tr.rows.filter((r) => r.depth === 1 && r.type === "toggle").length === 13));
  eq("Announce flags 行绑定 announceFlags", rowOf(trees[0], "PTP_TIMESCALE").toggleField, "announceFlags");
  eq("Follow_Up flags 行绑定 followUpFlags", rowOf(trees[2], "PTP_TWO_STEP").toggleField, "followUpFlags");
  const ti = makeInstance();
  ti.toggleMasterFlag("syncFlags", 9);
  eq("点击 Sync TWO_STEP → bit9 清零", ti.master.cfg.syncFlags, 0x0000);
  ti.toggleMasterFlag("syncFlags", 9);
  eq("再点一次 → bit9 置回", ti.master.cfg.syncFlags, 0x0200);
  ti.toggleMasterFlag("delayRespFlags", 10);
  eq("点击 Delay_Resp UNICAST → bit10 置位", ti.master.cfg.delayRespFlags, 0x0400);
  ti.toggleMasterFlag("announceFlags", 15);
  eq("点击 Announce SECURITY → bit15 置位", ti.master.cfg.announceFlags, 0x8038);
  ti.toggleMasterFlag("syncFlags", 6);
  eq("点击 Sync SYNCHRONIZATION_UNCERTAIN → bit6 置位", ti.master.cfg.syncFlags, 0x0240);
  const syncFlagsBefore = ti.master.cfg.syncFlags;
  ti.toggleMasterFlag("", 9);
  eq("空字段名不改状态", ti.master.cfg.syncFlags, syncFlagsBefore);
  ti.toggleMasterFlag("syncFlags", undefined);
  eq("缺位号不改状态", ti.master.cfg.syncFlags, syncFlagsBefore);
  // 切换后 flags 十六进制摘要联动
  ti.master.cfg.syncFlags = 0x0040;
  eq("flags 摘要反映切换后的位", rowOf(ti.masterTrees[1], "flags").display, "0x0040, SYNCHRONIZATION_UNCERTAIN");

  /* ---------- 字段读 / 写回 ---------- */
  const gi = makeInstance();
  eq("getMasterField 数字转字符串", gi.getMasterField("domainNumber"), "43");
  eq("getMasterField null → 空串", gi.getMasterField("vlanId"), "");
  gi.setMasterField("priority1", "200");
  eq("写回数字字段", gi.master.cfg.priority1, 200);
  gi.setMasterField("logAnnounceInterval", "-1");
  eq("写回负数 interval", gi.master.cfg.logAnnounceInterval, -1);
  gi.setMasterField("timeSource", "0x90");
  eq("接受 0x 前缀写法", gi.master.cfg.timeSource, 144);
  gi.setMasterField("clockIdentity", "AA-BB:CC DD/EE FF 00 11");
  eq("clockIdentity 清洗分隔符", gi.master.cfg.clockIdentity, "aabbccddeeff0011");
  gi.setMasterField("dstMac", " 01-1B-19-00-00-01 ");
  eq("dstMac 去首尾空白", gi.master.cfg.dstMac, "01-1B-19-00-00-01");
  gi.setMasterField("vlanId", "33");
  eq("vlanId 数字", gi.master.cfg.vlanId, 33);
  gi.setMasterField("vlanId", "");
  eq("vlanId 置空 → 不打 tag", gi.master.cfg.vlanId, null);
  gi.setMasterField("clockClass", "abc");
  eq("非数字文本暂存（由启动校验拦截）", gi.master.cfg.clockClass, "abc");

  /* ---------- 启动前范围校验 ---------- */
  const vd = makeInstance();
  eq("默认配置校验通过", vd.validateMasterFields(), null);
  vd.master.cfg.domainNumber = 300;
  check("domain 越界拦截", /domainNumber 超出范围/.test(vd.validateMasterFields()));
  vd.master.cfg.domainNumber = 43;
  vd.master.cfg.clockIdentity = "zzz";
  check("非法 clockIdentity 拦截", /clockIdentity/.test(vd.validateMasterFields()));
  vd.master.cfg.clockIdentity = "";
  eq("clockIdentity 留空合法（由网卡派生）", vd.validateMasterFields(), null);
  vd.master.cfg.vlanId = 5000;
  check("VLAN 越界拦截", /VLAN ID/.test(vd.validateMasterFields()));
  vd.master.cfg.vlanId = null;
  vd.master.cfg.portNumber = "";
  check("必填字段留空拦截", /不能为空/.test(vd.validateMasterFields()));
  vd.master.cfg.portNumber = 1;
  vd.master.cfg.logSyncInterval = 200;
  check("logMessageInterval 越界拦截", /logMessageInterval 超出范围/.test(vd.validateMasterFields()));
  vd.master.cfg.logSyncInterval = -4;
  vd.master.cfg.clockClass = "abc";
  check("非数字字段拦截", /grandmasterClockClass/.test(vd.validateMasterFields()));

  /* ---------- 校验失败时启动按钮不发请求 ---------- */
  const ri = makeInstance();
  ri.master.cfg.interface = "some-nic";
  ri.master.cfg.clockClass = 999;
  const callsBefore = fetchCalls.length;
  await ri.runMaster();
  eq("字段非法 → 不发请求", fetchCalls.length, callsBefore);
  eq("字段非法 → 状态 err", ri.master.status.kind, "err");
  check("字段非法提示含校验失败", ri.master.status.msg.includes("字段校验失败"));
  eq("字段非法 → 未进入运行", ri.master.running, false);

  /* ---------- 表单修改的字段确实进入启动请求体 ---------- */
  const wi = makeInstance();
  wi.master.cfg.interface = "Hyper-V Virtual Ethernet Adapter";
  wi.setMasterField("priority1", "201");
  wi.setMasterField("timeSource", "160");
  wi.setMasterField("logSyncInterval", "-6");
  wi.setMasterField("domainNumber", "24");
  wi.setMasterField("clockIdentity", "11223344556677aa");
  wi.setMasterField("offsetScaledLogVariance", "4608");
  wi.toggleMasterFlag("delayRespFlags", 10);
  await wi.runMaster();
  const wbody = JSON.parse(lastCall().opts.body);
  eq("表单改 priority1 → 请求体", wbody.priority1, 201);
  eq("表单改 timeSource → 请求体", wbody.timeSource, 160);
  eq("表单改 logSyncInterval → 请求体", wbody.logSyncInterval, -6);
  eq("表单改 domainNumber → 请求体", wbody.domainNumber, 24);
  eq("表单改 clockIdentity → 请求体", wbody.clockIdentity, "11223344556677aa");
  eq("表单改 variance → 请求体", wbody.offsetScaledLogVariance, 4608);
  eq("切换 unicast 位 → 请求体 delayRespFlags", wbody.delayRespFlags, 0x0400);
  eq("unicast 位 → 派生 delayRespUnicast", wbody.delayRespUnicast, true);
  eq("报文 flags 全部进入请求体", [wbody.announceFlags, wbody.syncFlags, wbody.followUpFlags], [0x0038, 0x0200, 0x0200]);
  eq("syncFlags bit9 → 派生 twoStep", wbody.twoStep, true);

  /* ---------- Ethernet II 源 MAC 回填 ---------- */
  const si = makeInstance();
  si.master.srcMac = "00:15:5d:95:ec:41";
  eq("Source 显示真实源 MAC", rowOf(si.masterTrees[0], "Source").display, "00:15:5d:95:ec:41");
  eq("未启动时源 MAC 占位提示", rowOf(makeInstance().masterTrees[0], "Source").display, "（启动后由网卡决定）");
}

main()
  .then(() => {
    if (failures.length) {
      console.error("\n" + failures.length + " 项前端检查失败: " + failures.join("; "));
      process.exit(1);
    }
    console.log("\nALL FRONTEND CHECKS PASS");
  })
  .catch((e) => {
    console.error("测试脚本异常:", e);
    process.exit(1);
  });
