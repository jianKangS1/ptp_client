# 软件架构设计文档（AI 上下文入口）

> 本文档面向 AI 与开发者，描述 ptp_client 的整体架构、进程入口、核心函数职责与调用链。
> 修改代码前先读本文档；重大结构变更后请同步更新本文档中的函数名与行号。
> 行号基于 2026-09 当前代码，若对不上请以函数名搜索为准。

---

## 1. 总体架构

```
┌─────────────────────────── 用户界面层 ───────────────────────────┐
│  CLI (argparse)                 Web 控制台 (FastAPI + 静态 JS)     │
│  ntp/cli.py:main()              web/app.py:create_app()           │
│  ptp/cli.py:main()              web/static/index.html + *.js      │
└────────────┬─────────────────────────────┬───────────────────────┘
             │                             │ HTTP: /api/ntp/exchange
             │ 直接调用                      │       /api/ptp/build
             ▼                             │       /api/ptp/g8275-acr/{start,poll,stop}
┌─────────────────────── 会话/编排层 ───────────────────────────────┐
│  ptp/g82752_unicast.py : G82752UnicastSession  (协商+测量+续约+CANCEL)│
│  web/ptp_lab.py        : start/poll/stop 后台线程编排 + 报文采集     │
└────────────┬─────────────────────────────────────────────────────┘
             │
             ▼
┌─────────────────────── 协议传输层 ────────────────────────────────┐
│  ptp/client.py : PTPAcrUnicastClient  (UDP 319 事件 + 320 通用,     │
│                                        接收线程 + 报文缓冲队列)      │
│  ntp/client.py : NTPClient            (UDP 123 单次请求-应答)       │
└────────────┬─────────────────────────────────────────────────────┘
             │
             ▼
┌─────────────────────── 报文编解码层 ──────────────────────────────┐
│  ptp/header.py, ptp/packet.py, ptp/serde.py, ptp/signaling.py     │
│  ptp/request_builder.py, ptp/delay_request.py                     │
│  ntp/packet.py, ntp/serde.py, ntp/request_builder.py              │
│  ptp/pcap.py, ntp/pcap.py  (pcap 导出)                             │
└───────────────────────────────────────────────────────────────────┘
```

包根：`src/ptp_client/`（src 布局，`pip install -e .` 后可用 `python -m ptp_client.xxx`）。

---

## 2. 主函数（进程入口）

| 入口                    | 定义位置                                                                       | 说明                                                                                                                                                                                                                             |
| ----------------------- | ------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| NTP CLI `main()`        | [ntp/cli.py:21](file:///e:/project/ptp_client/src/ptp_client/ntp/cli.py#L21)   | `ntp-client` 命令 / `python -m ptp_client.ntp`，解析参数→`NTPClient.exchange()`→打印结果                                                                                                                                         |
| PTP CLI `main()`        | [ptp/cli.py:217](file:///e:/project/ptp_client/src/ptp_client/ptp/cli.py#L217) | `ptp-acr-client` 命令 / `python -m ptp_client.ptp`，子命令 delay/estimate/build/g8275-negotiate/g8275-acr；g8275 流程走 `_run_g8275_session()`（[ptp/cli.py:131](file:///e:/project/ptp_client/src/ptp_client/ptp/cli.py#L131)） |
| Web `main()`            | [web/app.py:244](file:///e:/project/ptp_client/src/ptp_client/web/app.py#L244) | `ntp-web` 命令 / `python -m ptp_client.web`（`web/__main__.py` 转发），uvicorn 启动 `create_app()`，监听 127.0.0.1:8765                                                                                                          |
| Web 工厂 `create_app()` | [web/app.py:116](file:///e:/project/ptp_client/src/ptp_client/web/app.py#L116) | 创建 FastAPI 实例并注册全部路由                                                                                                                                                                                                  |

入口注册见 `pyproject.toml` 的 `[project.scripts]`。

---

## 3. 收包（RX）

### PTP（核心，双端口 + 后台接收线程）

- **收包主循环**：`PTPAcrUnicastClient._receiver_loop()` — [ptp/client.py:440](file:///e:/project/ptp_client/src/ptp_client/ptp/client.py#L440)
  后台线程（`start()` 时创建，名为 `ptp-recv`），`select()` 同时轮询事件 socket(319) 与通用 socket(320)，`recvfrom(4096)` 取数据报。
- **单包解析入队**：`PTPAcrUnicastClient._ingest_ptp_datagram()` — [ptp/client.py:376](file:///e:/project/ptp_client/src/ptp_client/ptp/client.py#L376)
  解析 `PTPHeader`，按 `message_length` 截断，放入 `_general_buf`（deque + Condition 缓冲），并回调 `on_packet("rx", ...)`。
- **等待/匹配取包**：`_pop_matching_general(accept, deadline)` — [ptp/client.py:457](file:///e:/project/ptp_client/src/ptp_client/ptp/client.py#L457)
  业务侧从缓冲中按谓词取包（GRANT/Sync/Follow_Up/Delay_Resp 匹配都走这里），超时抛 `TimeoutError`。
- **Sync 采样**：`wait_sync_sample()` — [ptp/client.py:667](file:///e:/project/ptp_client/src/ptp_client/ptp/client.py#L667)（两步法配对 Follow_Up；Follow_Up 先行降级路径 `_try_sync_sample_follow_up_led()` L504）
- **Delay_Resp 收取**：在 `exchange_delay()` 内通过 `accept_delay_resp` 谓词 + `_pop_matching_general` 完成 — [ptp/client.py:626](file:///e:/project/ptp_client/src/ptp_client/ptp/client.py#L626)
- **Web 实时视图挂钩**：`PtpPacketCollector.on_packet()` — [web/ptp_lab.py:59](file:///e:/project/ptp_client/src/ptp_client/web/ptp_lab.py#L59)（构造 `PTPAcrUnicastClient(on_packet=collector.on_packet)` 注入，见 ptp_lab.py L330 附近；TX/RX 全部记录用于 poll 与 pcap）

### NTP（同步单次）

- **收包**：`NTPClient.exchange()` 内 `sock.recv(2048)` — [ntp/client.py:91](file:///e:/project/ptp_client/src/ptp_client/ntp/client.py#L91)（connect 后同步等 48 字节应答，无独立线程）

---

## 4. 发包与协商（TX / G.8275.2）

### 发包原语（ptp/client.py）

| 函数                            | 位置                                                                             | 用途                                                                                                                                                                                                                                                        |
| ------------------------------- | -------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `send_general(udp_payload)`     | [client.py:240](file:///e:/project/ptp_client/src/ptp_client/ptp/client.py#L240) | 320 通用端口发送（Signalling 走这里）                                                                                                                                                                                                                       |
| `_send_event(payload)`          | [client.py:253](file:///e:/project/ptp_client/src/ptp_client/ptp/client.py#L253) | 319 事件端口发送（Delay_Req 走这里；Windows 下优先 raw IP 发送 `_send_event`→`ipv4_send.send_ipv4_udp_raw`）                                                                                                                                                |
| `exchange_delay(spec, timeout)` | [client.py:589](file:///e:/project/ptp_client/src/ptp_client/ptp/client.py#L589) | 组包→`_send_event` 发 Delay_Req→等 Delay_Resp→返回 t3/t4 结果                                                                                                                                                                                               |
| `estimate_offset_and_delay()`   | [client.py:755](file:///e:/project/ptp_client/src/ptp_client/ptp/client.py#L755) | 一次 Sync 采样 + 一次 Delay 交换，算 E2E offset / mean path delay                                                                                                                                                                                           |
| 组包                            | `build_ptp_udp_payload(spec)`                                                    | [ptp/request_builder.py:40](file:///e:/project/ptp_client/src/ptp_client/ptp/request_builder.py#L40)；Delay_Req 规格由 `build_delay_request_spec()`（[ptp/delay_request.py:72](file:///e:/project/ptp_client/src/ptp_client/ptp/delay_request.py#L72)）生成 |

### 协商状态机（ptp/g82752_unicast.py，类 `G82752UnicastSession`，L85）

| 函数                                             | 位置                                                                                                                                                                                                                                                | 用途                                                                                                                           |
| ------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| `negotiate()`                                    | [L325](file:///e:/project/ptp_client/src/ptp_client/ptp/g82752_unicast.py#L325)                                                                                                                                                                     | **协商主函数**：REQUEST_UNICAST_TX(Announce+Sync[+Delay_Resp]) → 等 GRANT → 记录 `G82752NegotiationState.grants`               |
| `_negotiate_with_retries()`                      | [L289](file:///e:/project/ptp_client/src/ptp_client/ptp/g82752_unicast.py#L289)                                                                                                                                                                     | 带重试的单类协商（`_send_signaling` + `_collect_grants_until`）                                                                |
| `_send_signaling(tlvs)`                          | [L161](file:///e:/project/ptp_client/src/ptp_client/ptp/g82752_unicast.py#L161)                                                                                                                                                                     | 组装 Signalling 报文并经 `client.send_general()` 发出                                                                          |
| `measure_acr(cfg)`                               | [L422](file:///e:/project/ptp_client/src/ptp_client/ptp/g82752_unicast.py#L422)                                                                                                                                                                     | **ACR 测量主函数**：周期 `wait_sync_sample` + `exchange_delay`，产出 `PTPAcrEstimateResult`，期间 `_renew_if_due()`(L134) 续约 |
| `start_acr()` / `_manager_loop()` / `wait_acr()` | [L716](file:///e:/project/ptp_client/src/ptp_client/ptp/g82752_unicast.py#L716) / [L738](file:///e:/project/ptp_client/src/ptp_client/ptp/g82752_unicast.py#L738) / [L758](file:///e:/project/ptp_client/src/ptp_client/ptp/g82752_unicast.py#L758) | 后台 manager 线程：negotiate → measure_acr；`request_stop()`(L773) 非阻塞请求停止，`is_finished()`(L777) 查询结束              |
| `renew_now()` / `cancel_unicast()`               | [L676](file:///e:/project/ptp_client/src/ptp_client/ptp/g82752_unicast.py#L676) / [L683](file:///e:/project/ptp_client/src/ptp_client/ptp/g82752_unicast.py#L683)                                                                                   | 续约 / 发 CANCEL_UNICAST_TX 拆除单播合约                                                                                       |
| Signalling TLV 编解码                            | `build_request_unicast_tlv`(L39) / `build_cancel_unicast_tlv`(L74) / `build_signaling_udp_payload`(L186) / `extract_grants_from_signaling_udp`(L131)                                                                                                | [ptp/signaling.py](file:///e:/project/ptp_client/src/ptp_client/ptp/signaling.py)                                              |

### NTP 发包

- `NTPClient.exchange()` — [ntp/client.py:63](file:///e:/project/ptp_client/src/ptp_client/ntp/client.py#L63)：`sock.send(payload)`（L90）+ 同步 recv；请求报文由 `build_ntp_packet(spec)`（[ntp/request_builder.py:19](file:///e:/project/ptp_client/src/ptp_client/ntp/request_builder.py#L19)）构造。

---

## 5. Web 展示（前端）

| 文件                                                                                        | 职责                                                                                                                                                                                                                                 |
| ------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| [web/static/index.html](file:///e:/project/ptp_client/src/ptp_client/web/static/index.html) | 单页双页签：NTP 表单/结果、PTP ACR 表单（GM/绑定、协商参数、Delay_Req 字段、JSON 编辑）+ 右侧结果区（实时报文列表 `#ptp-msg-list`、统计、选中报文 hex/JSON、估计表、pcap 预览）                                                      |
| [web/static/ptp-app.js](file:///e:/project/ptp_client/src/ptp_client/web/static/ptp-app.js) | PTP 页签逻辑：`buildPtpAcrBody()` 收集表单 → `runPtpAcr()` POST start → `pollPtpRun()` 每 500ms GET poll 增量渲染（`appendPtpRows`/`applyPtpPollResult`，Wireshark 式）→ `stopPtpAcr()` POST stop；`previewPtpPacket()` 离线组包预览 |
| [web/static/app.js](file:///e:/project/ptp_client/src/ptp_client/web/static/app.js)         | NTP 页签逻辑：表单↔JSON、POST `/api/ntp/exchange`、渲染结果与下载 pcap                                                                                                                                                               |
| [web/static/styles.css](file:///e:/project/ptp_client/src/ptp_client/web/static/styles.css) | 暗色主题样式（`.msg-row` 实时报文行等）                                                                                                                                                                                              |
| 挂载点                                                                                      | `create_app()` 中 `app.mount("/static", ...)` + `index()` 路由返回 index.html（[web/app.py:229](file:///e:/project/ptp_client/src/ptp_client/web/app.py#L229)）                                                                      |

---

## 6. 接收网页请求（后端 API，全部在 web/app.py `create_app()` 内注册）

| 路由                                       | 处理函数                | 位置       | 转发到                                                                      |
| ------------------------------------------ | ----------------------- | ---------- | --------------------------------------------------------------------------- |
| GET `/api/health`                          | `health()`              | app.py:127 | —                                                                           |
| POST `/api/ntp/exchange`                   | `ntp_exchange()`        | app.py:131 | `build_ntp_packet()` + `NTPClient.exchange()` + `build_ntp_exchange_pcap()` |
| POST `/api/ptp/build`                      | `ptp_build()`           | app.py:184 | `build_ptp_packet_response()`（ptp_lab.py:136，离线不联网）                 |
| POST `/api/ptp/g8275-acr/start`            | `ptp_g8275_acr_start()` | app.py:194 | `start_g8275_acr_lab()`（ptp_lab.py:270）                                   |
| GET `/api/ptp/g8275-acr/poll?run_id&since` | `ptp_g8275_acr_poll()`  | app.py:215 | `poll_g8275_acr_lab()`（ptp_lab.py:380）                                    |
| POST `/api/ptp/g8275-acr/stop?run_id`      | `ptp_g8275_acr_stop()`  | app.py:222 | `stop_g8275_acr_lab()`（ptp_lab.py:409）                                    |

请求体校验用 Pydantic 模型（app.py L30–L113）：`G8275AcrRequestModel`（L98）等。

---

## 7. Web 运行编排（web/ptp_lab.py）

一次浏览器 ACR 运行的生命周期：

```
POST /start ──► start_g8275_acr_lab()          # 建 client+session+collector，注册 _RUNS[run_id]
   │              └─ 线程 "ptp-lab-run" ──► _lab_worker()   # ptp_lab.py:208
   │                       ├─ session.start_acr(...)        # 后台 manager: negotiate → measure_acr
   │                       ├─ 循环: run.stop_event? → session.request_stop()
   │                       ├─ session.is_finished() 退出
   │                       ├─ finally: session.cancel_unicast(wait_ack=False)  # ★ 停止时发 CANCEL 给 server
   │                       └─ finally: client.close(); 生成 pcap_base64; run.finished.set()
GET /poll  ──► poll_g8275_acr_lab(run_id, since)  # 增量返回 collector.records_since(since) + stats + estimates
POST /stop ──► stop_g8275_acr_lab(run_id)         # 仅置位 run.stop_event（非阻塞），由 worker 发 CANCEL
```

- 端口策略：事件 319 / 通用 320 固定（`start_g8275_acr_lab` 中 `src_adr=(bind, EVENT_PORT)`），前端无 bind_port。
- `measure_duration_sec<=0/None` = 一直运行直到用户点停止。
- 已结束 run 由 `_gc_finished_runs()`（L196）在 600s 后回收。
- 线程安全：`run.lock` 保护 estimates；collector 记录 append-only，poll 用切片快照。

---

## 8. 关键数据结构

| 结构                                  | 位置                 | 含义                                                               |
| ------------------------------------- | -------------------- | ------------------------------------------------------------------ |
| `PTPHeader` / `PortIdentity`          | ptp/header.py        | PTPv2 公共头（34B）与端口标识                                      |
| `PTPAcrEstimateResult`                | ptp/client.py:88     | 一次 offset/mean_path_delay 估计（含 sync+delay 原始 udp 字节）    |
| `G82752NegotiationState`              | g82752_unicast.py:61 | 协商结果：GM 身份 + `grants: {message_type: logPeriod}`            |
| `G82752AcrRunConfig`                  | g82752_unicast.py:72 | 测量循环配置（超时、间隔、时长、on_estimate 回调）                 |
| `PacketRecord` / `PtpPacketCollector` | web/ptp_lab.py:47/59 | Web 实时报文记录（index/dir/channel/hex/summary/src/dst）+ pcap 行 |
| `_LabRun`                             | web/ptp_lab.py:162   | 一次后台运行会话（stop_event/finished/estimates/pcap）             |
| `NTPPacket` / `NTPTime`               | ntp/packet.py        | 48B NTP 报文与 64 位时间戳                                         |
| `NTPExchangeResult`                   | ntp/client.py:25     | t1~t4、offset、RTT、双向原始字节                                   |

---

## 9. 配置与脚本

- `config/ntp-client.json`、`config/ptp-acr-client.json`（JSONC）→ 由 `scripts/start-*.ps1`、`scripts/configure-*.ps1` 读取并映射为 CLI 参数。
- `scripts/wsl/`：WSL 内 ptp4l 单播 master/client 配置（联调对端）。
- 测试：`tests/`（pytest；`pyproject.toml` 配 `pythonpath=["src"]`）。

## 10. 已知约束

- 软件时间戳（send/recv 边界取 `time.time()`），精度低于硬件打戳；见 ptp/client.py 顶部注释。
- 绑定 319/320 需管理员权限；被 ptp4l 占用时报 OSError(10048)。
- Windows 单播 319 发送优先走 raw IP socket（`ptp/ipv4_send.py`），失败回退普通 UDP。
- Web run 表 `_RUNS` 为进程内内存态，重启服务即清空；不支持多用户并发共享同一 run。
