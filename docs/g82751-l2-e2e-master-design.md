# G.8275.1 / 1588v2 层二 E2E Master（GM）模块 — 需求设计说明书

| 文档版本 | 修订日期   | 说明                                               |
| -------- | ---------- | -------------------------------------------------- |
| V0.1     | 2026-09-13 | 初稿：新增 L2 E2E 主时钟模块，含四种报文完整字段表 |

---

## 1. 引言

### 1.1 编写目的

本文档定义本仓库**新增模块**：软件实现的 **PTP 主时钟（Grandmaster）**，运行于 **层二（L2 / IEEE 802.3 Ethernet）传输**，支持 **ITU-T G.8275.1** 与 **IEEE 1588-2008/2019 通用** 两种配置文件，延迟机制为 **E2E（End-to-End）**。

读者为研发、测试、运维。本文档为需求+概要设计级，明确"做什么、怎么做、软件行为是什么"，并给出 Announce / Sync / Follow_Up / Delay_Resp 四种报文的**完整字段结构、数据宽度与字段作用**。

### 1.2 一句话需求

> 本机做 PTP Master，在二层口上周期性发出 **Announce** 与 **Sync（+ Follow_Up）**；收到下游 Slave 的 **Delay_Req** 后，记录接收时刻并回复 **Delay_Resp**。

### 1.3 与现有模块的关系

| 现有能力                                                        | 本模块关系                                      |
| --------------------------------------------------------------- | ----------------------------------------------- |
| `ptp/header.py`（34B 公共头）、`ptp/timestamp.py`（10B 时间戳） | **直接复用**，与传输层无关                      |
| `ptp/packet.py`（Sync/Follow_Up/Delay_Req/Delay_Resp 编解码）   | **复用**，需补 Announce                         |
| `ptp/request_builder.py`（spec dict → payload）                 | **扩展**，需补 `announce` 分支                  |
| `ptp/client.py`（UDP 319/320 从时钟客户端）                     | **不复用**，L2 需新传输层                       |
| `ptp/g82752_unicast.py`（G.8275.2 单播协商）                    | **不涉及**，G.8275.1 为组播、无 Signalling 协商 |
| `ptp/pcap.py`（UDP pcap，DLT 1/ETHERNET）                       | **复用**（已是以太网帧封装）                    |

### 1.4 范围

**范围内**：GM 角色、L2 传输、E2E 延迟机制、Announce/Sync/Follow_Up/Delay_Resp 收发、多下游 Slave 会话管理、配置与可观测。

**范围外**（明确不做）：
- ❌ P2P 延迟机制（Pdelay_Req/Resp/Resp_Follow_Up）→ 二期
- ❌ UDP/IPv4、IPv6 传输 → 已有 L4 路径覆盖
- ❌ Slave / ACR 驯钟逻辑（本模块是时间源，不跟踪上游）
- ❌ BC（边界时钟）/ TC（透明时钟）的 residenceTime 累加
- ❌ 802.1AS / G.8265.1 / MPT（多路径透明时钟）
- ❌ 硬件时间戳（`SO_TIMESTAMPING`）→ 三期，首版软件打戳

### 1.5 术语

| 术语            | 说明                                                                  |
| --------------- | --------------------------------------------------------------------- |
| GM              | Grandmaster，大时钟；本模块角色                                       |
| Slave           | 下游从时钟，本模块的对端                                              |
| E2E             | End-to-End 延迟测量：Sync/Follow_Up + Delay_Req/Delay_Resp            |
| 一步法 / 两步法 | Sync 内嵌精确时间戳 / Sync + Follow_Up 携带精确时间戳                 |
| L2 传输         | IEEE 1588 Annex H，EtherType 0x88F7，无 IP/UDP 头                     |
| 桥驻留地址      | 01-80-C2-00-00-xx，不被普通网桥转发，供 TC/BC 处理                    |
| PortIdentity    | clockIdentity(8B) + portNumber(2B) = 10B，唯一标识一个 PTP 端口       |
| Timestamp       | secondsField(UInteger48, 6B) + nanosecondsField(UInteger32, 4B) = 10B |

### 1.6 参考

- IEEE 1588-2008 第 13 章（报文格式）、第 11 章（E2E 延迟机制）、Annex H（L2 传输）
- ITU-T G.8275.1（电信 profile，全 L2 + TC）
- 仓库内 `docs/需求设计说明书.md`（总纲）、`ARCHITECTURE.md`
- 联调对端：`scripts/wsl/ptp4l-unicast-client.conf`（已改为 G.8275.1 L2 slave）

---

## 2. 系统概述

### 2.1 模块定位

```
                     ┌──────────────── 本模块（PTP L2 Master）─────────────────┐
  时间源              │                                                        │
  CLOCK_REALTIME ───►│ 时钟抽象 ─┬─► Announce 调度 ─┐                           │
  (或指定 PHC)        │           ├─► Sync 调度     ├─► L2 发送 ──► 0x88F7 ────┼──► 下游 Slave
                     │           ├─► Follow_Up     │                           │
                     │           └─► Delay_Resp ◄──┴── L2 接收 ◄── Delay_Req ──┼──◄ 下游 Slave
                     │                  ▲                                     │
                     │            Slave 会话表                                │
                     └────────────────────┬───────────────────────────────────┘
                                          │
                              CLI / Web API / 配置文件 / 日志指标
```

### 2.2 用户角色

| 角色        | 诉求                                                        |
| ----------- | ----------------------------------------------------------- |
| 实验室/联调 | 用软件模拟 GM，喂标准 ptp4l/自研 Slave 做互通验证           |
| 测试        | 构造特定字段（domain、interval、clockClass）验证 Slave 行为 |
| 运维        | 启停实例、查看在线 Slave 列表、Delay_Resp 成功率            |

### 2.3 运行环境

| 项            | 要求                                                                                                          |
| ------------- | ------------------------------------------------------------------------------------------------------------- |
| OS            | **Linux 优先**（`AF_PACKET/SOCK_RAW`，需 root 或 `CAP_NET_RAW`）                                              |
| OS（Windows） | 需 **Npcap**（`pcap_inject`/`pcap_sendqueue_transmit` 注入完整 L2 帧）；无 Npcap 时模块拒绝启动并给出明确错误 |
| 运行时        | Python 3.11+                                                                                                  |
| 网络          | 与 Slave **同一二层广播域**（同 VLAN/同交换机）；中间设备不得阻断 01-80-C2-00-00-0E                           |

---

## 3. 功能需求

| 编号  | 功能                           | 简述                                                                          | 优先级     |
| ----- | ------------------------------ | ----------------------------------------------------------------------------- | ---------- |
| MF-01 | L2 传输层                      | 原始以太网帧收发，EtherType 0x88F7，支持 VLAN tag                             | P0         |
| MF-02 | GM 身份与时钟质量              | 配置 clockIdentity / priority1 / priority2 / clockClass / accuracy / variance | P0         |
| MF-03 | Announce 周期发送              | 按 `logAnnounceInterval` 组播 Announce                                        | P0         |
| MF-04 | Sync 周期发送                  | 按 `logSyncInterval` 组播 Sync（一步/两步可配）                               | P0         |
| MF-05 | Follow_Up 发送                 | 两步法下紧随 Sync，携带精确 originTimestamp                                   | P0         |
| MF-06 | Delay_Req 接收与校验           | 过滤 domain/版本/类型，记录接收时刻 t2                                        | P0         |
| MF-07 | Delay_Resp 应答                | 回填 t2 + requestingPortIdentity，回发 Slave                                  | P0         |
| MF-08 | 多 Slave 会话管理              | 会话表、老化、数量上限、限速                                                  | P0         |
| MF-09 | 配置管理                       | JSON 配置文件 + Schema 校验 + CLI 覆盖                                        | P0         |
| MF-10 | 可观测性                       | 日志、计数指标、在线 Slave 查询、pcap 导出                                    | P1         |
| MF-11 | Web 集成                       | 控制台启停 Master、实时报文视图                                               | P1         |
| MF-12 | G.8275.1 / 1588v2 profile 切换 | 一键切换默认参数集与目的 MAC                                                  | P1         |
| MF-13 | P2P（Pdelay）支持              | Peer 延迟报文                                                                 | P2（二期） |
| MF-14 | 硬件时间戳                     | `SO_TIMESTAMPING` TX/RX 硬件戳                                                | P2（三期） |

---

## 4. 报文格式详细设计

> 所有 PTP 报文 = **34 字节公共头** + **报文 body**。L2 模式下 PTP 报文直接跟在以太头（14B，可选 4B VLAN tag）之后，`messageLength` = 34 + body 长度（**不含**以太网头，**不含**VLAN tag）。

### 4.1 PTP 公共头（34 字节，所有报文共有）

| 偏移 | 字段名                           | 宽度 | 类型                  | 作用                                                                                                                                                |
| ---- | -------------------------------- | ---- | --------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0    | transportSpecific + messageType  | 1 B  | UInteger4 + UInteger4 | 高 4 bit `transportSpecific`（G.8275.1 可配，默认 0）；低 4 bit `messageType`：0x0=Sync, 0x1=Delay_Req, 0x8=Follow_Up, 0x9=Delay_Resp, 0xB=Announce |
| 1    | reserved + versionPTP            | 1 B  | UInteger4 + UInteger4 | 高 4 bit 保留置 0；低 4 bit `versionPTP` **固定为 2**                                                                                               |
| 2    | messageLength                    | 2 B  | UInteger16            | **整个 PTP 报文长度**（34 + body），网络字节序。Announce=64, Sync=44, Follow_Up=44, Delay_Resp=54                                                   |
| 4    | domainNumber                     | 1 B  | UInteger8             | PTP 域号。G.8275.1 本项目用 **43**（标准范围 24–43）；1588v2 通用默认 0                                                                             |
| 5    | reserved                         | 1 B  | UInteger8             | 保留，置 0                                                                                                                                          |
| 6    | flagField                        | 2 B  | UInteger16            | 标志位（详见 §4.6）                                                                                                                                 |
| 8    | correctionField                  | 8 B  | Integer64             | **校正面**，单位 2^-16 ns（即 scaled ns）。GM 发出的报文恒为 0；TC 在此累加驻留时间                                                                 |
| 16   | reserved                         | 4 B  | UInteger32            | 保留，置 0                                                                                                                                          |
| 20   | sourcePortIdentity.clockIdentity | 8 B  | OctetArray8           | 发送方时钟唯一标识（通常由本机 MAC 派生，FF-FF-FF-FF-FF-FF 禁止）                                                                                   |
| 28   | sourcePortIdentity.portNumber    | 2 B  | UInteger16            | 发送方端口号，本机 GM 固定配 1                                                                                                                      |
| 30   | sequenceId                       | 2 B  | UInteger16            | **序列号**，同种报文独立计数，16 位回绕；Slave 用它配对 Sync↔Follow_Up 和 Delay_Req↔Delay_Resp                                                      |
| 32   | controlField                     | 1 B  | UInteger8             | 消息类型标志：Sync=0x0, Delay_Req=0x1, Follow_Up=0x2, Delay_Resp=0x3, Announce=0x5                                                                  |
| 33   | logMessageInterval               | 1 B  | Integer8              | 该类报文发送间隔的对数（2^x 秒）。Sync=logSyncInterval, Announce=logAnnounceInterval；Delay_Resp 填 0x7F（不适用）                                  |

### 4.2 Announce 报文（总长 64 B = 34 头 + 30 body）

> **作用**：周期性宣告 GM 的存在与时钟质量，供下游执行 BMC（最佳主时钟算法）。本模块固定为 GM，`stepsRemoved=0`。

| 偏移 | 字段名                                          | 宽度 | 类型        | 作用                                                                                 | GM 发送取值        |
| ---- | ----------------------------------------------- | ---- | ----------- | ------------------------------------------------------------------------------------ | ------------------ |
| 34   | originTimestamp                                 | 10 B | Timestamp   | GM 发送本 Announce 时的本地时间戳（部分实现忽略，不用于对钟）                        | 发送时刻           |
| 44   | currentUtcOffset                                | 2 B  | Integer16   | PTP 时间与 UTC 的偏移秒数（闰秒累计）；G.8275.1 默认 0                               | 可配，默认 0       |
| 46   | reserved                                        | 1 B  | UInteger8   | 保留，置 0                                                                           | 0                  |
| 47   | grandmasterPriority1                            | 1 B  | UInteger8   | GM 优先级 1（BMC 首要比较键，值越小越优）                                            | 可配，默认 128     |
| 48   | grandmasterClockQuality.clockClass              | 1 B  | UInteger8   | 时钟等级。6=已锁定主参考；7=已锁定备用；52~58=保持；248=默认。软件 GM 未驯服可配 248 | 可配，默认 6       |
| 49   | grandmasterClockQuality.clockAccuracy           | 1 B  | UInteger8   | 时钟精度枚举。0x20~0x2F 为 ppm 级；0xFE=unknown（软件打戳建议）                      | 可配，默认 0x31    |
| 50   | grandmasterClockQuality.offsetScaledLogVariance | 2 B  | UInteger16  | 时钟稳定度指标（对数方差），软件 GM 默认 0xFFFF                                      | 可配，默认 0xFFFF  |
| 52   | grandmasterPriority2                            | 1 B  | UInteger8   | GM 优先级 2（BMC 次比较键）                                                          | 可配，默认 128     |
| 53   | grandmasterIdentity                             | 8 B  | OctetArray8 | GM 的 clockIdentity（= 本机时钟标识，与 sourcePortIdentity.clockIdentity 相同）      | 本机 clockIdentity |
| 61   | stepsRemoved                                    | 2 B  | UInteger16  | 距 GM 的跳数。**GM 恒为 0**                                                          | 0                  |
| 62   | timeSource                                      | 1 B  | UInteger8   | 时间源枚举：0x10=GPS, 0x20=TERRESTRIAL_RADIO, 0x48=INTERNAL_OSCILLATOR 等            | 可配，默认 0x48    |

**头字段取值**：messageType=0xB；controlField=0x5；logMessageInterval=logAnnounceInterval（G.8275.1 默认 -3，即 125 ms）；flagField 由 §4.6 决定。

### 4.3 Sync 报文（总长 44 B = 34 头 + 10 body）

> **作用**：携带 GM 时间基准，是 Slave 对钟的核心报文。一步法时 `originTimestamp` 即为精确发送时刻；两步法时该字段为近似值，精确值在后续 Follow_Up 中。

| 偏移 | 字段名          | 宽度 | 类型      | 作用                                                                                      | GM 发送取值 |
| ---- | --------------- | ---- | --------- | ----------------------------------------------------------------------------------------- | ----------- |
| 34   | originTimestamp | 10 B | Timestamp | Sync 的发送时刻（一步法为精确值；两步法为发送瞬间近似值，供诊断，Slave 实际用 Follow_Up） | 发送时刻 t1 |

**头字段取值**：
- messageType=0x0
- controlField=0x0
- logMessageInterval=logSyncInterval（G.8275.1 默认 -4，即 62.5 ms）
- sequenceId：Sync 独立计数器
- flagField.twoStepFlag：两步法=1，一步法=0
- correctionField：GM 恒为 0（TC 才会累加驻留时间）

### 4.4 Follow_Up 报文（总长 44 B = 34 头 + 10 body）

> **作用**：仅在两步法下使用，紧跟对应 Sync 发出，携带 Sync 的**精确发送时刻**（精确到软件打戳精度）。Slave 通过相同 sequenceId 将其与 Sync 配对。

| 偏移 | 字段名                 | 宽度 | 类型      | 作用                                                              | GM 发送取值    |
| ---- | ---------------------- | ---- | --------- | ----------------------------------------------------------------- | -------------- |
| 34   | preciseOriginTimestamp | 10 B | Timestamp | 对应 Sync 的精确发送时刻（发送原语返回后立即取的硬件/软件时间戳） | Sync 的精确 t1 |

**头字段取值**：
- messageType=0x8
- controlField=0x2
- logMessageInterval=logSyncInterval（与对应 Sync 相同）
- sequenceId：**必须等于对应 Sync 的 sequenceId**（Slave 靠此配对，不得错配）
- sourcePortIdentity：与 Sync 相同
- correctionField：GM 恒为 0
- flagField.twoStepFlag=1

### 4.5 Delay_Resp 报文（总长 54 B = 34 头 + 20 body）

> **作用**：GM 收到下游 Slave 的 Delay_Req 后回复，携带 GM 收到该 Delay_Req 的时刻 t2。Slave 结合自身发送时刻 t3 与 GM 的 t2、t4 计算 mean path delay = ((t4–t3) + (t2–t1)) / 2。

| 偏移 | 字段名                               | 宽度 | 类型        | 作用                                                                        | GM 发送取值      |
| ---- | ------------------------------------ | ---- | ----------- | --------------------------------------------------------------------------- | ---------------- |
| 34   | receiveTimestamp                     | 10 B | Timestamp   | GM 收到**对应 Delay_Req** 的接收时刻 t2（RX 线程第一时间取戳）              | t2               |
| 44   | requestingPortIdentity.clockIdentity | 8 B  | OctetArray8 | **回填** Delay_Req 头部 sourcePortIdentity.clockIdentity（Slave 的时钟 ID） | Delay_Req 中的值 |
| 52   | requestingPortIdentity.portNumber    | 2 B  | UInteger16  | **回填** Delay_Req 头部 sourcePortIdentity.portNumber                       | Delay_Req 中的值 |

**头字段取值**：
- messageType=0x9
- controlField=0x3
- logMessageInterval=0x7F（不适用）
- sequenceId：**必须等于对应 Delay_Req 的 sequenceId**（Slave 靠此匹配应答）
- sourcePortIdentity：本机 GM 端口
- correctionField：0（GM 不做驻留时间累加）
- flagField.unicastFlag：若单播回发则 1，组播回发则 0

### 4.6 flagField 位定义（公共头偏移 6，2 字节）

| 字节 | 位  | 适用报文                           | 名称                     | 作用                                          | 本模块取值                  |
| ---- | --- | ---------------------------------- | ------------------------ | --------------------------------------------- | --------------------------- |
| 0    | 0   | Announce/Sync/Follow_Up/Delay_Resp | alternateMasterFlag      | 备用主标志。源端口处于 MASTER 态时为 FALSE    | 0                           |
| 0    | 1   | Sync                               | twoStepFlag              | Sync 是否有对应 Follow_Up：两步法=1，一步法=0 | 两步法=1                    |
| 0    | 2   | ALL                                | unicastFlag              | 目的地址是单播=1，组播=0                      | Delay_Resp 单播时=1，其余 0 |
| 0    | 5   | ALL                                | PTP profile specific 1   | profile 自定义                                | G.8275.1 可配，默认 0       |
| 0    | 6   | ALL                                | PTP profile specific 2   | profile 自定义                                | G.8275.1 可配，默认 0       |
| 0    | 7   | ALL                                | reserved                 | 保留                                          | 0                           |
| 1    | 0   | Announce                           | leap61                   | 本月末将插入正闰秒                            | 可配，默认 0                |
| 1    | 1   | Announce                           | leap59                   | 本月末将插入负闰秒                            | 可配，默认 0                |
| 1    | 2   | Announce                           | currentUtcOffsetValid    | currentUtcOffset 字段是否有效                 | 可配，默认 0                |
| 1    | 3   | Announce                           | ptpTimescale             | 是否使用 PTP 时标（与 TAI 一致）              | 默认 1                      |
| 1    | 4   | Announce                           | timeTraceable            | 时间是否可溯源到主参考                        | 可配，默认 1                |
| 1    | 5   | Announce                           | frequencyTraceable       | 频率是否可溯源到主参考                        | 可配，默认 1                |
| 1    | 6   | Announce                           | synchronizationUncertain | 同步是否不确定（可选）                        | 默认 0                      |
| 1    | 7   | Announce                           | reserved                 | 保留                                          | 0                           |

### 4.7 二层封装

```
┌────────────┬────────────┬──────────────┬──────────────┬─────────────────────┐
│ Dst MAC    │ Src MAC    │ (VLAN tag)   │ EtherType    │ PTP Payload          │
│ 6 B        │ 6 B        │ 4 B 可选     │ = 0x88F7     │ 公共头 + body         │
└────────────┴────────────┴──────────────┴──────────────┴─────────────────────┘
```

| Profile                 | Announce/Sync/Follow_Up/Delay_Resp 目的 MAC | 说明                                        |
| ----------------------- | ------------------------------------------- | ------------------------------------------- |
| **G.8275.1**（默认）    | `01-80-C2-00-00-0E`                         | 桥驻留地址，不被普通网桥泛洪，供 TC/BC 处理 |
| **IEEE 1588-2008 通用** | `01-1B-19-00-00-00`                         | 标准 PTP 组播 MAC，普通交换机泛洪           |

- 源 MAC = 绑定网卡的实际 MAC（或可配）
- VLAN tag 可选；G.8275.1 通常在 VLAN 内走，PCP 建议配 6（时钟类）
- `messageLength` = PTP payload 长度（**不含**以太头与 VLAN tag）

### 4.8 默认参数集

| 参数                     | G.8275.1 默认                        | 1588v2 通用默认     | 说明                                |
| ------------------------ | ------------------------------------ | ------------------- | ----------------------------------- |
| `domainNumber`           | **43**（本项目指定；标准范围 24–43） | 0                   | 必须与 Slave 一致                   |
| `logAnnounceInterval`    | -3（125 ms）                         | 0（1 s）            |                                     |
| `announceReceiptTimeout` | 3                                    | 3                   | Slave 侧用，Master 仅作会话老化参考 |
| `logSyncInterval`        | -4（62.5 ms）                        | 0（1 s）            |                                     |
| `logMinDelayReqInterval` | -4                                   | -3                  | 通告给 Slave 的最小 Delay_Req 间隔  |
| `delay_mechanism`        | E2E                                  | E2E                 | 首版固定                            |
| `time_stamping`          | software                             | software            | 三期支持 hardware                   |
| `twoStepFlag`            | 1                                    | 1                   | 0 = 一步法                          |
| 目的 MAC                 | `01-80-C2-00-00-0E`                  | `01-1B-19-00-00-00` | profile 决定，可配覆盖              |

---

## 5. 软件行为设计

### 5.1 进程与线程模型

```
主线程            ── 配置加载、实例管理、信号处理、CLI/Web 服务
  │
  ├─ TX 线程 (ptp-l2-master-tx)
  │     绝对时间调度循环：算最近到期报文 → sleep → 发送 → 推进 next_deadline
  │     负责 Announce / Sync / Follow_Up
  │
  ├─ RX 线程 (ptp-l2-master-rx)
  │     select/recv 阻塞收帧 → 解析 → 过滤 → 打戳 → 投递
  │
  └─ RESP 线程 (ptp-l2-master-resp)
        从队列取 Delay_Req 上下文 → 组 Delay_Resp → 发送
        （与 RX 解耦，避免发送阻塞导致 t2 打戳偏移）
```

**行为要求**：
- RX 线程**收到帧后第一件事是取时间戳**（`clock_gettime` MONOTONIC_RAW + REALTIME 双取），再做任何解析，以压低 t2 抖动。
- Delay_Resp 生成走队列 + 独立线程，保证 RX 循环不被 socket 写阻塞拖慢。
- 三线程均为 daemon；主线程收到 SIGINT/SIGTERM 后按 §5.7 优雅退出。

### 5.2 状态机

```
   ┌──────────┐  start() 校验通过(权限/网卡/配置)
   │  INIT    ├────────────────────────────────┐
   └──────────┘                                ▼
      ▲  校验失败 ──► 抛错退出          ┌───────────────┐
                                       │  LISTENING    │ 尚未发过任何报文
                                       └───────┬───────┘
                          首个 Announce 已发出  │
                                               ▼
                                       ┌───────────────┐
                          ┌───────────►│  MASTER/ACTIVE│◄───────────┐
                          │            └───────┬───────┘            │
                          │                    │ 连续发送失败 ≥ N 次 │ 恢复
                          │                    ▼                    │
                          │            ┌───────────────┐            │
                          │            │  FAULT        │────────────┘
                          │            └───────┬───────┘ (重试成功)
                          │                    │ 超过重试上限
                          │                    ▼
                          │            ┌───────────────┐
                          └────────────┤  STOPPED      │◄── stop() / 信号
                                       └───────────────┘
```

- Master **不执行 BMC 选主**：配置即宣告为 GM，不参与"谁当主"的选举。
- 若收到对端 Announce（可能存在双主），行为可配：`ignore`（默认）/ `log_warning` / `enter_passive`（三期）。
- 网络故障（send 抛 `OSError`）→ 进入 FAULT，指数退避重试（1s/2s/4s…上限 30s），恢复后回 ACTIVE 并计数告警。

### 5.3 周期发送调度行为

**必须对齐绝对时间边界**（电信要求）：

```
interval = 2 ** logSyncInterval
next_sync = (floor(t_now / interval) + 1) * interval     # 对齐到 interval 的整数倍
```

- Announce 与 Sync **各自独立**的 `sequenceId` 计数器，从 0 开始，16 位回绕。
- 两步法：Sync 发出后**立即**取发送时刻 t1，随后在 `follow_up_gap`（默认 1 ms，可配 0–5 ms）后发 Follow_Up，`preciseOriginTimestamp = t1`，`sequenceId` 复用该 Sync 的。
- 若 Follow_Up 因调度延迟落后于下一个 Sync 的到期时间，**优先补发 Follow_Up**，Sync 顺延一个周期（不得错配 sequenceId）。
- 发送时刻若已超过 `next + interval/2`（严重超时/系统挂起恢复后），**丢弃该拍**，直接推进到下一边界，并记 `tx_skipped` 计数。

### 5.4 Delay_Req → Delay_Resp 处理流程

```
1. RX 线程收到帧
2. 取 t2 = 接收时刻（软件戳，尽量贴近网卡）
3. 解析 Ethernet 头：EtherType != 0x88F7 → 丢弃，计数 rx_not_ptp
4. 解析 PTPHeader：
     version_ptp != 2                → 丢弃，计数 rx_bad_version
     domain_number != 本机 domain    → 丢弃，计数 rx_other_domain
     message_type != DELAY_REQ       → 丢弃（Announce/Sync/Pdelay 等 Master 不处理）
5. 解析 DelayReqBody（originTimestamp，仅记录用于诊断，不参与计算）
6. 会话登记：key = header.sourcePortIdentity
     不存在 → 新建 SlaveSession(mac=帧 Src MAC, clockIdentity, portNumber)
     存在   → 刷新 last_seen
     会话数已达上限 → 拒绝新建，计数 session_overflow，丢弃
7. 限速检查：该 Slave 的 Delay_Resp 速率超过 delay_resp_rate_limit → 丢弃并计数
8. 入队 (t2, header, body, src_mac) → RESP 线程
9. RESP 线程组包：
     receiveTimestamp        = t2
     requestingPortIdentity  = header.sourceIdentity
     sequenceId              = header.sequenceId
     correctionField         = 0
     control                 = 0x03
     logMessageInterval      = 0x7F
     dst MAC                 = 组播地址（或 delay_resp_unicast=1 时用 src_mac）
10. 发送；成功 → 更新 session.delay_resp_sent、记录 tx 报文；失败 → 计数 tx_errors，不重试
```

**时间戳精度要求**：t2 必须在 RX 系统调用返回后**第一时间**取，禁止在取戳前做任何内存分配、锁竞争或日志 I/O。软件打戳下 t2 抖动典型 ±几十 µs，需在可观测中输出抖动统计。

### 5.5 Slave 会话管理

`SlaveSession` 字段：

| 字段                 | 类型         | 说明                                        |
| -------------------- | ------------ | ------------------------------------------- |
| `port_identity`      | PortIdentity | Slave 的 clockIdentity + portNumber（主键） |
| `src_mac`            | 6B           | 最近一次 Delay_Req 的源 MAC（单播回发用）   |
| `last_seen`          | float        | 最近收到 Delay_Req 的 MONOTONIC 时间戳      |
| `delay_req_count`    | int          | 累计收到的 Delay_Req 数                     |
| `delay_resp_sent`    | int          | 累计成功发出的 Delay_Resp 数                |
| `delay_resp_dropped` | int          | 因限速/队列满丢弃的数                       |

**行为**：
- 老化：`session_timeout = announceReceiptTimeout * 2**logAnnounceInterval * 2`（默认 3×0.125×2 = 0.75 s），超时未再收到 Delay_Req 则移除会话并记日志。
- 上限：`max_slaves` 可配（默认 64），超限按 FIFO 驱逐最旧会话。
- 限速：`delay_resp_rate_limit`（默认 256 pps/实例），令牌桶实现，超出丢弃。

### 5.6 时钟源抽象

```python
class ClockSource(Protocol):
    def now_realtime_ns(self) -> int: ...       # CLOCK_REALTIME ns
    def now_monotonic_ns(self) -> int: ...       # CLOCK_MONOTONIC_RAW ns
```

- 默认实现：`time.clock_gettime_ns(CLOCK_REALTIME)` / `CLOCK_MONOTONIC_RAW`。
- 扩展点：三期接入硬件 PHC（`/dev/ptp0` 的 `clock_gettime`）。
- GM 发出的所有时间戳（originTimestamp / preciseOriginTimestamp / receiveTimestamp）**全部来自同一时钟源**，避免 REALTIME 与 PHC 混用导致系统性偏差。

### 5.7 启动与停止

**启动** `start(cfg)`：
1. 校验配置（domain、interval 范围、网卡存在）
2. 检查权限（root / CAP_NET_RAW / Npcap）
3. 创建 L2 socket（AF_PACKET / Npcap handle），绑定网卡，设置混杂模式（抓组播帧）
4. 生成 clockIdentity（若未配）：取网卡 MAC + 0xFFFE 填充（IEEE EUI-64 转换）
5. 启动 RX → RESP → TX 线程（顺序保证 TX 启动时 RX/RESP 已就绪）
6. 状态 → LISTENING → 首个 Announce 发出后 → ACTIVE

**停止** `stop()`：
1. 置位 `stop_event`
2. TX 线程退出调度循环；RX 线程 socket 关闭/超时退出
3. RESP 线程 drain 队列（最多等 `drain_timeout`，默认 100 ms）后退出
4. 关闭 socket
5. 状态 → STOPPED

### 5.8 异常与降级

| 场景                                      | 行为                                                    |
| ----------------------------------------- | ------------------------------------------------------- |
| socket 发送 `OSError`（网卡 down/拥塞）   | 计数 `tx_errors`，进入 FAULT，指数退避重试              |
| 收到非法 PTP 帧（长度不足、版本错、域错） | 静默丢弃 + 对应错误计数，不影响主循环                   |
| RESP 队列满（Slave 风暴）                 | 新 Delay_Req 丢弃，计数 `resp_queue_full`               |
| 系统时间被外部调时（REALTIME 跳变）       | TX 调度基于 MONOTONIC，不受影响；时间戳字段会反映新时间 |
| 收到对端 Announce（双主）                 | 按 `foreign_master_behavior` 配置：ignore / log_warning |

---

## 6. 模块划分与接口（概要）

```
src/ptp_client/ptp/
├── l2master/                  ← 新包
│   ├── __init__.py
│   ├── transport.py           L2Transport: 原始以太网帧收发（AF_PACKET / Npcap）
│   ├── announce.py            Announce 编解码（header.py + 新增 AnnounceBody）
│   ├── clock.py               ClockSource 抽象与默认实现
│   ├── session.py             SlaveSession 表 / 老化 / 限速
│   ├── scheduler.py           周期发送调度（对齐绝对时间边界）
│   ├── responder.py           Delay_Resp 组包 + RESP 线程
│   ├── master.py              Master 主类：状态机 + 线程编排
│   ├── config.py              配置数据类 + Schema 校验
│   └── cli.py                 CLI 入口
└── ...
```

**关键类接口（设计态，待实现时定稿）**：

```python
@dataclass
class MasterConfig:
    interface: str
    domain_number: int = 43
    profile: Literal["g82751", "1588v2"] = "g82751"
    clock_identity: Optional[bytes] = None      # None 则由 MAC 派生
    priority1: int = 128
    priority2: int = 128
    clock_class: int = 6
    clock_accuracy: int = 0x31
    offset_scaled_log_variance: int = 0xFFFF
    log_announce_interval: int = -3
    log_sync_interval: int = -4
    two_step: bool = True
    vlan_id: Optional[int] = None
    vlan_pcp: int = 6
    dst_mac_override: Optional[bytes] = None
    delay_resp_unicast: bool = False
    max_slaves: int = 64
    delay_resp_rate_limit: int = 256


class PtpL2Master:
    def __init__(self, cfg: MasterConfig) -> None: ...
    def start(self) -> None: ...
    def stop(self) -> None: ...
    def get_stats(self) -> MasterStats: ...        # 指标快照
    def list_slaves(self) -> list[SlaveSession]: ...
```

---

## 7. 配置管理

配置文件 `config/ptp-l2-master.json`（JSONC）+ `config/ptp-l2-master.schema.json`（JSON Schema）。

**校验规则**（启动时强制）：
- `domain_number`：G.8275.1 范围 24–43；1588v2 范围 0–127
- `log_announce_interval`：G.8275.1 范围 -3 到 0；1588v2 范围 -3 到 1
- `log_sync_interval`：G.8275.1 范围 -7 到 -3；1588v2 范围 -7 到 1
- `interface`：必须存在且为以太网接口
- `clock_identity`：若提供必须为 16 hex 且非全 FF

CLI 可覆盖单个字段：`ptp-l2-master --iface eth0 --domain 43 --profile g82751`。

---

## 8. 可观测性

| 维度       | 内容                                                                                                                                                                 |
| ---------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 日志       | 分级（DEBUG/INFO/WARN/ERROR），带 domain、sequenceId、session 上下文；DEBUG 级记录每个报文的关键字段                                                                 |
| 计数器     | `announce_sent`, `sync_sent`, `follow_up_sent`, `delay_req_recv`, `delay_resp_sent`, `delay_resp_dropped`, `tx_errors`, `rx_bad_*`, `session_overflow`, `tx_skipped` |
| 状态查询   | `get_stats()` 返回所有计数器 + 当前状态机状态 + 运行时长                                                                                                             |
| Slave 列表 | `list_slaves()` 返回在线会话快照                                                                                                                                     |
| pcap 导出  | 复用 `ptp/pcap.py`（DLT_EN10MB），记录所有收发帧供 Wireshark 分析                                                                                                    |
| Web（P1）  | 控制台页面：启停 Master、实时报文流、Slave 列表、计数器图表                                                                                                          |

---

## 9. 验收与测试要点

### 9.1 单元测试

- Announce/Sync/Follow_Up/Delay_Resp 编解码：字段偏移、字节宽度、值正确性（含边界值）
- 公共头 pack/unpack 往返一致
- `sequenceId` 回绕逻辑
- 会话老化、限速、上限驱逐
- 配置 Schema 校验（合法/非法用例）

### 9.2 互通测试

- 对端 = `ptp4l`（G.8275.1 L2 slave 配置，domain 43）：验证 ptp4l 能锁定本 GM，offset 收敛
- 对端 = 本仓库自研 Slave（若支持 L2）
- Wireshark 抓包确认：EtherType=0x88F7、`messageLength` 正确、各字段值符合 §4
- 多 Slave 并发：N 个 ptp4l slave 同时锁定

### 9.3 验收标准

- 单 Slave 场景下，对端 ptp4l 进入 SLAVE 态且 offset 持续稳定（软件打戳典型 ±100 µs 内）
- 连续运行 1 小时无崩溃、无内存泄漏、计数准确
- Delay_Resp 应答延迟（收到 Delay_Req 到发出 Delay_Resp）< 5 ms（99 分位）

---

## 10. 风险与待决事项

| 项                 | 说明                                     | 处置                                             |
| ------------------ | ---------------------------------------- | ------------------------------------------------ |
| WSL2 L2 能力       | WSL2 默认 NAT 网络不支持原始 L2 收发     | 联调需 mirrored 模式或物理机/虚拟机              |
| 软件时间戳抖动     | 无硬件 PHC 时 t1/t2 抖动大，对钟精度受限 | 文档明确精度上限；三期引入硬件时间戳             |
| Windows Npcap 依赖 | 需用户手动安装 Npcap 并勾选 WinPcap 兼容 | 启动时检测并给出安装指引                         |
| 目的 MAC 与交换机  | `01-80-C2-00-00-0E` 在某些交换机上被过滤 | 提供 `dst_mac_override` 切到 `01-1B-19-00-00-00` |
| 双主检测           | 收到对端 Announce 如何处理               | 首版 ignore + log，三期支持 enter_passive        |

---

## 11. 文档修订记录

| 版本 | 日期       | 作者 | 变更说明                                                                  |
| ---- | ---------- | ---- | ------------------------------------------------------------------------- |
| V0.1 | 2026-09-13 | —    | 初稿：模块需求 + 四种报文完整字段表（Announce/Sync/Follow_Up/Delay_Resp） |

---

*本文档为需求+概要设计级，详细实现（各模块代码、Web 集成）在开发阶段展开。*
