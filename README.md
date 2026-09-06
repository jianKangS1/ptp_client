# PTP Client — 多协议时间同步客户端

> NTP / SNTP 客户端、PTPv2 G.8275.2 单播 ACR 客户端、Web 控制台实验室。
> 运行环境：Windows（PowerShell）+ Python 3.11+；联调对端可用 WSL 中的 linuxptp（ptp4l）。

---

## 1. 项目结构

```
ptp_client/
├── src/ptp_client/          # Python 包源码（src 布局）
│   ├── ntp/                 # NTP/SNTP 客户端：报文构造、交换、pcap 导出、CLI
│   ├── ptp/                 # PTPv2 客户端：Delay_Req/Resp、G.8275.2 Signalling 单播协商、ACR 测量、CLI
│   └── web/                 # FastAPI 应用 + 静态 UI（NTP / PTP ACR 两个页签）
├── config/                  # JSON 配置文件（含 JSON Schema）
│   ├── ntp-client.json
│   └── ptp-acr-client.json  # 允许 // 行注释与 /* */ 块注释（JSONC）
├── scripts/                 # PowerShell 启动/配置脚本 + WSL 辅助脚本
│   ├── start-ntp-client.ps1 / configure-ntp-client.ps1
│   ├── start-ptp-acr-client.ps1 / stop-ptp-acr-client.ps1 / configure-ptp-acr-client.ps1
│   ├── start-ntp-web.ps1
│   └── wsl/                 # WSL 内 ptp4l 单播 master/client 配置与安装脚本
├── tests/                   # pytest 单元测试（报文编解码、协商、续约、pcap 等）
├── docs/                    # 需求设计说明书、G.8275.2 架构文档、标准 PDF
└── .vscode/                 # tasks.json（一键任务）、launch.json（调试配置）
```

三个入口（见 `pyproject.toml` 的 `[project.scripts]`）：

| 命令 | 模块 | 功能 |
|------|------|------|
| `ntp-client` | `ptp_client.ntp.cli` | NTP 单次查询 |
| `ntp-web` | `ptp_client.web.app` | Web 控制台 |
| `ptp-acr-client` | `ptp_client.ptp.cli` | PTP ACR 客户端 |

未安装包时统一用 `python -m ptp_client.xxx` 并设置 `PYTHONPATH=src`（脚本已自动处理）。

---

## 2. 环境准备与安装

```powershell
# 在仓库根目录（e:\project\ptp_client）
# 安装 CLI + 开发依赖（pytest）
pip install -e ".[dev]"

# 安装 Web 依赖（fastapi、uvicorn）
pip install -e ".[web]"
```

对应 VS Code 任务：`NTP: 安装依赖 (pip editable)`、`Web: 安装依赖 (pip web)`。

---

## 3. NTP 客户端

### 3.1 直接命令行

```powershell
$env:PYTHONPATH = "e:\project\ptp_client\src"

# 最简用法：向服务器发一次 SNTP 查询，打印 offset / RTT / t1~t4
python -m ptp_client.ntp pool.ntp.org

# 常用参数
python -m ptp_client.ntp 192.168.1.1 --port 123 --timeout 5
```

可定制请求报文字段（RFC 5905 实验室用途），主要参数：

| 参数 | 说明 |
|------|------|
| `--port` / `--timeout` | UDP 端口（默认 123）/ 超时秒（默认 5） |
| `--leap` `--version` `--mode` `--stratum` `--poll` `--precision` | 头部各字段 |
| `--root-delay` `--root-dispersion` | 秒为单位的 NTP short 格式 |
| `--ref-id` | 4 个 ASCII 字符（如 `LOCL`）或 8 位十六进制（如 `47505300`） |
| `--origin-unix` 或 `--origin-ntp-sec/--origin-ntp-frac` | Origin 时间戳（二选一，省略=发送时刻） |
| `--ref-ts-sec/--ref-ts-frac` `--recv-ts-*` `--xmit-ts-*` | 其余三个时间戳 |

输出示例：`stratum / version / mode / leap`、`kiss_code`（如有）、`offset_seconds`、`rtt_seconds`、`t1(origin) t2(recv) t3(xmit) t4(dest)`。

### 3.2 配置文件 + 脚本启动

编辑 `config/ntp-client.json`：

```json
{
  "host": "pool.ntp.org",
  "port": 123,
  "timeout": 5.0,
  "extraArgs": []
}
```

`extraArgs` 中的字符串会原样追加到命令行（可放 3.1 表中任意参数）。

```powershell
# 校验/预览配置（不发网络请求，打印等效命令）
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\configure-ntp-client.ps1

# 读取配置并执行一次查询后退出
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\start-ntp-client.ps1
```

VS Code 任务：`NTP: 校验/预览配置`、`NTP: 命令行客户端（单次查询后退出）`。

---

## 4. PTP ACR 客户端（G.8275.2 单播）

模块：`python -m ptp_client.ptp <子命令>`，使用 UDP 事件端口 319 / 通用端口 320。

### 4.1 子命令一览

| 子命令 | 功能 |
|--------|------|
| `delay <master>` | 只发一次 Delay_Req，等待 Delay_Resp，打印 t3/t4 与报文摘要 |
| `estimate <master>` | 等待 Sync(+Follow_Up)，再做一次 Delay 交换，输出 offset 与 mean path delay |
| `build <type>` | 离线构造报文并打印十六进制（`delay_req/sync/follow_up/delay_resp`），不联网 |
| `g8275-negotiate <master>` | G.8275.2 Signalling REQUEST/GRANT 协商 Announce+Sync（可 `--cancel-after` 撤销） |
| `g8275-acr <master>` | 完整流程：协商 Announce+Sync → 周期 Delay_Req/Delay_Resp → 输出 offset/延迟估计 |

### 4.2 常用参数

```powershell
$env:PYTHONPATH = "e:\project\ptp_client\src"

# 例：与 WSL ptp4l GM 联调 ACR 测量
python -m ptp_client.ptp g8275-acr 172.19.173.58 `
  --domain 44 --bind 172.19.160.1 --bind-port 319 `
  --announce-log 0 --sync-log 0 --duration 60 --measure-duration 0 `
  --delay-req-interval 1.0 --sync-timeout 8 --delay-timeout 8
```

| 参数 | 说明 |
|------|------|
| `--domain` | PTP domainNumber（G.8275.2 默认 44，须与 GM 一致；G.8275.1 组播常用 24） |
| `--clock-identity` / `--port-number` | 本机 PortIdentity（16 位十六进制 / 端口号） |
| `--bind` / `--bind-port` | 本机绑定 IPv4；`319`=绑定 319/320 端口对（可能需管理员权限），`0`=双 ephemeral |
| `--transport unicast\|multicast` | `estimate`/`delay` 模式：单播连 GM，或加入 224.0.1.129 组播（G.8275.1） |
| `--announce-log` / `--sync-log` | Signalling 请求速率，间隔 = 2^n 秒（0=1/s，-3=8/s） |
| `--duration` | 单播合约 durationField 秒；到期前自动续约 |
| `--measure-duration` | Delay_Req 测量总时长，0=一直运行直到 Ctrl+C |
| `--delay-req-interval` | 客户端发 Delay_Req 间隔秒（本地策略，不写入报文），0=只发一次 |
| `--delay-req-flags` 等 `--delay-req-*` | 单独覆盖 Delay_Req 报文字段（flags、correction-ns、origin-sec/ns） |
| `--negotiate-delay-resp` / `--delay-resp-log` | 额外协商单播 Delay_Resp（lab 用） |
| `--cancel-after` | 测量完成后发送 CANCEL 拆除 |

退出码：`0` 成功；`1` 网络/协商/超时错误；`130` Ctrl+C 中断。

### 4.3 配置文件 + 脚本启动（推荐）

编辑 `config/ptp-acr-client.json`（带注释，JSONC 格式）。关键字段与 CLI 参数对应关系：

| 配置字段 | 对应 CLI | 说明 |
|----------|---------|------|
| `profile` | — | `g8275.2`→单播 domain 44；`g8275.1`→组播 domain 24 |
| `master` | 位置参数 | GM 的 IP；留空则脚本自动取 WSL eth0 地址 |
| `mode` | 子命令 | `g8275-acr` / `g8275-negotiate` / `estimate` / `delay` |
| `domain` / `bind` / `bindPort` | `--domain` / `--bind` / `--bind-port` | |
| `announceLogPeriod` / `syncLogPeriod` / `durationSec` / `measureDurationSec` | `--announce-log` 等 | |
| `syncTimeout` / `delayTimeout` / `delayTimeoutSingle` | `--sync-timeout` / `--delay-timeout` / `--timeout` | |
| `delayRequest.*` | `--delay-req-*` | 含 `requestIntervalSec` 发送间隔 |
| `extraArgs` | 原样追加 | 如 `["--negotiate-delay-resp", "--delay-resp-log", "0"]`、`["--cancel-after"]` |

```powershell
# 校验配置并打印等效 python 命令（不联网）
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\configure-ptp-acr-client.ps1

# 启动客户端（前台运行，Ctrl+C 停止并发送 CANCEL）
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\start-ptp-acr-client.ps1

# 清理残留的 python -m ptp_client.ptp 进程
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\stop-ptp-acr-client.ps1
```

VS Code 任务：`PTP ACR: 校验/预览配置`、`PTP ACR: 启动客户端…`、`PTP ACR: 停止客户端…`。
VS Code 调试（F5 面板）：`PTP ACR: estimate (调试)`、`PTP ACR: delay (调试)`、`PTP ACR: g8275-negotiate (调试)`，启动时会提示输入 master、domain、bind 等。

---

## 5. Web 控制台（NTP + PTP ACR 实验室）

```powershell
# 需先安装 Web 依赖：pip install -e ".[web]"
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\start-ntp-web.ps1
# 或： $env:PYTHONPATH="src"; python -m ptp_client.web
```

- 地址：<http://127.0.0.1:8765/>，`Ctrl+C` 停止。
- VS Code 任务：`Web: 启动控制台（NTP + PTP，http://127.0.0.1:8765）`（默认构建任务）。

页面两个页签：

- **NTP**：填写服务器与请求报文字段 →「发送并接收」；支持「从 JSON 加载并发送」「导出当前请求配置 JSON」；结果显示 offset/RTT/t1~t4、报文解析，并可「下载 .pcap」。
- **PTP ACR**：填写 GM/绑定/协商参数与 Delay_Req 字段 →「预览报文」（离线组包）或「运行 G8275 ACR」；结果表格 + 下载 PCAP；支持 JSON 编辑/导出。

REST API（供脚本或前端调用）：

| 方法 | 路径 | 功能 |
|------|------|------|
| GET | `/api/health` | 健康检查 |
| POST | `/api/ntp/exchange` | 发送自定义 NTP 请求并返回解析结果 + pcap(base64) |
| POST | `/api/ptp/build` | 离线构造 PTP 报文并返回 hex/字段摘要 |
| POST | `/api/ptp/g8275-acr/start` | 启动后台 G.8275.2 ACR 运行，返回 run_id（事件/通用端口固定 319/320） |
| GET | `/api/ptp/g8275-acr/poll?run_id&since` | 增量拉取报文（实时列表）+ 统计 + 估计，运行结束返回 PCAP |
| POST | `/api/ptp/g8275-acr/stop?run_id` | 停止运行：结束测量循环并向服务器发送 CANCEL |

---

## 6. WSL 中运行 ptp4l（搭建对端 GM / 参考从时钟）

详见 `scripts/wsl/COMMANDS.txt`。要点：

```bash
# WSL 内安装 linuxptp
sudo apt-get update && sudo apt-get install -y linuxptp

# 作为单播 master（GM）：编辑 ptp4l-unicast-master.conf 后
sudo ptp4l -i eth0 -f ./ptp4l-unicast-master.conf -m

# 作为单播 slave（与 Windows 自研客户端对比抓包）：
sudo ptp4l -i eth0 -f ./ptp4l-unicast-client.conf -m
```

- 配置位于 `scripts/wsl/`（WSL 路径 `/mnt/e/project/ptp_client/scripts/wsl/`），需把 `UDPv4` 改成 GM IP、`[eth0]` 节名与 `-i` 网卡名一致（`ip -br link` 查网卡）。
- `config/ptp-acr-client.json` 的 `master` 留空时，Windows 启动脚本会自动取 WSL eth0 的 IPv4。
- `scripts/wsl/install_python311_*.sh` 为 WSL 内安装 Python 3.11 的辅助脚本。

---

## 7. 运行测试

```powershell
# 仓库根目录（pyproject 已配置 testpaths=tests、pythonpath=src）
pytest
```

覆盖：NTP/PTP 报文编解码、pcap 构造、Delay_Req 规格解析、G.8275.2 Signalling 协商与续约逻辑。

---

## 8. 快速上手推荐流程

1. `pip install -e ".[dev]"`（+ Web 需要时 `pip install -e ".[web]"`）。
2. WSL 里用 `ptp4l-unicast-master.conf` 起一个 GM（或指向真实 GM 设备）。
3. 编辑 `config/ptp-acr-client.json`（`master`、`bind`、`domain`），先跑
   `scripts\configure-ptp-acr-client.ps1` 预览命令，确认无误后跑
   `scripts\start-ptp-acr-client.ps1` 观察 offset/延迟输出。
4. 需要可视化/抓包对比时启动 Web 控制台，在浏览器里操作并下载 PCAP。
5. NTP 功能改 `config/ntp-client.json` 后用 `start-ntp-client.ps1` 单次查询。
