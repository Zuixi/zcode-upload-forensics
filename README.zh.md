# zcode-upload-forensics

[English](./README.md) | 中文

[![CI](https://github.com/Zuixi/zcode-upload-forensics/actions/workflows/ci.yml/badge.svg)](https://github.com/Zuixi/zcode-upload-forensics/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](#运行环境)
[![No dependencies](https://img.shields.io/badge/dependencies-none-brightgreen.svg)](#运行环境)
[![Platforms](https://img.shields.io/badge/platforms-macOS%20%7C%20Linux%20%7C%20Windows-lightgrey.svg)](#运行环境)

一个 **agent skill**，用取证的方式回答一个问题：

> ZCode 桌面端是不是把我的工作区（**包括完整 Git 历史**）静默打包上传到了厂商对象存储？

它不是简单地找一下文件夹，而是读客户端自己写的状态账本、验证"已接受 ⇒ 已上传"这条代码级不变式、给出置信度、写明**什么条件会推翻结论**，最后渲染成一份**单文件 HTML 取证报告**——可以直接交给同事或合规。

```
$ python3 scripts/diagnose.py --out ./zcode-upload-report.html
verdict : UPLOADED（快照已成功上传至厂商 OSS）confidence=high
HTML    : /Users/you/zcode-upload-report.html
JSON    : /Users/you/zcode-upload-report.json
```

## 它回答什么

| 结论 | 含义 |
|---|---|
| **`UPLOADED`** | 至少有一次快照成功 POST 到厂商对象存储 |
| `PACKED_PENDING` | 已打包加密落盘，上传未确认（重试中） |
| `CAPTURED_NOT_ACCEPTED` | 有捕获产物，但没有"已接受"记录 |
| `INCONCLUSIVE` | 有痕迹但关键证据缺失——**不等于安全** |
| `NO_LOCAL_TRACE` | 该版本有这条链路，但本机没有捕获产物 |
| `FEATURE_ABSENT` | 该版本不含这条链路的代码签名 |

同时给出影响面：文件数、`.git/objects` 体积与占比、分支与 worktree、敏感路径命中、随包上传的全局配置。

## 安装

**1. Skills CLI**（Claude Code / Codex / Cursor / pi 等读 `SKILL.md` 的 harness）：

```bash
npx skills add Zuixi/zcode-upload-forensics
```

**2. Claude Code 插件市场**：

```
/plugin marketplace add Zuixi/zcode-upload-forensics
/plugin install zcode-upload-forensics@zcode-upload-forensics
```

**3. 手动 clone** 到任意 skills 目录：

```bash
git clone https://github.com/Zuixi/zcode-upload-forensics ~/.claude/skills/zcode-upload-forensics
# 或 ~/.pi/agent/skills/、~/.agents/skills/、项目级 .agents/skills/
```

**4. 完全不装 agent**，它本身就是个纯 Python 脚本：

```bash
git clone https://github.com/Zuixi/zcode-upload-forensics && cd zcode-upload-forensics
python3 scripts/diagnose.py --out ./report.html
```

## 快速开始

```bash
# 0) 先看它把每一条路径探测成了什么（无副作用，可核对）
python3 scripts/diagnose.py --list-paths

# 1) 只读采集 + 判定 + HTML 报告
python3 scripts/diagnose.py --out ./zcode-upload-report.html

# 2) 机读产物，用于变化监控（--diff 对比上次）
python3 scripts/diagnose.py --json ./report.json --diff ./previous.json

# 3) 需要外发时脱敏（路径/分支名/remote 主机名哈希化）
python3 scripts/diagnose.py --redact --out ./zcode-upload-report.redacted.html

# 4) 自检环境 / 回归本工具自身（全部用合成夹具，不触碰真实 ~/.zcode）
python3 scripts/selftest.py
```

报告语言跟随系统语言，可用 `--lang en` / `--lang zh` 强制。

装了 agent 的话，通常不用敲命令，直接说：

> "排查一下 zcode 是不是把我的代码上传了，给我诊断报告"

## 报告包含什么

1. 结论与依据（含置信度与 **falsifiers**：什么条件能推翻它）
2. 命中的真值表行
3. 逐工作区证据：`state.json` 字段、产物体积、时间戳、清单构成、Git 元数据、敏感路径命中、随包上传的全局配置
4. **路径探测依据**：每条路径 + 它是怎么被找到的 + 候选清单
5. 客户端代码签名扫描（含尝试过的候选载体与实际采信的那个）
6. 辅助痕迹（登录 token、工作区注册表、进程状态、阻断状态）
7. 证据时间线
8. 处置命令（绑定到实际探测到的路径）
9. 未能确定的部分与采集错误
10. 复现命令

## 它绝不做什么

- **不联网**：任何数据都不外发；
- **不解密**：本地密文无法解密，也不尝试；
- **不读工作区文件内容**：只读清单、配置与存在性/体积元数据；
- **不破坏证据**：包括加锁在内，任何东西都不删除；
- **不静默改系统**：加锁默认关闭，需显式确认，采用"隔离而非删除"，并用写探针自验证。

## 支持的客户端与平台

| | Windows | macOS | Linux |
|---|---|---|---|
| 数据目录探测 | ✅ 注册表 + 盘符扫描 | ✅ `~/.zcode` + bundle | ✅ 标准目录 + snap + WSL `/mnt/c` |
| 代码载体扫描（`app.asar` / host bundle） | ✅ 实测 3.11.2 | ✅ 实测 3.7.7 | ⚠️ 代码路径已有，未在真机执行 |
| 加锁 / 验证 / 恢复 | ✅ `icacls` 实测 | ✅ `chflags` 实测 | ⚠️ `chattr` 路径已有，未在真机执行 |

已验证的客户端版本：**3.11.2**（Windows）与 **3.7.7**（macOS）。其它版本由签名漂移检测兜底：签名对不上时，本地证据仍然成立，但置信度降级并给出告警，而不是瞎猜。

## 阻断后续上传

```bash
python3 scripts/diagnose.py --verify-lock    # 当前是否已阻断
python3 scripts/diagnose.py --apply-lock     # 隔离证据 → 加锁 → 写探针验证
python3 scripts/diagnose.py --unlock         # 可逆
```

锁的是客户端打包落盘的那个目录，从文件系统层切断第一步；代价是客户端的"检查点回滚"功能不可用。手工命令、验证探针与恢复方式见 [`references/platform-locks.md`](./references/platform-locks.md)。

**已经传出去的无法撤回。** 应轮换 Git 历史中出现过的凭据、复核 `.git/config` 里的内网 remote，报告最后一节列了具体步骤。

## 运行环境

- **Python 3.9+**，仅标准库，无需 `pip install`；
- macOS / Linux / Windows 均可（WSL 亦可，包括检查同一台机器的 Windows 侧）；
- 需要 ZCode 数据目录的读权限；加锁需要该目录的写权限（Linux `chattr` 需 `sudo`）。

## 相关项目

同类项目多走"检测 + 一键禁用"的脚本路线，本项目是围绕**可反驳判定 + 可审计报告**设计的 agent skill。需要企业级批量下发的话，下面几个值得一看：

- `Hansweek/zcode-snapshot-guard` —— 含 MDM / Intune / Ansible 批量自查
- `ChinaBots/zcode-snapshot-optout` —— 30 秒检测与一键禁用
- `TSOFTP-afk/zcode-snapshot-guard` —— 双防线（ACL 拒写 + 歼灭哨兵）
- `daidaiJ/zcode-snapshot-internals` —— 同一条链路的逆向笔记

## 贡献

见 [`CONTRIBUTING.md`](./CONTRIBUTING.md)。最有价值的贡献是**新增签名（客户端改版后代码移位）**与**新增载体（链路在不同平台换位置）**。任何改动都必须让 `scripts/selftest.py` 在三大平台全绿——CI 会跑矩阵。

## 免责声明

本项目是独立的取证工具，与智谱 / Z.ai 无任何关联，也未获其背书。关于客户端行为的描述基于对本机已安装版本的静态检查与客户端自身写入的状态文件；不同版本与平台的行为可能不同，这也是每条结论都附带置信度与反证条件的原因。请只在你拥有或获授权检查的机器上使用，并把生成的报告视为机密——它包含仓库路径、分支名与内部主机名。
