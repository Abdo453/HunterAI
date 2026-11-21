---
name: "poshc2"
description: ">"
---

# Poshc2

*Sourced from killvxk-malskills-zh*

# PoshC2

支持代理的 C2 框架，植入体涵盖 PowerShell、C#、Python、C。

## 快速开始

```bash
curl -sSL https://raw.githubusercontent.com/nettitude/PoshC2/master/Install.sh | bash
posh-project -n MyOp
posh-server
posh
posh-payloads
```

## Handler REPL 命令

| 命令 | 用途 |
|------|------|
| `listimplants` | 显示活跃植入体 |
| `implant <id>` | 与植入体交互 |
| `run <cmd>` | 执行系统命令 |
| `loadmodule <module>` | 加载后渗透模块 |
| `inject-shellcode` | 向进程注入 shellcode |
| `invoke-mimikatz` | 运行 Mimikatz |
| `sharphound` | BloodHound 数据采集 |
| `get-system` | 尝试权限提升 |

## 资源

| 文件 | 加载时机 |
|------|----------|
| `references/` | 模块列表、代理配置、C 植入体用法 |

