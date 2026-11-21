---
name: "covenant"
description: ">"
---

# Covenant

*Sourced from killvxk-malskills-zh*

# Covenant

具有 Web 界面和 Grunt 植入物的协作型 .NET C2 框架。

## 快速开始

```bash
docker run -it -p 7443:7443 ghcr.io/cobbr/covenant
# or: dotnet run --project Covenant/Covenant.csproj
# Access: https://localhost:7443
```

## 核心概念

| 术语 | 含义 |
|------|---------|
| Grunt | 植入物 Agent |
| Listener | HTTP/HTTPS/SMB 监听端点 |
| Launcher | 有效载荷生成器（二进制、脚本等） |
| Task | 后渗透操作 |

## 常用任务

| 任务 | 用途 |
|------|---------|
| `Shell` | 运行 Shell 命令 |
| `Assembly` | 在内存中执行 .NET 程序集 |
| `PowerShell` | 运行 PowerShell 代码块 |
| `SharpHound` | 内置 BloodHound 数据收集 |
| `Mimikatz` | 凭据提取 (Credential Extraction) |
| `PortScan` | 内网端口扫描 |
| `Download / Upload` | 文件传输 |

## 参考资源

| 文件 | 加载时机 |
|------|--------------|
| `references/` | REST API 用法、自定义任务创建、SMB 链接 |

