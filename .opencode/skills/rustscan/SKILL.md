---
name: "rustscan"
description: ">"
---

# Rustscan

*Sourced from killvxk-malskills-zh*

# RustScan

内置 nmap 流水线的快速端口扫描器。

## 快速开始

```bash
rustscan -a 10.10.10.5 -- -sV -sC
rustscan -a 10.10.10.5 -p 22,80,443,445 -- -A
rustscan -a 10.10.10.0/24 --ulimit 5000 -- -sV
```

## 核心参数

| 参数 | 用途 |
|------|------|
| `-a <addr>` | 目标 IP、CIDR 或主机名 |
| `-p <ports>` | 指定端口 |
| `--ulimit` | 文件描述符限制（越高越快） |
| `-b <batch>` | 同时探测的批次大小 |
| `-t <ms>` | 每个端口的超时时间（毫秒） |
| `--no-nmap` | 跳过 nmap，仅列出开放端口 |
| `-- <nmap flags>` | 直接传递给 nmap 的参数 |

## 常用工作流

### 完整服务扫描
```bash
rustscan -a 192.168.1.100 --ulimit 5000 -- -sV -sC -O
```

### 仅发现模式
```bash
rustscan -a 10.0.0.0/24 --no-nmap -b 1024 | tee open_ports.txt
```

## 资源文件

| 文件 | 加载时机 |
|------|----------|
| `references/` | 性能调优与 Docker 使用方法 |

