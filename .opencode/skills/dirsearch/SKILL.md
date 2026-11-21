---
name: "dirsearch"
description: ">"
---

# Dirsearch

*Sourced from killvxk-malskills-zh*

# Dirsearch

Web 目录和文件暴力破解工具，支持递归、扩展名过滤和代理。

## 快速开始

```bash
pip install dirsearch

# 基础扫描
dirsearch -u https://target.com

# 指定扩展名
dirsearch -u https://target.com -e php,asp,aspx,bak,txt

# 递归扫描
dirsearch -u https://target.com -r

# 输出到文件
dirsearch -u https://target.com -o results.txt
```

## 核心参数

| 参数 | 说明 |
|------|---------|
| `-u URL` | 目标 URL |
| `-e EXT` | 扩展名（逗号分隔） |
| `-w FILE` | 自定义字典文件 |
| `-r` | 递归扫描 |
| `-R N` | 最大递归深度 |
| `-t N` | 线程数（默认：25） |
| `-x CODES` | 排除指定状态码 |
| `--proxy URL` | HTTP 代理 |
| `-o FILE` | 输出文件 |
| `--format FORMAT` | plain/json/xml/md |

## 常用工作流

**PHP 应用扫描（含备份文件）：**
```bash
dirsearch -u https://target.com -e php,bak,old,txt,zip -r -t 30
```

**排除 404 及噪声响应：**
```bash
dirsearch -u https://target.com -x 404,403,301
```

**API 路径发现：**
```bash
dirsearch -u https://api.target.com -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt
```

## 资源

| 文件 | 何时加载 |
|------|--------------|
| `references/` | 字典选择与递归深度调优 |

