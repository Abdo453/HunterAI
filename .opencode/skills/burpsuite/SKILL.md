---
name: "burpsuite"
description: ">"
---

# Burpsuite

*Sourced from killvxk-malskills-zh*

# Burp Suite

Web 应用安全测试平台。

## 快速开始

```bash
burpsuite
# Set browser proxy: 127.0.0.1:8080
# Install CA cert: browse to http://burp while proxied
```

## 核心工具

| 工具 | 用途 |
|------|-----|
| **Proxy** | 拦截 / 修改 HTTP/S 流量 |
| **Repeater** | 重放并修改单个请求 |
| **Intruder** | 自动化模糊测试 / 暴力破解 |
| **Scanner** | 主动/被动漏洞检测（专业版） |
| **Decoder** | URL、Base64、十六进制编解码 |
| **Comparer** | 对比两个 HTTP 响应的差异 |
| **Extender** | 加载 BApp 插件 |

## 快捷键

| 快捷键 | 操作 |
|----------|--------|
| `Ctrl+R` | 发送到 Repeater |
| `Ctrl+I` | 发送到 Intruder |
| `Ctrl+F` | 转发已拦截的请求 |
| `Ctrl+Z` | 丢弃请求 |

## 常见工作流程

### SQLi 手工检测
1. 捕获请求 → Repeater（`Ctrl+R`）
2. 修改参数值，观察响应差异

### Intruder 暴力破解
1. 捕获请求 → Intruder → 用 `§` 标记插入位置
2. 加载字典 → 开始攻击

## 资源

| 文件 | 加载时机 |
|------|--------------|
| `references/` | BApp 推荐、匹配替换规则、扫描配置 |

