---
name: "binwalk"
description: ">"
---

# Binwalk

*Sourced from killvxk-malskills-zh*

# Binwalk

固件分析与提取 — 从二进制 blob 中识别并提取嵌入文件。

## 快速开始

```bash
# Install
apt install binwalk

# Scan firmware for signatures
binwalk firmware.bin

# Extract all found content
binwalk -e firmware.bin
# Output in _firmware.bin.extracted/

# Recursive extraction
binwalk -eM firmware.bin
```

## 核心参数

| 参数 | 用途 |
|------|---------|
| `-e` | 提取找到的文件 |
| `-M` | 递归提取（俄罗斯套娃模式） |
| `-B` | 特征签名扫描（默认） |
| `-E` | 熵值分析 |
| `-A` | 反汇编 CPU 指令 |
| `-C DIR` | 输出目录 |
| `-q` | 静默模式 |
| `--dd TYPE:OFFSET:SIZE` | 手动提取 |
| `-l N` | 限制提取大小 |

## 常见工作流程

**完整固件分析：**
```bash
binwalk -eM firmware.bin -C ./extracted/
ls ./extracted/
```

**查找压缩/加密区域（熵值分析）：**
```bash
binwalk -E firmware.bin
# High entropy = encrypted/compressed, low = plaintext
```

**提取后查找硬编码字符串：**
```bash
binwalk -eM firmware.bin
find ./_firmware.bin.extracted/ -type f | xargs strings | grep -i "password\|admin\|key"
```

## 资源

| 文件 | 加载时机 |
|------|--------------|
| `references/` | 文件系统类型与 QEMU 模拟说明 |

