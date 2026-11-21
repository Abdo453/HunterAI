---
name: "wireshark"
description: ">"
---

# Wireshark

*Sourced from killvxk-malskills-zh*

# Wireshark / tshark

数据包捕获与协议分析工具。

## 快速开始（tshark CLI）

```bash
tshark -i eth0 -w capture.pcap
tshark -r capture.pcap -Y "http" -T fields -e http.host -e http.request.uri
tshark -r capture.pcap -Y "ntlmssp" -T fields -e ip.src -e ntlmssp.auth.username
```

## 常用显示过滤器

| 过滤器 | 用途 |
|--------|---------|
| `tcp.port == 445` | SMB 流量 |
| `http.request.method == "POST"` | POST 请求 |
| `ftp.request.command == "PASS"` | FTP 密码 |
| `ntlmssp` | NTLM 认证 |
| `kerberos` | Kerberos 流量 |
| `dns` | DNS 查询 |
| `ip.addr == 10.0.0.5` | 指定 IP 的收发流量 |

## 常用工作流

### 追踪 TCP 流
```bash
tshark -r capture.pcap -q -z follow,tcp,ascii,0
```

### 导出 HTTP 对象
Wireshark GUI：文件 → 导出对象 → HTTP

## 参考资源

| 文件 | 何时加载 |
|------|--------------|
| `references/` | 过滤器速查表及凭据提取模式 |

