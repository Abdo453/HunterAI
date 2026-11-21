#!/usr/bin/env bash
set -e

# 1. Tool aliases
which kube-hunter && ln -sf /usr/bin/kube-hunter /usr/local/bin/kube_hunter || true
which recon-ng && ln -sf /usr/bin/recon-ng /usr/local/bin/recon_ng || true
which vol && ln -sf /usr/bin/vol /usr/local/bin/volatility || true

# 2. SSRFmap from GitHub
if [ ! -d /opt/SSRFmap ]; then
    git clone --depth 1 https://github.com/swisskyrepo/SSRFmap /opt/SSRFmap || true
fi
if [ -f /opt/SSRFmap/ssrfmap.py ]; then
    ln -sf /opt/SSRFmap/ssrfmap.py /usr/local/bin/ssrfmap
    chmod +x /usr/local/bin/ssrfmap /opt/SSRFmap/ssrfmap.py || true
fi

# 3. crt.sh query tool
cat << 'EOF' > /usr/local/bin/crt.sh
#!/usr/bin/env bash
TARGET="$1"
curl -s "https://crt.sh/?q=%25.${TARGET}&output=json" | jq -r '.[].name_value' 2>/dev/null | sort -u
EOF
chmod +x /usr/local/bin/crt.sh

# 4. getjs fast extractor
cat << 'EOF' > /usr/local/bin/getjs
#!/usr/bin/env python3
import sys, re, urllib.request
if len(sys.argv) < 2:
    sys.exit(0)
url = sys.argv[1]
try:
    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
    with urllib.request.urlopen(req, timeout=10) as r:
        html = r.read().decode('utf-8', errors='ignore')
        for src in re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.I):
            print(src)
except Exception:
    pass
EOF
chmod +x /usr/local/bin/getjs

# 5. subzy downloader
if [ ! -f /usr/local/bin/subzy ]; then
    curl -sL https://github.com/LukaSikic/subzy/releases/download/v1.1.2/subzy_1.1.2_linux_amd64.tar.gz | tar -xz -C /usr/local/bin subzy 2>/dev/null || true
    chmod +x /usr/local/bin/subzy || true
fi

# 6. gospider downloader
if [ ! -f /usr/local/bin/gospider ]; then
    curl -sL https://github.com/jaeles-project/gospider/releases/download/v1.1.6/gospider_v1.1.6_linux_x86_64.zip -o /tmp/gospider.zip 2>/dev/null || true
    if [ -f /tmp/gospider.zip ]; then
        unzip -q -o /tmp/gospider.zip -d /tmp/gospider_unzip 2>/dev/null || true
        cp /tmp/gospider_unzip/gospider* /usr/local/bin/gospider 2>/dev/null || true
        chmod +x /usr/local/bin/gospider || true
        rm -rf /tmp/gospider.zip /tmp/gospider_unzip
    fi
fi

echo "INSTALLATION FINISHED"
