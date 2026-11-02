path = r"E:\Agant\PentestAI-Unified\pentest.py"
with open(path, 'r', encoding='utf-8') as f:
    content = f.read()

replacements = [
    ('add("waf-bypass", "تجاوز WAF باستخدام سلم المستويات", cmd_waf_bypass, [',
     'add("waf-bypass-ladder", "تجاوز WAF باستخدام سلم المستويات", cmd_waf_bypass, ['),
]

for old, new in replacements:
    if old in content:
        content = content.replace(old, new, 1)
        print("Replaced: " + old[:60] + "...")
    else:
        print("NOT FOUND: " + old[:60] + "...")

with open(path, 'w', encoding='utf-8') as f:
    f.write(content)
print("Done")
