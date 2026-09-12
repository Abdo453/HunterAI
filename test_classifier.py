from orchestrator.task_classifier import TaskClassifier
tc = TaskClassifier()
tests = [
    ("write python tool to parse nmap output",              "CODING"),
    ("analyze this XSS vulnerability and exploit it",       "SECURITY"),
    ("build automated web recon tool finds security issues","MIXED"),
    ("explain what SQL injection is",                       "SECURITY"),
    ("fix this python function error",                      "CODING"),
    ("scan target with nmap and find vulnerabilities",      "SECURITY"),
]
ok = 0
for t, expected in tests:
    r = tc.classify(t)
    match = r.task_type.value == expected
    ok += 1 if match else 0
    status = "OK" if match else "!!"
    print(f"{status} [{r.task_type.value:8}] expected={expected} | {t[:45]}")
print(f"\nScore: {ok}/{len(tests)}")
