from pathlib import Path

snippet = """
# Auto-detect Ollama Host
if curl -s -m 1 http://127.0.0.1:11434/api/version >/dev/null 2>&1; then
    export OLLAMA_HOST="http://127.0.0.1:11434"
elif curl -s -m 1 http://172.17.80.1:11434/api/version >/dev/null 2>&1; then
    export OLLAMA_HOST="http://172.17.80.1:11434"
fi
"""

for rc in [Path.home() / ".bashrc", Path.home() / ".zshrc"]:
    if rc.exists():
        t = rc.read_text(encoding="utf-8", errors="ignore")
        if "Auto-detect Ollama Host" not in t:
            rc.write_text(t + "\n" + snippet + "\n", encoding="utf-8")

print("Shell configs updated successfully.")
