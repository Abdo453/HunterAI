"""
LEDGER-KALI-01 — verify_kali_toolchain.py unit tests.

Simulates a Kali host (no network, no target contact) to prove the readiness
check correctly distinguishes READY / MISSING / UNHEALTHY for both local
binaries and Ollama models.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import patch

import yaml

from scripts.verify_kali_toolchain import probe, check_ollama_models, load_env_host, main


def _yaml_tools():
    return yaml.safe_load(Path("config/tools.yaml").read_text(encoding="utf-8"))


def test_probe_missing_binary():
    result = probe("definitely-not-installed-xyz", timeout=2.0)
    assert result["status"] == "MISSING"
    assert result["path"] is None


def test_ollama_models_available():
    payload = {"models": [
        {"name": "xploiter/pentester:latest"},
        {"name": "qwen2.5-coder:14b"},
        {"name": "WhiteRabbitNeo/Llama-3.1-WhiteRabbitNeo-2-8B:latest"},
    ]}
    with patch("subprocess.run") as m:
        m.return_value.returncode = 0
        m.return_value.stdout = json.dumps(payload)
        results = check_ollama_models("http://localhost:11434",
                                      ["xploiter/pentester:latest",
                                       "qwen2.5-coder:14b",
                                       "WhiteRabbitNeo/Llama-3.1-WhiteRabbitNeo-2-8B:latest"],
                                      timeout=5.0)
    assert all(r["status"] == "READY" for r in results), results


def test_ollama_model_missing():
    payload = {"models": [{"name": "some-other-model:latest"}]}
    with patch("subprocess.run") as m:
        m.return_value.returncode = 0
        m.return_value.stdout = json.dumps(payload)
        results = check_ollama_models("http://localhost:11434",
                                      ["xploiter/pentester:latest"], timeout=5.0)
    assert results[0]["status"] == "MISSING"
    assert "NOT PULLED" in results[0]["detail"]


def test_load_env_host_default(monkeypatch):
    monkeypatch.delenv("OLLAMA_HOST", raising=False)
    # .env.example exists; ensure default fallback works when no .env override.
    host = load_env_host()
    assert host == "http://localhost:11434"


def test_main_strict_exits_zero_when_all_ready(tmp_path, monkeypatch):
    """All configured tools READY + all Ollama models available -> exit 0."""
    tools_cfg = _yaml_tools()
    fake_paths = {spec["cmd"]: f"/usr/bin/{spec['cmd']}" for cat in tools_cfg.values()
                  if isinstance(cat, dict) for spec in cat.values()
                  if isinstance(spec, dict) and "cmd" in spec}

    def fake_which(binary):
        return fake_paths.get(binary)

    version_out = "tool version 1.2.3"

    def fake_run(cmd, **kwargs):
        class R:
            returncode = 0
            stdout = version_out
            stderr = ""
        return R()

    monkeypatch.setattr(sys, "argv", ["verify_kali_toolchain.py", "--strict", "--output", str(tmp_path / "report.json")])
    with patch("shutil.which", side_effect=fake_which), \
         patch("subprocess.run", side_effect=fake_run), \
         patch("scripts.verify_kali_toolchain.load_env_host", return_value="http://localhost:11434"), \
         patch("scripts.verify_kali_toolchain.check_ollama_models", return_value=[
             {"status": "READY", "binary": "ollama", "path": "http://localhost:11434",
              "name": "ollama:xploiter/pentester:latest",
              "detail": "model xploiter/pentester:latest available"},
             {"status": "READY", "binary": "ollama", "path": "http://localhost:11434",
              "name": "ollama:qwen2.5-coder:14b",
              "detail": "model qwen2.5-coder:14b available"},
             {"status": "READY", "binary": "ollama", "path": "http://localhost:11434",
              "name": "ollama:WhiteRabbitNeo/Llama-3.1-WhiteRabbitNeo-2-8B:latest",
              "detail": "model WhiteRabbitNeo/Llama-3.1-WhiteRabbitNeo-2-8B:latest available"},
         ]):
        rc = main()
    report = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))
    assert rc == 0
    assert report["summary"]["required_ready"] is True
    assert report["summary"]["MISSING"] == 0


def _fake_completed(*args, **kwargs):
    class R:
        returncode = 0
        stdout = "tool version 1.2.3"
        stderr = ""
    return R()


def test_main_strict_exits_nonzero_when_required_missing(tmp_path, monkeypatch):
    """A required tool MISSING -> exit 2 in strict mode."""
    monkeypatch.setattr(sys, "argv", ["verify_kali_toolchain.py", "--strict", "--output", str(tmp_path / "report2.json")])
    with patch("shutil.which", return_value=None), \
         patch("subprocess.run", side_effect=_fake_completed), \
         patch("scripts.verify_kali_toolchain.load_env_host", return_value="http://localhost:11434"), \
         patch("scripts.verify_kali_toolchain.check_ollama_models", return_value=[]):
        rc = main()
    assert rc == 2
    report = json.loads((tmp_path / "report2.json").read_text(encoding="utf-8"))
    assert report["summary"]["required_ready"] is False
