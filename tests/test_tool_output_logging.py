"""
Unit tests for Persistent Tool Output Logging (.txt files), NetworkTools Sanitization,
and WebTools Fallback Fuzzing.
"""
import os
import shutil
import tempfile
import pytest
from pathlib import Path

from tools.tool_manager import ToolManager, ToolResult
from tools.network_tools import NetworkTools
from tools.web_tools import WebTools


@pytest.fixture
def temp_output_dir():
    d = tempfile.mkdtemp(prefix="test_tool_out_")
    yield d
    shutil.rmtree(d, ignore_errors=True)


@pytest.mark.asyncio
async def test_tool_manager_save_output_to_txt(temp_output_dir):
    tm = ToolManager(output_dir=temp_output_dir)

    # Execute a simple echo command (available on all OSes)
    cmd = 'python -c "print(\'HELLOFROMTOOL\')"'
    res = await tm.execute(cmd)

    assert res.returncode == 0
    assert "HELLOFROMTOOL" in res.stdout
    assert res.output_file is not None
    assert os.path.isfile(res.output_file)
    assert res.output_file.endswith(".txt")

    # Verify file contents
    with open(res.output_file, "r", encoding="utf-8") as f:
        content = f.read()

    assert "PentestAI Tool Execution Log" in content
    assert "HELLOFROMTOOL" in content
    assert "SUCCESS" in content


@pytest.mark.asyncio
async def test_tool_manager_flexible_args(temp_output_dir):
    tm = ToolManager(output_dir=temp_output_dir)

    # Test passing args as list: execute("python", ["-c", "print('FLEXARGS')"])
    res = await tm.execute("python", ["-c", "print('FLEXARGS')"])

    assert res.returncode == 0
    assert "FLEXARGS" in res.stdout
    assert res.output_file is not None
    assert os.path.isfile(res.output_file)


def test_tool_manager_list_and_get_output(temp_output_dir):
    tm = ToolManager(output_dir=temp_output_dir)

    # Save manual output
    filepath = tm._save_tool_output("testtool", "testtool -u http://example.com", "SAMPLE_STDOUT", "SAMPLE_STDERR", 0, 1.23)
    assert filepath is not None
    assert os.path.isfile(filepath)

    files = tm.list_output_files()
    assert len(files) >= 1
    assert files[0]["filename"] == os.path.basename(filepath)

    content = tm.get_output_content(os.path.basename(filepath))
    assert content is not None
    assert "SAMPLE_STDOUT" in content
    assert "SAMPLE_STDERR" in content


def test_network_tools_host_cleaning():
    mgr = ToolManager()
    net = NetworkTools(mgr)

    # Test stripping URL scheme, paths, query, and port
    assert net._clean_host("http://example.com/test?id=1") == "example.com"
    assert net._clean_host("https://sub.domain.org:8443/admin") == "sub.domain.org"
    assert net._clean_host("192.168.1.50:8080") == "192.168.1.50"
    assert net._clean_host("scanme.nmap.org") == "scanme.nmap.org"


@pytest.mark.asyncio
async def test_web_tools_fallback_fuzzer(temp_output_dir):
    tm = ToolManager(output_dir=temp_output_dir)
    wt = WebTools(tm)

    # Test python_dir_fuzz with local mock target or fast run
    # Even if target is unreachable, it should complete without exception and return a ToolResult
    res = await wt.python_dir_fuzz("http://127.0.0.1:59999", wordlist=None)

    assert isinstance(res, ToolResult)
    assert res.tool == "gobuster"
    assert res.output_file is not None
    assert os.path.isfile(res.output_file)
