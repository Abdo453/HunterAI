"""
Exhaustive CLI Subparser and Alias Suite for PentestAI-Unified.
Tests every registered subcommand (all 88 subcommands) for valid parsing, argument binding,
flags resilience, and launcher alias consistency.
"""

import pytest
import pentest


@pytest.fixture
def parser():
    return pentest.build_parser()


def test_subparser_registry_count(parser):
    """Verify that all expected subcommands are registered in the CLI parser."""
    subparsers_action = None
    for action in parser._actions:
        if action.dest == "command":
            subparsers_action = action
            break

    assert subparsers_action is not None, "Subparser action 'command' not found on main parser"
    choices = subparsers_action.choices
    assert len(choices) >= 88, f"Expected at least 88 registered subcommands, got {len(choices)}"
    
    # Core master launchers and essential tools must exist
    essential_commands = [
        "all", "run", "web", "ui", "opencode", "opencode-ui",
        "wordlist", "seclists", "recon", "hunt", "validate", "report",
        "burp-logs", "poc-bundle", "verify", "safety-check", "lead-board"
    ]
    for cmd in essential_commands:
        assert cmd in choices, f"Essential command '{cmd}' missing from parser choices"


def test_exhaustive_all_88_subcommands_parse(parser):
    """Exhaustive test: Every single subparser parses valid synthetic input without error."""
    arg_map = {
        'all': ['example.com'],
        'arsenal': [],
        'arsenal-list': [],
        'autopilot': ['example.com'],
        'browse': ['https://example.com'],
        'burp-logs': ['dummy.xml'],
        'bypass-403': ['https://example.com/admin'],
        'chat': [],
        'cloud-recon': ['--keyword', 'mycorp'],
        'controller': ['status'],
        'cors': ['https://example.com'],
        'crlf': ['https://example.com'],
        'domxss': ['https://example.com'],
        'h': ['example.com'],
        'hunt': ['example.com'],
        'jwt-scan': ['eyJhbGciOiJIUzI1NiJ9.e30.dummy'],
        'kali-run': ['nmap', 'example.com'],
        'lead-board': ['show', 'example.com'],
        'llm-redteam': ['https://example.com/api/chat'],
        'mcp-serve': [],
        'memory-gc': [],
        'memory-read': ['working', 'example.com', 'last_scan'],
        'memory-read-triple': ['example.com', 'state'],
        'memory-stats': [],
        'memory-stats-triple': [],
        'memory-write': ['working', 'example.com', 'key', 'val'],
        'memory-write-triple': ['example.com', 'key', 'val'],
        'mitre-tree': [],
        'nosqli': ['https://example.com/user?id=1'],
        'omni': ['example.com'],
        'oob': ['example.com'],
        'opencode': ['example.com'],
        'opencode-ui': ['example.com'],
        'orchestrator-create': ['example.com', 'global_orchestrator', 'subdomain enum', 'T1595'],
        'orchestrator-export': [],
        'orchestrator-next': [],
        'orchestrator-stats': [],
        'param-discover': ['https://example.com/api'],
        'pickup': ['example.com'],
        'plan-difficulty': ['example.com', 'T1595'],
        'poc-bundle': ['example.com', 'xss', 'req.json'],
        'providers': [],
        'r': ['example.com'],
        'rag-hypothesis': ['example.com', '/login'],
        'rag-retrieve': ['sqli cheat sheet'],
        'recon': ['example.com'],
        'remember': ['example.com', 'found open port 8080'],
        'report': ['example.com', 'IDOR in profile update'],
        'run': ['example.com'],
        'safety-check': ['nmap -sV target.com', 'target.com'],
        'sast': ['.'],
        'scan-cves': ['192.168.1.1'],
        'scope': ['api.example.com'],
        'seclists': ['passwords'],
        'secrets-hunt': ['--js-bundle', '.'],
        'setup': [],
        'skills': [],
        'sniper': ['example.com'],
        'status': [],
        'surface': ['example.com'],
        'takeover': ['--recon', '.'],
        'task-graph': ['example.com', 'T1595'],
        'think': ['how to bypass cloudflare waf'],
        'token-scan': ['0x1234567890abcdef'],
        'tool-ai': ['nmap', 'example.com'],
        'triage': [],
        'triple-agent': ['example.com', 'T1595'],
        'ui': ['example.com'],
        'v': ['SQL injection in id param'],
        'validate': ['SQL injection in id param'],
        'verify': ['poc_dir'],
        'verify-sweep': ['tests/'],
        'waf-autowafuzzer': ['https://example.com'],
        'waf-bypass': ['https://example.com'],
        'waf-bypass-ladder': ['https://example.com', '<script>alert(1)</script>'],
        'waf-fingerprint': ['https://example.com', 'cloudflare'],
        'waf-gene-bank': ['https://example.com'],
        'waf-grant-approval': ['--tool', 'sqlmap'],
        'waf-padding': ['https://example.com', 'UNION SELECT 1'],
        'waf-parser-bug': ['https://example.com', 'payload'],
        'waf-protocol': ['https://example.com', 'grpc', 'payload'],
        'waf-rag-add': ['--waf', 'cloudflare', '--entries', 'test.json'],
        'waf-rag-status': [],
        'waf-rl-train': ['https://example.com'],
        'waf-semantic': ['https://example.com', 'SELECT *'],
        'web': ['example.com'],
        'web3-audit': ['contracts/Token.sol'],
        'wordlist': ['ai diverge']
    }

    subparsers_action = [a for a in parser._actions if a.dest == "command"][0]
    all_subcommands = set(subparsers_action.choices.keys())
    assert set(arg_map.keys()) == all_subcommands, f"Diff: {all_subcommands.symmetric_difference(arg_map.keys())}"

    for cmd, args in arg_map.items():
        parsed = parser.parse_args([cmd] + args)
        assert hasattr(parsed, "func"), f"Command '{cmd}' does not bind a target function"
        assert callable(parsed.func), f"Command '{cmd}' handler function is not callable"


def test_dual_launchers_and_alias_consistency(parser):
    """Verify alias parity between primary launchers and shortcuts."""
    # Web launcher and alias
    parsed_web = parser.parse_args(["web", "target.com", "--port", "9000"])
    assert parsed_web.command == "web"
    assert parsed_web.target == "target.com"
    assert parsed_web.port == 9000

    parsed_ui = parser.parse_args(["ui", "target.com", "--port", "9000"])
    assert parsed_ui.command == "ui"
    assert parsed_ui.target == "target.com"

    # OpenCode launcher and alias
    parsed_opencode = parser.parse_args(["opencode", "target.com", "--port", "8888"])
    assert parsed_opencode.command == "opencode"
    assert parsed_opencode.target == "target.com"
    assert parsed_opencode.port == 8888

    parsed_opencode_ui = parser.parse_args(["opencode-ui", "target.com", "--port", "8888"])
    assert parsed_opencode_ui.command == "opencode-ui"

    # Headless master flags
    parsed_all_web = parser.parse_args(["all", "target.com", "--web"])
    assert parsed_all_web.web is True
    assert parsed_all_web.opencode is False

    parsed_all_opencode = parser.parse_args(["all", "target.com", "--opencode"])
    assert parsed_all_opencode.opencode is True
    assert parsed_all_opencode.web is False

    # Wordlist and Seclists alias
    parsed_wordlist = parser.parse_args(["wordlist", "sqli", "--think"])
    assert parsed_wordlist.query == "sqli"
    assert parsed_wordlist.think is True

    parsed_seclists = parser.parse_args(["seclists", "ai_llm", "--profile", "deep"])
    assert parsed_seclists.query == "ai_llm"
    assert parsed_seclists.profile == "deep"


def test_cli_help_formatter_resilience(parser):
    """Ensure top-level help formatting renders cleanly without exception."""
    help_text = parser.format_help()
    assert "PentestAI" in help_text or "pentest.py" in help_text
    assert "web" in help_text
    assert "opencode" in help_text
    assert "wordlist" in help_text
