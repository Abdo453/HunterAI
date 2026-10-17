"""
اختبارات سجل الأدوات المركب (core/tool_registry.py) — Phase B.
يختبر: التسجيل، رفض المجهول، التحقق من الوسائط، الإذن، التنفيذ الآمن (python محلي فقط)،
تدقيق الأحداث، إخفاء الأسرار. لا يستهدف أي نظام خارجي.
"""
import asyncio
import pytest

from core.tool_registry import (
    ToolDefinition, ToolResult, ToolError, ApprovalRequired, AuthContext,
    CliTool, ToolRegistry, RiskLevel,
)


def _echo_tool(executable="python"):
    definition = ToolDefinition(
        tool_id="echo.safe",
        name="safe echo",
        description="يطبع دليل عبر python محليًا فقط",
        backend="cli",
        executable=executable,
        allowed_executables=[executable],
        input_schema={
            "type": "object",
            "properties": {
                "text": {
                    "type": "string",
                    "cli_flag": "-c",
                    "cli_positional": True,
                },
                "times": {"type": "integer", "cli_flag": "--times", "enum": [1, 2]},
            },
            "required": ["text"],
        },
        required_permissions=["run_tool"],
        risk_level=RiskLevel.LOW,
        timeout_s=5.0,
        max_output_bytes=4096,
        approval_required=False,
        enabled=True,
        scope_relevant=False,
    )
    return RecordingCliTool(definition)


def _ctx(**overrides):
    base = dict(
        worker_id="w-1", worker_role="analyst",
        granted_permissions=["run_tool"],
        in_scope_targets=["example"],
        out_of_scope_targets=[],
        approve_high_risk=False,
    )
    base.update(overrides)
    return AuthContext(**base)


class RecordingCliTool(CliTool):
    """أداة اختبار تُعيد نتيجة وهمية آمنة (لا subprocess فعلي)."""
    def __init__(self, definition, should_fail=False):
        super().__init__(definition)
        self.executed_with = []
        self.should_fail = should_fail

    async def execute(self, arguments, ctx):
        self.executed_with.append((arguments, ctx))
        if self.should_fail:
            return ToolResult(ok=False, tool_id=self.defn.tool_id,
                              error="boom", error_category="EXECUTION_ERROR")
        text = arguments.get("text", "")
        return ToolResult(ok=True, tool_id=self.defn.tool_id,
                          output=f"echo: {text}",
                          raw_output=f"echo: {text}",
                          exit_code=0)


class TestRegistryRegistration:
    def test_register_and_get(self):
        reg = ToolRegistry()
        reg.register(_echo_tool())
        tool = reg.get("echo.safe")
        assert tool is not None
        assert tool.describe().tool_id == "echo.safe"

    def test_require_unknown_raises(self):
        reg = ToolRegistry()
        with pytest.raises(ToolError, match="غير مسجّلة"):
            reg.require("no.such.tool")

    def test_list_enabled_only(self):
        reg = ToolRegistry()
        reg.register(_echo_tool())
        names = [d.tool_id for d in reg.list_tools(enabled_only=True)]
        assert "echo.safe" in names


class TestInputValidation:
    def test_missing_required(self):
        reg = ToolRegistry()
        reg.register(_echo_tool())
        tool = reg.require("echo.safe")
        with pytest.raises(ToolError, match="مطلوب"):
            tool.validate_input({})

    def test_unknown_key(self):
        reg = ToolRegistry()
        reg.register(_echo_tool())
        tool = reg.require("echo.safe")
        with pytest.raises(ToolError, match="غير معروف"):
            tool.validate_input({"text": "hi", "nope": 1})

    def test_wrong_type(self):
        reg = ToolRegistry()
        reg.register(_echo_tool())
        tool = reg.require("echo.safe")
        with pytest.raises(ToolError, match="نوع"):
            tool.validate_input({"text": 123})

    def test_enum_violation(self):
        reg = ToolRegistry()
        reg.register(_echo_tool())
        tool = reg.require("echo.safe")
        with pytest.raises(ToolError, match="غير مسموحة"):
            tool.validate_input({"text": "hi", "times": 9})


class TestAuthorization:
    def test_missing_permission(self):
        reg = ToolRegistry()
        reg.register(_echo_tool())
        tool = reg.require("echo.safe")
        ctx = _ctx(granted_permissions=[])
        with pytest.raises(ToolError, match="الإذن"):
            tool.authorize(ctx, {"text": "hi"})

    def test_out_of_scope(self):
        definition = ToolDefinition(
            tool_id="net.scan", name="net scan",
            description="", backend="cli", executable="python",
            allowed_executables=["python"],
            input_schema={"type": "object",
                          "properties": {"target": {"type": "string"}},
                          "required": ["target"]},
            required_permissions=["run_tool"],
            risk_level=RiskLevel.LOW,
            scope_relevant=True,
        )
        tool = CliTool(definition)
        ctx = _ctx(in_scope_targets=["example"],
                   out_of_scope_targets=[])
        # "evil.other.com" خارج نطاق "example" completely
        with pytest.raises(ToolError, match="خارج النطاق"):
            tool.authorize(ctx, {"target": "evil.other.com"})

    def test_high_risk_requires_approval(self):
        definition = ToolDefinition(
            tool_id="danger.cmd", name="danger",
            description="", backend="cli", executable="python",
            allowed_executables=["python"],
            input_schema={"type": "object", "properties": {}, "required": []},
            required_permissions=["run_tool"],
            risk_level=RiskLevel.HIGH,
        )
        tool = CliTool(definition)
        ctx = _ctx(approve_high_risk=False)
        with pytest.raises(ApprovalRequired):
            tool.authorize(ctx, {})

        ctx2 = _ctx(approve_high_risk=True)
        tool.authorize(ctx2, {})  # لا يُرفع استثناء عند الموافقة


class TestExecution:
    @pytest.mark.asyncio
    async def test_safe_python_executes(self):
        reg = ToolRegistry()
        reg.register(_echo_tool())
        ctx = _ctx()
        result = await reg.call_tool(
            "echo.safe", {"text": "hello world"}, ctx)
        assert result.ok is True
        assert "hello world" in result.output

    @pytest.mark.asyncio
    async def test_unknown_tool_call_raised(self):
        reg = ToolRegistry()
        ctx = _ctx()
        with pytest.raises(ToolError, match="غير مسجّلة"):
            await reg.call_tool("no.such.tool", {}, ctx)

    @pytest.mark.asyncio
    async def test_disabled_tool_raised(self):
        reg = ToolRegistry()
        tool = _echo_tool()
        tool.defn = ToolDefinition(
            tool_id="echo.safe", name="safe echo", description="",
            backend="cli", executable="python", allowed_executables=["python"],
            input_schema={"type": "object", "properties": {},
                          "required": []},
            enabled=False,
        )
        reg.register(tool)
        ctx = _ctx()
        with pytest.raises(ToolError, match="معطلة"):
            await reg.call_tool("echo.safe", {}, ctx)

    @pytest.mark.asyncio
    async def test_approval_required_flow(self):
        reg = ToolRegistry()
        definition = ToolDefinition(
            tool_id="danger.cmd", name="danger",
            description="", backend="cli", executable="python",
            allowed_executables=["python"],
            input_schema={"type": "object", "properties": {}, "required": []},
            required_permissions=["run_tool"],
            risk_level=RiskLevel.HIGH,
            approval_required=True,
        )
        reg.register(RecordingCliTool(definition))
        ctx = _ctx(approve_high_risk=False)
        approved = []

        async def handler(tid, op):
            approved.append((tid, op))
            return True

        # بدون معالج موافقة → يُرفع استثناء (الرسالة بالإنجليزية في الكود)
        with pytest.raises(ToolError, match="human approval required"):
            await reg.call_tool("danger.cmd", {}, ctx)

        # مع معالج يوافق → يُنفّذ
        result = await reg.call_tool("danger.cmd", {}, ctx, approval_handler=handler)
        assert result.ok is True
        assert approved == [("danger.cmd", "danger")]

    @pytest.mark.asyncio
    async def test_audit_log_recorded(self):
        reg = ToolRegistry()
        reg.register(_echo_tool())
        ctx = _ctx()
        await reg.call_tool("echo.safe", {"text": "audit me"}, ctx)
        logs = reg.audit_log()
        assert len(logs) >= 1
        assert any(l["event"] == "executed" for l in logs)

    @pytest.mark.asyncio
    async def test_secret_redaction_in_output(self):
        reg = ToolRegistry()
        reg.register(_echo_tool())
        ctx = _ctx()
        result = await reg.call_tool(
            "echo.safe", {"text": "token sk-abcdef123456 here"}, ctx)
        assert result.ok is True
        assert "sk-abcdef123456" not in result.output
        assert "***" in result.output


class TestArgvBuilding:
    def test_positional_argv_no_shell_string(self):
        reg = ToolRegistry()
        reg.register(_echo_tool())
        tool = reg.require("echo.safe")
        argv = tool._build_argv({"text": "hello world", "times": 1})
        assert argv[0] == "python"
        assert "-c" in argv
        assert "hello world" in argv
        assert argv.index("-c") < argv.index("hello world")
        joined = " ".join(argv)
        assert "&&" not in joined
        assert ";" not in joined

    def test_flag_argv(self):
        reg = ToolRegistry()
        reg.register(_echo_tool())
        tool = reg.require("echo.safe")
        argv = tool._build_argv({"text": "x", "times": 2})
        assert "--times" in argv
        assert "2" in argv
