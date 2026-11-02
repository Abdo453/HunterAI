"""
Security Package — نظام الصلاحيات والحماية للإيجنت
==================================================

يوفر إطار عمل كامل لتحديد الصلاحيات قبل التشغيل، مع رفض ذكي واضح
بدلاً من رفض عام متكرر.

المكونات:
  - PermissionMatrix: defining allowed/denied tools, ops, envs, users
  - PolicyEngine: evaluating requests against the matrix
  - ToolGateway: single bridge for all tool calls (check, log, rate-limit)
  - PreApproval: pre-approved scopes/tokens for repeated tasks
  - SandboxExecutor: isolated execution with limits
  - Verifier: result verification before delivery
  - UXMessages: clear refusal/approval messages
"""
from .permission_matrix import PermissionMatrix, PermissionDecision, ToolOp, EnvScope, UserRole
from .policy_engine import PolicyEngine, PolicyResult
from .tool_gateway import ToolGateway, GatewayResult
from .pre_approval import PreApprovalManager, PreApproval
from .sandbox_executor import SandboxExecutor, SandboxResult
from .verifier import Verifier, VerificationResult
from .ux_messages import UXMessages

__all__ = [
    "PermissionMatrix", "PermissionDecision", "ToolOp", "EnvScope", "UserRole",
    "PolicyEngine", "PolicyResult",
    "ToolGateway", "GatewayResult",
    "PreApprovalManager", "PreApproval",
    "SandboxExecutor", "SandboxResult",
    "Verifier", "VerificationResult",
    "UXMessages",
]
