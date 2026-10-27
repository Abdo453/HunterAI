"""
EKG-CG — Executable Knowledge Graph for Command Generation
============================================================
قاعدة معرفة الأوامر القابلة للتنفيذ. تمنع هلوسة الأوامر (Command Generation Hallucination)
بإجبار الوكيل على اختيار أوامر موثقة مسبقاً من سجل آمن، والتحقق من توافقها مع البيئة
قبل التنفيذ.

المكونات:
- CommandEntry: نموذج أمر واحد مع متطلباته البيئية ومستوى أمانه.
- CommandRegistry: سجل الأوامر الموثقة مع البحث والفلترة حسب الأداة والهدف والنوع.
- EnvironmentCompatibilityChecker: مفقق توافق البيئة قبل التنفيذ.
"""

from core.command_kb.models import CommandEntry, CommandSafetyLevel, CommandCategory
from core.command_kb.registry import CommandRegistry, bootstrap_command_kb
from core.command_kb.compatibility import EnvironmentCompatibilityChecker

__all__ = [
    "CommandEntry",
    "CommandSafetyLevel",
    "CommandCategory",
    "CommandRegistry",
    "bootstrap_command_kb",
    "EnvironmentCompatibilityChecker",
]
