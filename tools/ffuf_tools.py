"""ffuf Tool Adapter — L1: واجهة تشغيل موحدة لـ ffuf مع مخرجات JSON منظمة"""
from __future__ import annotations

from typing import Optional, List
from tools.tool_manager import ToolManager, ToolResult


class FfufTools:
    """
    L1 Tool Adapter لـ ffuf.
    يشغل ffuf بخروج JSON (-o - -of json) ويُعيد ToolResult موحد.
    لا يعدل في الكود الأصلي للأداة؛ طبقة خارجية فقط.
    """

    def __init__(self, mgr: ToolManager):
        self.mgr = mgr

    def is_available(self) -> bool:
        return self.mgr.is_available("ffuf")

    async def run(
        self,
        url: str,
        wordlist: str,
        extensions: Optional[str] = None,
        filter_status: Optional[str] = None,
        filter_size: Optional[str] = None,
        filter_words: Optional[str] = None,
        rate_limit: int = 50,
        timeout: int = 300,
    ) -> ToolResult:
        """
        يشغل ffuf ضد الهدف مع كلمة مرور محددة.
        يرجع JSON عبر stdout (-o - -of json) لسهولةパרסينغ.
        """
        cmd_parts = [
            "ffuf",
            "-u", url,
            "-w", wordlist,
            "-o", "-",
            "-of", "json",
            "-rl", str(rate_limit),
        ]

        if extensions:
            cmd_parts += ["-e", extensions]
        if filter_status:
            cmd_parts += ["-fc", filter_status]
        if filter_size:
            cmd_parts += ["-fs", filter_size]
        if filter_words:
            cmd_parts += ["-fw", filter_words]

        cmd = " ".join(cmd_parts)
        return await self.mgr.execute(cmd, timeout=timeout)

    async def run_directory_brute(
        self,
        url: str,
        wordlist: str = "common.txt",
        **kwargs,
    ) -> ToolResult:
        """فخّ دليل افتراضي (directory brute force)."""
        return await self.run(url=url, wordlist=wordlist, **kwargs)
