"""
Smart Code Chunker
==================
Splits large JavaScript files into structural units (functions, classes, route defs, configs)
with cross-referencing, avoiding context overflow while preserving call relationships.
"""
import logging
import re
from typing import List

from core.code_intel.models import CodeChunk

logger = logging.getLogger("hunter_ai.code_intel.chunker")


class SmartCodeChunker:
    """Deconstructs JavaScript source into semantic chunks"""

    @classmethod
    def chunk_javascript(cls, code: str, file_path: str = "", max_chunk_lines: int = 150) -> List[CodeChunk]:
        chunks: List[CodeChunk] = []
        if not code.strip():
            return chunks

        lines = code.splitlines()
        total_lines = len(lines)

        # Regex patterns for structural boundaries
        fn_pattern = re.compile(r"^\s*(?:async\s+)?function\s+([a-zA-Z0-9_$]+)\s*\(", re.M)
        const_fn_pattern = re.compile(r"^\s*(?:const|let|var)\s+([a-zA-Z0-9_$]+)\s*=\s*(?:async\s*)?\([^)]*\)\s*=>", re.M)
        class_pattern = re.compile(r"^\s*class\s+([a-zA-Z0-9_$]+)", re.M)
        route_pattern = re.compile(r"(?:router|app)\.(get|post|put|delete|use)\s*\(\s*[\'\"]([^\'\"]+)[\'\"]", re.I)

        # 1. Look for explicit function/class definitions
        boundaries = []
        for idx, line in enumerate(lines):
            fn_m = fn_pattern.match(line)
            if fn_m:
                boundaries.append((idx, "function", fn_m.group(1)))
                continue
            cf_m = const_fn_pattern.match(line)
            if cf_m:
                boundaries.append((idx, "function", cf_m.group(1)))
                continue
            cl_m = class_pattern.match(line)
            if cl_m:
                boundaries.append((idx, "class", cl_m.group(1)))
                continue

        # If no explicit boundaries detected (e.g. minified script or inline script), use line window chunking
        if len(boundaries) == 0:
            step = max_chunk_lines
            for start in range(0, total_lines, step):
                end = min(start + step, total_lines)
                chunk_code = "\n".join(lines[start:end])
                calls = re.findall(r"([a-zA-Z0-9_$]+)\s*\(", chunk_code)
                unique_calls = list(dict.fromkeys(calls))[:15]
                chunks.append(CodeChunk(
                    file_path=file_path,
                    chunk_type="block",
                    name=f"block_{start+1}_{end}",
                    start_line=start + 1,
                    end_line=end,
                    code=chunk_code,
                    calls=unique_calls
                ))
            return chunks

        # Chunk based on detected boundaries
        for i, (start_idx, c_type, name) in enumerate(boundaries):
            end_idx = boundaries[i + 1][0] if i + 1 < len(boundaries) else total_lines
            if end_idx - start_idx > max_chunk_lines:
                end_idx = start_idx + max_chunk_lines

            chunk_code = "\n".join(lines[start_idx:end_idx])
            calls = re.findall(r"([a-zA-Z0-9_$]+)\s*\(", chunk_code)
            unique_calls = [c for c in dict.fromkeys(calls) if c != name][:15]

            chunks.append(CodeChunk(
                file_path=file_path,
                chunk_type=c_type,
                name=name,
                start_line=start_idx + 1,
                end_line=end_idx,
                code=chunk_code,
                calls=unique_calls
            ))

        return chunks