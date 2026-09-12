"""
URL & Parameter Normalizer for BurpAgent
Collapses dynamic UUIDs, integer IDs, and hashes into templated endpoint paths:
e.g. /api/v1/users/55 -> /api/v1/users/{id}
"""
import re
from typing import Tuple, List

class URLNormalizer:
    """توحيد مسارات الـ Endpoints لاستيعاب الخريطة الهيكلية لتطبيق الويب"""

    # Regex patterns for dynamic URL path parameters
    UUID_PATTERN = re.compile(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')
    HEX_HASH_PATTERN = re.compile(r'^[0-9a-fA-F]{24,64}$')
    INT_PATTERN = re.compile(r'^\d+$')

    @classmethod
    def normalize_path(cls, path: str) -> Tuple[str, List[str]]:
        """
        يحول: /api/users/102/orders/a1b2c3d4-e5f6-7890-1234-567890abcdef
        إلى: /api/users/{id}/orders/{uuid}
        """
        segments = [s for s in path.strip("/").split("/") if s]
        normalized_segments = []
        extracted_path_params = []

        for seg in segments:
            if cls.INT_PATTERN.match(seg):
                normalized_segments.append("{id}")
                extracted_path_params.append(seg)
            elif cls.UUID_PATTERN.match(seg):
                normalized_segments.append("{uuid}")
                extracted_path_params.append(seg)
            elif cls.HEX_HASH_PATTERN.match(seg):
                normalized_segments.append("{hash}")
                extracted_path_params.append(seg)
            else:
                normalized_segments.append(seg)

        norm_path = "/" + "/".join(normalized_segments)
        return norm_path, extracted_path_params

    @classmethod
    def get_endpoint_id(cls, method: str, host: str, path: str) -> str:
        norm_path, _ = cls.normalize_path(path)
        return f"{method.upper()} {host}{norm_path}"
