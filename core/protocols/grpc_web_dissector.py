"""
HunterAI gRPC-Web & Protocol Buffer Wire Dissector (V13.0)
==========================================================
Dissects and audits gRPC and gRPC-Web binary streams:
1. Dynamic Protobuf Wire Dissector:
   - Decodes raw wire-format binary payloads without requiring original .proto files.
   - Parses Varint (0), Fixed64 (1), Length-Delimited string/bytes (2), and Fixed32 (5).
2. gRPC Authentication & Metadata Interceptor Auditor:
   - Verifies RPC method invocation authorization headers.
3. Information Disclosure in gRPC Error Trailers:
   - Analyzes `grpc-status` and `grpc-message` for internal stack traces and SQL leaks.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import unquote


class ProtobufWireType(IntEnum):
    VARINT = 0
    FIXED64 = 1
    LENGTH_DELIMITED = 2
    START_GROUP = 3  # Deprecated
    END_GROUP = 4    # Deprecated
    FIXED32 = 5


@dataclass
class ProtobufField:
    field_number: int
    wire_type: ProtobufWireType
    raw_bytes: bytes
    decoded_value: Any  # int, str, float, or nested dict

    def to_dict(self) -> Dict[str, Any]:
        return {
            "field_number": self.field_number,
            "wire_type": self.wire_type.name,
            "decoded_value": str(self.decoded_value),
        }


class ProtobufWireDissector:
    """
    Parses arbitrary Protocol Buffer binary byte streams dynamically
    without requiring access to pre-compiled .proto schema definitions.
    """

    @classmethod
    def decode_varint(cls, data: bytes, offset: int) -> Tuple[int, int]:
        """
        Decodes a protobuf variable-length integer (Varint).
        Returns (decoded_integer, new_offset).
        """
        res = 0
        shift = 0
        while offset < len(data):
            byte = data[offset]
            offset += 1
            res |= (byte & 0x7F) << shift
            if (byte & 0x80) == 0:
                break
            shift += 7
        return res, offset

    @classmethod
    def dissect(cls, data: bytes) -> List[ProtobufField]:
        """
        Decodes raw protobuf bytes into a list of structured fields.
        """
        # Handle gRPC 5-byte frame prefix (1-byte compressed flag + 4-byte big-endian message length)
        if len(data) >= 5 and data[0] in (0, 1):
            msg_len = struct.unpack(">I", data[1:5])[0]
            if 5 + msg_len <= len(data):
                data = data[5: 5 + msg_len]

        fields: List[ProtobufField] = []
        offset = 0
        total_len = len(data)

        while offset < total_len:
            try:
                tag, offset = cls.decode_varint(data, offset)
                wire_type_val = tag & 0x07
                field_number = tag >> 3

                if wire_type_val not in (0, 1, 2, 5):
                    # Unrecognized wire type or corruption
                    break

                wire_type = ProtobufWireType(wire_type_val)

                if wire_type == ProtobufWireType.VARINT:
                    val, offset = cls.decode_varint(data, offset)
                    fields.append(ProtobufField(
                        field_number=field_number,
                        wire_type=wire_type,
                        raw_bytes=b"",
                        decoded_value=val
                    ))

                elif wire_type == ProtobufWireType.FIXED64:
                    if offset + 8 > total_len:
                        break
                    raw = data[offset:offset + 8]
                    offset += 8
                    val = struct.unpack("<d", raw)[0]
                    fields.append(ProtobufField(
                        field_number=field_number,
                        wire_type=wire_type,
                        raw_bytes=raw,
                        decoded_value=val
                    ))

                elif wire_type == ProtobufWireType.LENGTH_DELIMITED:
                    length, offset = cls.decode_varint(data, offset)
                    if offset + length > total_len:
                        break
                    raw = data[offset:offset + length]
                    offset += length

                    # Attempt UTF-8 string decode, fallback to hex bytes
                    try:
                        decoded_str = raw.decode("utf-8")
                        # If string contains null bytes or unprintable chars, treat as bytes
                        if any(ord(c) < 32 and c not in ("\n", "\r", "\t") for c in decoded_str):
                            val = raw.hex()
                        else:
                            val = decoded_str
                    except Exception:
                        val = raw.hex()

                    fields.append(ProtobufField(
                        field_number=field_number,
                        wire_type=wire_type,
                        raw_bytes=raw,
                        decoded_value=val
                    ))

                elif wire_type == ProtobufWireType.FIXED32:
                    if offset + 4 > total_len:
                        break
                    raw = data[offset:offset + 4]
                    offset += 4
                    val = struct.unpack("<f", raw)[0]
                    fields.append(ProtobufField(
                        field_number=field_number,
                        wire_type=wire_type,
                        raw_bytes=raw,
                        decoded_value=val
                    ))

            except Exception:
                break

        return fields


class GRPCWebSecurityAuditor:
    """
    Audits gRPC and gRPC-Web request/response trailers for authorization and leaks.
    """

    SENSITIVE_RPC_PATTERNS = [
        "admin", "delete", "purge", "update_role", "transfer", "execute",
        "system", "config", "manage", "secret", "token", "password"
    ]

    LEAK_SIGNATURES = [
        "syntax error", "pg_query", "sqlstate", "traceback",
        "file \"", "exception in thread", "fatal error", "127.0.0.1", "10.0."
    ]

    @classmethod
    def audit_rpc_request(
        cls,
        rpc_method_path: str,
        headers: Dict[str, str],
        raw_protobuf_body: bytes
    ) -> Dict[str, Any]:
        """
        Audits an incoming or outgoing gRPC-Web RPC request.
        """
        headers_lower = {k.lower(): v for k, v in headers.items()}
        method_lower = rpc_method_path.lower()

        has_auth = any(k in headers_lower for k in ["authorization", "grpc-metadata-authorization", "x-api-key"])
        is_sensitive_method = any(p in method_lower for p in cls.SENSITIVE_RPC_PATTERNS)

        dissected_fields = ProtobufWireDissector.dissect(raw_protobuf_body)

        is_unauth_sensitive = is_sensitive_method and not has_auth

        return {
            "rpc_method": rpc_method_path,
            "has_authorization_metadata": has_auth,
            "is_sensitive_operation": is_sensitive_method,
            "is_unauthorized_hazard": is_unauth_sensitive,
            "risk_level": "HIGH" if is_unauth_sensitive else "LOW",
            "dissected_fields_count": len(dissected_fields),
            "dissected_fields": [f.to_dict() for f in dissected_fields],
            "recommendation": (
                "Implement a gRPC ServerInterceptor enforcing valid JWT credentials before invoking handler."
                if is_unauth_sensitive else "Metadata authorization present."
            )
        }

    @classmethod
    def audit_response_trailers(cls, trailers: Dict[str, str]) -> Dict[str, Any]:
        """
        Audits gRPC response trailers for status code errors and sensitive leaks.
        """
        trailers_lower = {k.lower(): v for k, v in trailers.items()}
        grpc_status = int(trailers_lower.get("grpc-status", "0"))
        grpc_message = unquote(trailers_lower.get("grpc-message", ""))

        leak_detected = any(sig in grpc_message.lower() for sig in cls.LEAK_SIGNATURES)

        return {
            "grpc_status": grpc_status,
            "grpc_message": grpc_message,
            "contains_internal_leak": leak_detected,
            "risk_level": "HIGH" if leak_detected else "LOW",
            "details": (
                f"Information Leak: gRPC error trailer exposes internal implementation details: '{grpc_message}'"
                if leak_detected else "Trailers sanitized."
            )
        }
