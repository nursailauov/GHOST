from __future__ import annotations

from dataclasses import dataclass
from typing import List, Sequence, Tuple


@dataclass
class _LengthDelimited:
    results: Sequence["_FieldResult"]


@dataclass
class _FieldResult:
    field: int
    wire_type: str
    data: object


class Parser:
    """Small protobuf wire-format parser compatible with this project usage."""

    def parse(self, data: str | bytes | bytearray) -> List[_FieldResult]:
        raw = self._to_bytes(data)
        results, _ = self._parse_message(raw, 0, len(raw))
        return results

    def _to_bytes(self, data: str | bytes | bytearray) -> bytes:
        if isinstance(data, str):
            value = data.strip()
            try:
                return bytes.fromhex(value)
            except ValueError:
                return value.encode("utf-8", errors="ignore")
        if isinstance(data, bytearray):
            return bytes(data)
        if isinstance(data, bytes):
            return data
        raise TypeError(f"Unsupported input type: {type(data)!r}")

    def _parse_message(self, raw: bytes, offset: int, end: int) -> Tuple[List[_FieldResult], int]:
        results: List[_FieldResult] = []
        pos = offset

        while pos < end:
            try:
                key, pos = self._read_varint(raw, pos, end)
            except ValueError:
                break
            field_number = key >> 3
            wire = key & 0x07
            if field_number == 0:
                break

            if wire == 0:  # varint
                value, pos = self._read_varint(raw, pos, end)
                results.append(_FieldResult(field=field_number, wire_type="varint", data=value))
            elif wire == 1:  # fixed64
                if pos + 8 > end:
                    break
                value = int.from_bytes(raw[pos : pos + 8], "little")
                pos += 8
                results.append(_FieldResult(field=field_number, wire_type="bytes", data=f"{value:016x}"))
            elif wire == 2:  # length-delimited
                length, pos = self._read_varint(raw, pos, end)
                if length < 0 or pos + length > end:
                    break
                payload = raw[pos : pos + length]
                pos += length

                nested_results = self._try_parse_nested(payload)
                if nested_results is not None:
                    results.append(
                        _FieldResult(
                            field=field_number,
                            wire_type="length_delimited",
                            data=_LengthDelimited(results=nested_results),
                        )
                    )
                    continue

                string_value = self._try_decode_string(payload)
                if string_value is not None:
                    results.append(_FieldResult(field=field_number, wire_type="string", data=string_value))
                else:
                    results.append(_FieldResult(field=field_number, wire_type="bytes", data=payload.hex()))
            elif wire == 5:  # fixed32
                if pos + 4 > end:
                    break
                value = int.from_bytes(raw[pos : pos + 4], "little")
                pos += 4
                results.append(_FieldResult(field=field_number, wire_type="bytes", data=f"{value:08x}"))
            else:
                break

        return results, pos

    def _try_parse_nested(self, payload: bytes) -> List[_FieldResult] | None:
        if not payload:
            return []
        nested, nested_end = self._parse_message(payload, 0, len(payload))
        if nested and nested_end == len(payload):
            return nested
        return None

    def _try_decode_string(self, payload: bytes) -> str | None:
        try:
            text = payload.decode("utf-8")
        except UnicodeDecodeError:
            return None

        if not text:
            return ""
        if any(ord(ch) < 32 and ch not in "\r\n\t" for ch in text):
            return None
        return text

    def _read_varint(self, raw: bytes, offset: int, end: int) -> Tuple[int, int]:
        shift = 0
        value = 0
        pos = offset

        while pos < end:
            b = raw[pos]
            pos += 1
            value |= (b & 0x7F) << shift
            if (b & 0x80) == 0:
                return value, pos
            shift += 7
            if shift >= 64:
                raise ValueError("Varint is too long")

        raise ValueError("Unexpected end while reading varint")
