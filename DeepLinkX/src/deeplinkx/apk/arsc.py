from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Any, Optional

from ..errors import ApkError
from .axml import (
    RES_STRING_POOL, StringPool, T_ATTRIBUTE, T_BOOL, T_INT_DEC, T_INT_HEX, T_REFERENCE,
    T_STRING, Ref,
)

RES_TABLE = 0x0002
RES_TABLE_PACKAGE = 0x0200
RES_TABLE_TYPE = 0x0201
RES_TABLE_TYPE_SPEC = 0x0202

NO_ENTRY = 0xFFFFFFFF


@dataclass
class _Entry:
    name: str
    vtype: int
    data: int
    default_config: bool


class ResourceTable:
    def __init__(self, data: bytes):
        self._entries: dict[int, list[_Entry]] = {}
        self._type_names: dict[tuple[int, int], str] = {}
        self._global: Optional[StringPool] = None
        self._parse(data)

    def _parse(self, data: bytes) -> None:
        if len(data) < 12 or struct.unpack_from("<H", data, 0)[0] != RES_TABLE:
            raise ApkError("resources.arsc: bad table header")
        total = min(struct.unpack_from("<I", data, 4)[0], len(data))
        pos = struct.unpack_from("<H", data, 2)[0]
        while pos + 8 <= total:
            ctype, hsize, csize = struct.unpack_from("<HHI", data, pos)
            if csize < 8 or pos + csize > len(data):
                raise ApkError("resources.arsc: chunk size is invalid")
            if ctype == RES_STRING_POOL and self._global is None:
                self._global = StringPool(data, pos)
            elif ctype == RES_TABLE_PACKAGE:
                self._parse_package(data, pos, hsize, csize)
            pos += csize

    def _parse_package(self, data: bytes, start: int, hsize: int, size: int) -> None:
        pkg_id = struct.unpack_from("<I", data, start + 8)[0]
        type_strings_off = struct.unpack_from("<I", data, start + 8 + 4 + 256)[0]
        key_strings_off = struct.unpack_from("<I", data, start + 8 + 4 + 256 + 8)[0]
        type_pool = StringPool(data, start + type_strings_off) if type_strings_off else None
        key_pool = StringPool(data, start + key_strings_off) if key_strings_off else None
        pos = start + hsize
        end = start + size
        while pos + 8 <= end:
            ctype, ch, cs = struct.unpack_from("<HHI", data, pos)
            if cs < 8 or pos + cs > len(data):
                raise ApkError("resources.arsc: package chunk is invalid")
            if ctype == RES_TABLE_TYPE and key_pool is not None:
                self._parse_type(data, pos, ch, cs, pkg_id, type_pool, key_pool)
            pos += cs

    def _parse_type(self, data, start, hsize, size, pkg_id, type_pool, key_pool) -> None:
        type_id = data[start + 8]
        flags = data[start + 9]
        count = struct.unpack_from("<I", data, start + 12)[0]
        entries_start = struct.unpack_from("<I", data, start + 16)[0]
        config_size = struct.unpack_from("<I", data, start + 20)[0]
        cfg = data[start + 24:start + 20 + config_size] if config_size > 4 else b""
        default = not any(cfg)
        if type_pool is not None:
            self._type_names[(pkg_id, type_id)] = type_pool.get(type_id - 1) or ""
        offsets_at = start + hsize
        sparse = bool(flags & 0x01)
        offset16 = bool(flags & 0x02)
        if count > 2_000_000:
            raise ApkError("resources.arsc: type entry count is implausible")
        for i in range(count):
            if sparse:
                idx, off = struct.unpack_from("<HH", data, offsets_at + 4 * i)
                entry_off = off * 4
                entry_idx = idx
            elif offset16:
                raw = struct.unpack_from("<H", data, offsets_at + 2 * i)[0]
                if raw == 0xFFFF:
                    continue
                entry_off = raw * 4
                entry_idx = i
            else:
                entry_off = struct.unpack_from("<I", data, offsets_at + 4 * i)[0]
                if entry_off == NO_ENTRY:
                    continue
                entry_idx = i
            at = start + entries_start + entry_off
            if at + 8 > len(data):
                continue
            esize, eflags, key = struct.unpack_from("<HHI", data, at)
            if eflags & 0x0001 or eflags & 0x0008:
                continue
            vat = at + esize
            if vat + 8 > len(data):
                continue
            _vs, _r0, vtype, vdata = struct.unpack_from("<HBBI", data, vat)
            res_id = (pkg_id << 24) | (type_id << 16) | entry_idx
            self._entries.setdefault(res_id, []).append(
                _Entry(key_pool.get(key) or "", vtype, vdata, default)
            )

    def _pick(self, res_id: int) -> Optional[_Entry]:
        entries = self._entries.get(int(res_id))
        if not entries:
            return None
        for e in entries:
            if e.default_config:
                return e
        return entries[0]

    def name_of(self, res_id: int) -> Optional[str]:
        e = self._pick(res_id)
        if e is None:
            return None
        tname = self._type_names.get(((int(res_id) >> 24) & 0xFF, (int(res_id) >> 16) & 0xFF), "")
        return f"@{tname}/{e.name}" if tname else f"@{e.name}"

    def value_of(self, res_id: int, depth: int = 0) -> Any:
        e = self._pick(res_id)
        if e is None or depth > 8:
            return None
        if e.vtype == T_STRING:
            return self._global.get(e.data) if self._global else None
        if e.vtype == T_BOOL:
            return e.data != 0
        if e.vtype in (T_INT_DEC, T_INT_HEX):
            return struct.unpack("<i", struct.pack("<I", e.data))[0]
        if e.vtype in (T_REFERENCE, T_ATTRIBUTE):
            return self.value_of(e.data, depth + 1)
        return None

    def string_of(self, res_id: int) -> Optional[str]:
        v = self.value_of(res_id)
        return v if isinstance(v, str) else None

    def resolve(self, value: Any) -> Any:
        if isinstance(value, Ref):
            v = self.value_of(value)
            return value if v is None else v
        return value

    def __len__(self) -> int:
        return len(self._entries)
