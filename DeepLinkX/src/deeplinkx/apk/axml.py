from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Any, Optional
from xml.sax.saxutils import escape, quoteattr

from ..errors import ApkError

RES_STRING_POOL = 0x0001
RES_XML = 0x0003
RES_XML_START_NS = 0x0100
RES_XML_END_NS = 0x0101
RES_XML_START_ELEMENT = 0x0102
RES_XML_END_ELEMENT = 0x0103
RES_XML_CDATA = 0x0104
RES_XML_RESOURCE_MAP = 0x0180

T_NULL = 0x00
T_REFERENCE = 0x01
T_ATTRIBUTE = 0x02
T_STRING = 0x03
T_FLOAT = 0x04
T_DIMENSION = 0x05
T_FRACTION = 0x06
T_INT_DEC = 0x10
T_INT_HEX = 0x11
T_BOOL = 0x12

ANDROID_NS = "http://schemas.android.com/apk/res/android"

# attribute resource ids from the framework, used when the name string is stripped
ANDROID_ATTR_IDS = {
    0x01010000: "theme", 0x01010001: "label", 0x01010002: "icon", 0x01010003: "name",
    0x01010004: "taskAffinity", 0x01010006: "permission", 0x01010007: "readPermission",
    0x01010008: "writePermission", 0x01010009: "protectionLevel", 0x0101000C: "hasCode",
    0x0101000E: "enabled", 0x0101000F: "debuggable", 0x01010010: "exported",
    0x01010011: "process", 0x01010018: "authorities", 0x0101001B: "grantUriPermissions",
    0x0101001C: "priority", 0x0101001D: "launchMode", 0x01010026: "mimeType",
    0x01010027: "scheme", 0x01010028: "host", 0x01010029: "port", 0x0101002A: "path",
    0x0101002B: "pathPrefix", 0x0101002C: "pathPattern", 0x01010202: "targetActivity",
    0x0101020C: "minSdkVersion", 0x0101021B: "versionCode", 0x0101021C: "versionName",
    0x01010270: "targetSdkVersion", 0x01010271: "maxSdkVersion", 0x01010272: "testOnly",
    0x01010280: "allowBackup", 0x0101028E: "required", 0x010104EA: "extractNativeLibs",
    0x010104EC: "usesCleartextTraffic", 0x010104EE: "autoVerify", 0x01010505: "directBootAware",
    0x01010527: "networkSecurityConfig", 0x01010572: "compileSdkVersion",
    0x01010603: "requestLegacyExternalStorage",
}


class Ref(int):
    """resource reference (@0x7f...)"""

    def __repr__(self) -> str:
        return f"@0x{int(self):08x}"

    __str__ = __repr__


@dataclass
class Attr:
    name: str
    ns: Optional[str]
    value: Any
    vtype: int
    res_id: Optional[int] = None


@dataclass
class Element:
    tag: str
    attrs: list[Attr] = field(default_factory=list)
    children: list["Element"] = field(default_factory=list)
    text: str = ""
    line: int = 0
    ns_decls: dict[str, str] = field(default_factory=dict)

    def get(self, name: str, default: Any = None) -> Any:
        for a in self.attrs:
            if a.name == name and a.ns in (ANDROID_NS, None, ""):
                return a.value
        for a in self.attrs:
            if a.name == name:
                return a.value
        return default

    def has(self, name: str) -> bool:
        return any(a.name == name for a in self.attrs)

    def iter(self, tag: Optional[str] = None):
        if tag is None or self.tag == tag:
            yield self
        for c in self.children:
            yield from c.iter(tag)

    def find(self, tag: str) -> Optional["Element"]:
        for c in self.children:
            if c.tag == tag:
                return c
        return None

    def findall(self, tag: str) -> list["Element"]:
        return [c for c in self.children if c.tag == tag]


class _Reader:
    __slots__ = ("data", "size")

    def __init__(self, data: bytes):
        self.data = data
        self.size = len(data)

    def u16(self, off: int) -> int:
        if off < 0 or off + 2 > self.size:
            raise ApkError("binary xml: read past end of data")
        return struct.unpack_from("<H", self.data, off)[0]

    def u32(self, off: int) -> int:
        if off < 0 or off + 4 > self.size:
            raise ApkError("binary xml: read past end of data")
        return struct.unpack_from("<I", self.data, off)[0]

    def i32(self, off: int) -> int:
        if off < 0 or off + 4 > self.size:
            raise ApkError("binary xml: read past end of data")
        return struct.unpack_from("<i", self.data, off)[0]


class StringPool:
    def __init__(self, data: bytes, start: int):
        r = _Reader(data)
        if r.u16(start) != RES_STRING_POOL:
            raise ApkError("string pool chunk expected")
        header_size = r.u16(start + 2)
        self.chunk_size = r.u32(start + 4)
        count = r.u32(start + 8)
        style_count = r.u32(start + 12)
        flags = r.u32(start + 16)
        strings_start = r.u32(start + 20)
        self.utf8 = bool(flags & (1 << 8))
        if count > 5_000_000 or start + self.chunk_size > len(data):
            raise ApkError("string pool is corrupt")
        offsets_at = start + header_size
        self._offsets = [r.u32(offsets_at + 4 * i) for i in range(count)]
        self._base = start + strings_start
        self._data = data
        self._cache: dict[int, str] = {}
        self.style_count = style_count

    def __len__(self) -> int:
        return len(self._offsets)

    def get(self, idx: int) -> Optional[str]:
        if idx is None or idx < 0 or idx >= len(self._offsets) or idx == 0xFFFFFFFF:
            return None
        cached = self._cache.get(idx)
        if cached is not None:
            return cached
        pos = self._base + self._offsets[idx]
        d = self._data
        if pos >= len(d):
            raise ApkError("string offset out of range")
        if self.utf8:
            n = d[pos]
            pos += 1
            if n & 0x80:
                n = ((n & 0x7F) << 8) | d[pos]
                pos += 1
            blen = d[pos]
            pos += 1
            if blen & 0x80:
                blen = ((blen & 0x7F) << 8) | d[pos]
                pos += 1
            raw = bytes(d[pos:pos + blen])
            value = raw.decode("utf-8", errors="replace")
        else:
            n = struct.unpack_from("<H", d, pos)[0]
            pos += 2
            if n & 0x8000:
                n = ((n & 0x7FFF) << 16) | struct.unpack_from("<H", d, pos)[0]
                pos += 2
            raw = bytes(d[pos:pos + n * 2])
            value = raw.decode("utf-16-le", errors="replace")
        self._cache[idx] = value
        return value


def is_binary_xml(data: bytes) -> bool:
    return len(data) >= 8 and struct.unpack_from("<HH", data, 0) == (RES_XML, 8)


def _value(r: _Reader, pool: StringPool, raw_idx: int, vtype: int, data: int) -> Any:
    if vtype == T_STRING:
        return pool.get(data if raw_idx == 0xFFFFFFFF else raw_idx) or ""
    if vtype == T_BOOL:
        return data != 0
    if vtype in (T_INT_DEC, T_INT_HEX):
        return struct.unpack("<i", struct.pack("<I", data))[0]
    if vtype in (T_REFERENCE, T_ATTRIBUTE):
        return Ref(data)
    if vtype == T_NULL:
        return None
    if vtype == T_FLOAT:
        return struct.unpack("<f", struct.pack("<I", data))[0]
    if 0x1C <= vtype <= 0x1F:
        return "#%08x" % data
    if vtype == T_DIMENSION or vtype == T_FRACTION:
        return "0x%x" % data
    return data


def parse_axml(data: bytes) -> Element:
    if not is_binary_xml(data):
        raise ApkError("not a binary android xml document")
    r = _Reader(data)
    total = min(r.u32(4), len(data))
    pos = 8
    pool: Optional[StringPool] = None
    res_map: list[int] = []
    ns_stack: list[tuple[str, str]] = []
    pending_ns: dict[str, str] = {}
    root: Optional[Element] = None
    stack: list[Element] = []

    while pos + 8 <= total:
        ctype = r.u16(pos)
        hsize = r.u16(pos + 2)
        csize = r.u32(pos + 4)
        if csize < 8 or pos + csize > len(data):
            raise ApkError("binary xml: chunk size is invalid")
        if ctype == RES_STRING_POOL:
            pool = StringPool(data, pos)
        elif ctype == RES_XML_RESOURCE_MAP:
            res_map = [r.u32(pos + hsize + 4 * i) for i in range((csize - hsize) // 4)]
        elif ctype == RES_XML_START_NS:
            if pool is None:
                raise ApkError("binary xml: namespace before string pool")
            prefix = pool.get(r.u32(pos + 16)) or ""
            uri = pool.get(r.u32(pos + 20)) or ""
            ns_stack.append((prefix, uri))
            pending_ns[prefix] = uri
        elif ctype == RES_XML_END_NS:
            if ns_stack:
                ns_stack.pop()
        elif ctype == RES_XML_START_ELEMENT:
            if pool is None:
                raise ApkError("binary xml: element before string pool")
            line = r.u32(pos + 8)
            base = pos + hsize
            name = pool.get(r.u32(base + 4)) or ""
            attr_start = r.u16(base + 8)
            attr_size = r.u16(base + 10)
            attr_count = r.u16(base + 12)
            el = Element(tag=name, line=line)
            if pending_ns:
                el.ns_decls = dict(pending_ns)
                pending_ns = {}
            if attr_size < 20:
                raise ApkError("binary xml: attribute size is invalid")
            a_at = base + attr_start
            for i in range(attr_count):
                o = a_at + i * attr_size
                ns_idx = r.u32(o)
                name_idx = r.u32(o + 4)
                raw_idx = r.u32(o + 8)
                vtype = data[o + 15] if o + 15 < len(data) else 0
                vdata = r.u32(o + 16)
                aname = pool.get(name_idx) or ""
                res_id = res_map[name_idx] if name_idx < len(res_map) else None
                if not aname and res_id is not None:
                    aname = ANDROID_ATTR_IDS.get(res_id, f"attr_0x{res_id:08x}")
                ns_uri = pool.get(ns_idx) if ns_idx != 0xFFFFFFFF else None
                el.attrs.append(Attr(aname, ns_uri, _value(r, pool, raw_idx, vtype, vdata), vtype, res_id))
            if stack:
                stack[-1].children.append(el)
            elif root is None:
                root = el
            stack.append(el)
        elif ctype == RES_XML_END_ELEMENT:
            if stack:
                stack.pop()
        elif ctype == RES_XML_CDATA:
            if pool is not None and stack:
                stack[-1].text += pool.get(r.u32(pos + 16)) or ""
        pos += csize
    if root is None:
        raise ApkError("binary xml: document has no root element")
    return root


def element_to_xml(root: Element, resolver=None) -> str:
    prefixes: dict[str, str] = {}

    def collect(e: Element):
        for p, u in e.ns_decls.items():
            prefixes.setdefault(u, p)
        for c in e.children:
            collect(c)

    collect(root)
    prefixes.setdefault(ANDROID_NS, "android")
    out: list[str] = ['<?xml version="1.0" encoding="utf-8"?>']

    def fmt(v: Any) -> str:
        if isinstance(v, bool):
            return "true" if v else "false"
        if isinstance(v, Ref):
            if resolver:
                n = resolver(v)
                if n:
                    return n
            return repr(v)
        return str(v)

    def emit(e: Element, depth: int):
        pad = "  " * depth
        parts = [f"{pad}<{e.tag}"]
        for p, u in e.ns_decls.items():
            parts.append(f"\n{pad}    xmlns:{p}={quoteattr(u)}")
        for a in e.attrs:
            pre = prefixes.get(a.ns or "", "")
            nm = f"{pre}:{a.name}" if pre else a.name
            parts.append(f"\n{pad}    {nm}={quoteattr(fmt(a.value))}")
        if not e.children and not e.text.strip():
            parts.append("/>")
            out.append("".join(parts))
            return
        parts.append(">")
        out.append("".join(parts))
        if e.text.strip():
            out.append(f"{pad}  {escape(e.text.strip())}")
        for c in e.children:
            emit(c, depth + 1)
        out.append(f"{pad}</{e.tag}>")

    emit(root, 0)
    return "\n".join(out) + "\n"
