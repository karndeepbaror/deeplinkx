"""Minimal but complete DEX reader.

Reads the id tables, class definitions and class data and walks every method's
bytecode with the Dalvik opcode width table to collect invoke targets,
const-string values and type references. No decompilation is attempted.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Iterator, Optional

from ..errors import ApkError

NO_INDEX = 0xFFFFFFFF
ENDIAN_TAG = 0x12345678


def _build_widths() -> bytes:
    w = bytearray([1] * 256)

    def setr(lo: int, hi: int, n: int) -> None:
        for i in range(lo, hi + 1):
            w[i] = n

    setr(0x00, 0x00, 1)
    w[0x01], w[0x02], w[0x03] = 1, 2, 3
    w[0x04], w[0x05], w[0x06] = 1, 2, 3
    w[0x07], w[0x08], w[0x09] = 1, 2, 3
    setr(0x0A, 0x11, 1)
    w[0x12] = 1
    w[0x13] = 2
    w[0x14] = 3
    w[0x15] = 2
    w[0x16] = 2
    w[0x17] = 3
    w[0x18] = 5
    w[0x19] = 2
    w[0x1A] = 2
    w[0x1B] = 3
    w[0x1C] = 2
    w[0x1D] = w[0x1E] = 1
    w[0x1F] = w[0x20] = 2
    w[0x21] = 1
    w[0x22] = w[0x23] = 2
    w[0x24] = w[0x25] = w[0x26] = 3
    w[0x27] = w[0x28] = 1
    w[0x29] = 2
    w[0x2A] = 3
    w[0x2B] = w[0x2C] = 3
    setr(0x2D, 0x31, 2)
    setr(0x32, 0x3D, 2)
    setr(0x3E, 0x43, 1)
    setr(0x44, 0x6D, 2)
    setr(0x6E, 0x72, 3)
    w[0x73] = 1
    setr(0x74, 0x78, 3)
    w[0x79] = w[0x7A] = 1
    setr(0x7B, 0x8F, 1)
    setr(0x90, 0xAF, 2)
    setr(0xB0, 0xCF, 1)
    setr(0xD0, 0xE2, 2)
    setr(0xE3, 0xF9, 1)
    w[0xFA] = w[0xFB] = 4
    w[0xFC] = w[0xFD] = 3
    w[0xFE] = w[0xFF] = 2
    return bytes(w)


WIDTHS = _build_widths()
INVOKE_OPS = frozenset(list(range(0x6E, 0x73)) + list(range(0x74, 0x79)) + [0xFA, 0xFB])
INVOKE_NAMES = {
    0x6E: "virtual", 0x6F: "super", 0x70: "direct", 0x71: "static", 0x72: "interface",
    0x74: "virtual/range", 0x75: "super/range", 0x76: "direct/range", 0x77: "static/range",
    0x78: "interface/range", 0xFA: "polymorphic", 0xFB: "polymorphic/range",
}


def decode_mutf8(raw: bytes) -> str:
    raw = raw.replace(b"\xc0\x80", b"\x00")
    s = raw.decode("utf-8", "surrogatepass")
    if any("\ud800" <= ch <= "\udfff" for ch in s):
        try:
            s = s.encode("utf-16-le", "surrogatepass").decode("utf-16-le", "replace")
        except UnicodeError:
            s = s.encode("utf-8", "replace").decode("utf-8", "replace")
    return s


def descriptor_to_name(desc: str) -> str:
    """Lcom/foo/Bar; -> com.foo.Bar"""
    if desc.startswith("L") and desc.endswith(";"):
        return desc[1:-1].replace("/", ".")
    return desc.replace("/", ".")


@dataclass
class MethodRef:
    cls: str
    name: str
    desc: str

    @property
    def sig(self) -> str:
        return f"{self.cls}->{self.name}{self.desc}"

    @property
    def class_name(self) -> str:
        return descriptor_to_name(self.cls)


@dataclass
class Method:
    ref: MethodRef
    access: int
    code_off: int
    invokes: list[tuple[int, MethodRef]] = field(default_factory=list)
    strings: list[str] = field(default_factory=list)
    new_instances: list[str] = field(default_factory=list)
    insn_count: int = 0

    @property
    def name(self) -> str:
        return self.ref.name


@dataclass
class ClassInfo:
    name: str  # dotted
    descriptor: str
    access: int
    superclass: Optional[str]
    interfaces: list[str]
    source_file: Optional[str]
    methods: list[Method] = field(default_factory=list)

    def method(self, name: str) -> list[Method]:
        return [m for m in self.methods if m.name == name]


class _Cursor:
    __slots__ = ("d", "p")

    def __init__(self, d: bytes, p: int):
        self.d = d
        self.p = p

    def uleb(self) -> int:
        result = 0
        shift = 0
        d = self.d
        p = self.p
        while True:
            b = d[p]
            p += 1
            result |= (b & 0x7F) << shift
            if not b & 0x80:
                break
            shift += 7
            if shift > 35:
                raise ApkError("dex: bad uleb128")
        self.p = p
        return result


class Dex:
    def __init__(self, data: bytes, name: str = "classes.dex"):
        self.name = name
        self.data = data
        self.bad_classes = 0
        if len(data) < 0x70 or data[:4] != b"dex\n":
            raise ApkError(f"{name}: not a dex file")
        (self.file_size, self.header_size, endian) = struct.unpack_from("<III", data, 32)
        if endian != ENDIAN_TAG:
            raise ApkError(f"{name}: unsupported endianness")
        if self.header_size < 0x70:
            raise ApkError(f"{name}: bad header size")
        self.version = data[4:7].decode("ascii", "replace")
        (self.string_ids_size, self.string_ids_off, self.type_ids_size, self.type_ids_off,
         self.proto_ids_size, self.proto_ids_off, self.field_ids_size, self.field_ids_off,
         self.method_ids_size, self.method_ids_off, self.class_defs_size,
         self.class_defs_off) = struct.unpack_from("<12I", data, 56)
        for label, off, n, sz in (
            ("string_ids", self.string_ids_off, self.string_ids_size, 4),
            ("type_ids", self.type_ids_off, self.type_ids_size, 4),
            ("proto_ids", self.proto_ids_off, self.proto_ids_size, 12),
            ("field_ids", self.field_ids_off, self.field_ids_size, 8),
            ("method_ids", self.method_ids_off, self.method_ids_size, 8),
            ("class_defs", self.class_defs_off, self.class_defs_size, 32),
        ):
            if n and off + n * sz > len(data):
                raise ApkError(f"{name}: {label} table is out of range")
        self._str_cache: dict[int, str] = {}
        self._type_cache: dict[int, str] = {}
        self._method_cache: dict[int, MethodRef] = {}
        self._proto_cache: dict[int, str] = {}

    # ----- tables -----
    def string(self, idx: int) -> str:
        s = self._str_cache.get(idx)
        if s is not None:
            return s
        if idx >= self.string_ids_size:
            raise ApkError("dex: string index out of range")
        off = struct.unpack_from("<I", self.data, self.string_ids_off + 4 * idx)[0]
        cur = _Cursor(self.data, off)
        cur.uleb()
        end = self.data.find(b"\x00", cur.p)
        if end < 0:
            raise ApkError("dex: unterminated string")
        s = decode_mutf8(self.data[cur.p:end])
        self._str_cache[idx] = s
        return s

    def strings(self) -> Iterator[str]:
        for i in range(self.string_ids_size):
            try:
                yield self.string(i)
            except ApkError:
                continue

    def type(self, idx: int) -> str:
        t = self._type_cache.get(idx)
        if t is None:
            if idx >= self.type_ids_size:
                raise ApkError("dex: type index out of range")
            sidx = struct.unpack_from("<I", self.data, self.type_ids_off + 4 * idx)[0]
            t = self.string(sidx)
            self._type_cache[idx] = t
        return t

    def proto(self, idx: int) -> str:
        p = self._proto_cache.get(idx)
        if p is None:
            if idx >= self.proto_ids_size:
                raise ApkError("dex: proto index out of range")
            _shorty, ret, params_off = struct.unpack_from("<III", self.data, self.proto_ids_off + 12 * idx)
            params = ""
            if params_off:
                n = struct.unpack_from("<I", self.data, params_off)[0]
                if n > 255:
                    raise ApkError("dex: too many parameters")
                for i in range(n):
                    t = struct.unpack_from("<H", self.data, params_off + 4 + 2 * i)[0]
                    params += self.type(t)
            p = f"({params}){self.type(ret)}"
            self._proto_cache[idx] = p
        return p

    def method_ref(self, idx: int) -> MethodRef:
        m = self._method_cache.get(idx)
        if m is None:
            if idx >= self.method_ids_size:
                raise ApkError("dex: method index out of range")
            cls, proto, name = struct.unpack_from("<HHI", self.data, self.method_ids_off + 8 * idx)
            m = MethodRef(self.type(cls), self.string(name), self.proto(proto))
            self._method_cache[idx] = m
        return m

    def field_ref(self, idx: int) -> tuple[str, str, str]:
        if idx >= self.field_ids_size:
            raise ApkError("dex: field index out of range")
        cls, typ, name = struct.unpack_from("<HHI", self.data, self.field_ids_off + 8 * idx)
        return self.type(cls), self.string(name), self.type(typ)

    # ----- classes -----
    def class_descriptors(self) -> list[str]:
        out = []
        for i in range(self.class_defs_size):
            cidx = struct.unpack_from("<I", self.data, self.class_defs_off + 32 * i)[0]
            try:
                out.append(self.type(cidx))
            except ApkError:
                continue
        return out

    def classes(self, with_code: bool = True, only: Optional[set[str]] = None) -> Iterator[ClassInfo]:
        """Iterate class definitions. `only` is a set of dotted names."""
        for i in range(self.class_defs_size):
            try:
                info = self._class_at(i, with_code, only)
            except (ApkError, struct.error, IndexError, UnicodeError):
                self.bad_classes += 1
                continue
            if info is not None:
                yield info

    def _class_at(self, i: int, with_code: bool, only: Optional[set[str]]) -> Optional[ClassInfo]:
        d = self.data
        (cidx, access, sup, ifaces_off, src, _ann, cdata_off, _sv) = struct.unpack_from(
            "<8I", d, self.class_defs_off + 32 * i)
        desc = self.type(cidx)
        name = descriptor_to_name(desc)
        if only is not None and name not in only:
            return None
        interfaces: list[str] = []
        if ifaces_off:
            n = struct.unpack_from("<I", d, ifaces_off)[0]
            for k in range(min(n, 512)):
                interfaces.append(descriptor_to_name(
                    self.type(struct.unpack_from("<H", d, ifaces_off + 4 + 2 * k)[0])))
        info = ClassInfo(
            name=name, descriptor=desc, access=access,
            superclass=descriptor_to_name(self.type(sup)) if sup != NO_INDEX else None,
            interfaces=interfaces,
            source_file=self.string(src) if src != NO_INDEX else None,
        )
        if cdata_off:
            cur = _Cursor(d, cdata_off)
            sfields, ifields, dmethods, vmethods = (cur.uleb() for _ in range(4))
            if max(sfields, ifields, dmethods, vmethods) > 65535:
                raise ApkError("dex: implausible class data")
            for _ in range(sfields + ifields):
                cur.uleb()
                cur.uleb()
            for count in (dmethods, vmethods):
                midx = 0
                for _ in range(count):
                    midx += cur.uleb()
                    macc = cur.uleb()
                    code_off = cur.uleb()
                    ref = self.method_ref(midx)
                    m = Method(ref=ref, access=macc, code_off=code_off)
                    if with_code and code_off:
                        self._scan_code(m)
                    info.methods.append(m)
        return info

    def _scan_code(self, m: Method) -> None:
        d = self.data
        off = m.code_off
        if off + 16 > len(d):
            raise ApkError("dex: code item out of range")
        insns_size = struct.unpack_from("<I", d, off + 12)[0]
        base = off + 16
        end_units = insns_size
        if base + insns_size * 2 > len(d):
            raise ApkError("dex: code item is truncated")
        widths = WIDTHS
        u = 0
        count = 0
        unpack_h = struct.unpack_from
        while u < end_units:
            first = d[base + 2 * u]
            high = d[base + 2 * u + 1]
            if first == 0x00 and high != 0x00:
                ident = first | (high << 8)
                if ident == 0x0100:  # packed-switch payload
                    size = unpack_h("<H", d, base + 2 * u + 2)[0]
                    u += size * 2 + 4
                elif ident == 0x0200:  # sparse-switch payload
                    size = unpack_h("<H", d, base + 2 * u + 2)[0]
                    u += size * 4 + 2
                elif ident == 0x0300:  # fill-array-data payload
                    width = unpack_h("<H", d, base + 2 * u + 2)[0]
                    size = unpack_h("<I", d, base + 2 * u + 4)[0]
                    u += (size * width + 1) // 2 + 4
                else:
                    u += 1
                continue
            count += 1
            if first in INVOKE_OPS:
                idx = unpack_h("<H", d, base + 2 * u + 2)[0]
                try:
                    m.invokes.append((first, self.method_ref(idx)))
                except ApkError:
                    pass
            elif first == 0x1A:
                idx = unpack_h("<H", d, base + 2 * u + 2)[0]
                try:
                    m.strings.append(self.string(idx))
                except ApkError:
                    pass
            elif first == 0x1B:
                idx = unpack_h("<I", d, base + 2 * u + 2)[0]
                try:
                    m.strings.append(self.string(idx))
                except ApkError:
                    pass
            elif first == 0x22:
                idx = unpack_h("<H", d, base + 2 * u + 2)[0]
                try:
                    m.new_instances.append(descriptor_to_name(self.type(idx)))
                except ApkError:
                    pass
            u += widths[first]
        m.insn_count = count


def parse_dex(data: bytes, name: str = "classes.dex") -> Dex:
    return Dex(data, name)
