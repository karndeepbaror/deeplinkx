"""Writers for binary Android formats, used to build test fixtures.

Everything here is a from-scratch encoder (AXML, ARSC, DEX, APK + signing
block), so parser tests are true round-trips instead of opaque blobs.
"""
from __future__ import annotations

import datetime as dt
import io
import struct
import zipfile
from typing import Any, Optional

from deeplinkx.apk.axml import ANDROID_ATTR_IDS, ANDROID_NS, Ref

NAME_TO_ID = {v: k for k, v in ANDROID_ATTR_IDS.items()}
NONE = 0xFFFFFFFF


def _pad4(b: bytes) -> bytes:
    return b + b"\x00" * ((-len(b)) % 4)


# --------------------------------------------------------------------------- string pool
def string_pool(strings: list[str], utf8: bool = False) -> bytes:
    blobs = []
    for s in strings:
        if utf8:
            raw = s.encode("utf-8")
            n16 = len(s.encode("utf-16-le")) // 2

            def ln(n: int) -> bytes:
                return bytes([n]) if n < 0x80 else bytes([0x80 | (n >> 8), n & 0xFF])

            blobs.append(ln(n16) + ln(len(raw)) + raw + b"\x00")
        else:
            raw = s.encode("utf-16-le")
            n = len(raw) // 2
            head = struct.pack("<H", n) if n < 0x8000 else struct.pack("<HH", 0x8000 | (n >> 16), n & 0xFFFF)
            blobs.append(head + raw + b"\x00\x00")
    offsets = []
    pos = 0
    for b in blobs:
        offsets.append(pos)
        pos += len(b)
    data = _pad4(b"".join(blobs))
    header_size = 28
    strings_start = header_size + 4 * len(strings)
    size = strings_start + len(data)
    flags = 0x100 if utf8 else 0
    out = struct.pack("<HHIIIIII", 0x0001, header_size, size, len(strings), 0, flags, strings_start, 0)
    out += b"".join(struct.pack("<I", o) for o in offsets) + data
    return out


# --------------------------------------------------------------------------- AXML
class _Pool:
    def __init__(self) -> None:
        self.items: list[str] = []
        self.index: dict[str, int] = {}

    def add(self, s: str) -> int:
        if s not in self.index:
            self.index[s] = len(self.items)
            self.items.append(s)
        return self.index[s]


def _norm(node) -> tuple:
    return node if len(node) == 3 else (node[0], node[1] if len(node) > 1 else {}, [])


def _walk(node, fn) -> None:
    tag, attrs, kids = _norm(node)
    fn(tag, attrs)
    for k in kids:
        _walk(k, fn)


def build_axml(tree: tuple, utf8: bool = False, strip_names: bool = False) -> bytes:
    """tree = (tag, {attr: value}, [children]); attrs `android:x` use the android ns."""
    android_names: list[str] = []

    def collect(tag: str, attrs: dict) -> None:
        for k in attrs:
            if k != "#text" and k.startswith("android:") and k[8:] not in android_names:
                android_names.append(k[8:])

    _walk(tree, collect)
    pool = _Pool()
    ids: list[int] = []
    fake = 0x01019000
    for n in android_names:
        if strip_names:
            pool.items.append("")
        else:
            pool.add(n)
        rid = NAME_TO_ID.get(n)
        if rid is None:
            rid = fake
            fake += 1
        ids.append(rid)
    name_idx = {n: i for i, n in enumerate(android_names)}

    def string_idx(s: str) -> int:
        if s == "" and strip_names:
            pool.items.append("")
            return len(pool.items) - 1
        return pool.add(s)

    prefix_i = string_idx("android")
    uri_i = string_idx(ANDROID_NS)

    body = io.BytesIO()
    body.write(struct.pack("<HHIIIII", 0x0100, 16, 24, 1, NONE, prefix_i, uri_i))
    line = [2]

    def emit(node) -> None:
        tag, attrs, kids = _norm(node)
        attrs = dict(attrs)
        text = attrs.pop("#text", None)
        entries = []
        for k, v in attrs.items():
            if k.startswith("android:"):
                nm = k[8:]
                ns = uri_i
                nidx = name_idx[nm]
            else:
                nm = k
                ns = NONE
                nidx = string_idx(nm)
            if isinstance(v, bool):
                raw, vt, data = NONE, 0x12, 0xFFFFFFFF if v else 0
            elif isinstance(v, Ref):
                raw, vt, data = NONE, 0x01, int(v)
            elif isinstance(v, int):
                raw, vt, data = NONE, 0x10, v & 0xFFFFFFFF
            else:
                si = string_idx(str(v))
                raw, vt, data = si, 0x03, si
            entries.append((ns, nidx, raw, vt, data))
        tag_idx = string_idx(tag)
        ln = line[0]
        line[0] += 1
        size = 36 + 20 * len(entries)
        body.write(struct.pack("<HHIII", 0x0102, 16, size, ln, NONE))
        body.write(struct.pack("<IIHHHHHH", NONE, tag_idx, 20, 20, len(entries), 0, 0, 0))
        for ns, nidx, raw, vt, data in entries:
            body.write(struct.pack("<IIIHBBI", ns, nidx, raw, 8, 0, vt, data))
        if text is not None:
            body.write(struct.pack("<HHIIIIHBBI", 0x0104, 16, 28, ln, NONE, string_idx(text), 8, 0, 0, 0))
        for k in kids:
            emit(k)
        body.write(struct.pack("<HHIIIII", 0x0103, 16, 24, ln, NONE, NONE, tag_idx))

    emit(tree)
    body.write(struct.pack("<HHIIIII", 0x0101, 16, 24, 1, NONE, prefix_i, uri_i))

    sp = string_pool(pool.items, utf8)
    resmap = struct.pack("<HHI", 0x0180, 8, 8 + 4 * len(ids)) + b"".join(struct.pack("<I", i) for i in ids)
    payload = sp + resmap + body.getvalue()
    return struct.pack("<HHI", 0x0003, 8, 8 + len(payload)) + payload


# --------------------------------------------------------------------------- ARSC
def build_arsc(types: dict[str, dict[str, Any]], package_id: int = 0x7F, package_name: str = "com.test",
               extra_configs: Optional[dict[str, dict[str, dict[str, Any]]]] = None,
               sparse: bool = False) -> tuple[bytes, dict[str, int]]:
    """Returns (arsc bytes, {"@type/name": resource id}).

    types: {type_name: {entry_name: value}} for the default configuration.
    extra_configs: {type_name: {entry_name: {"mcc"... value}}} -> adds a second, non-default
    configuration whose value must NOT be chosen over the default one.
    """
    extra_configs = extra_configs or {}
    values = _Pool()
    keys = _Pool()
    type_names = list(types)

    def encode(v: Any) -> tuple[int, int]:
        if isinstance(v, bool):
            return 0x12, 0xFFFFFFFF if v else 0
        if isinstance(v, Ref):
            return 0x01, int(v)
        if isinstance(v, int):
            return 0x10, v & 0xFFFFFFFF
        return 0x03, values.add(str(v))

    ids: dict[str, int] = {}
    type_chunks = b""
    spec_chunks = b""
    for ti, tname in enumerate(type_names, start=1):
        names = list(types[tname])
        count = len(names)
        spec_chunks += struct.pack("<HHIBBHI", 0x0202, 16, 16 + 4 * count, ti, 0, 0, count)
        spec_chunks += b"\x00" * (4 * count)
        configs = [(b"\x00" * 60, {n: types[tname][n] for n in names})]
        if tname in extra_configs:
            cfg = bytearray(60)
            struct.pack_into("<H", cfg, 0, 310)  # mcc != 0 -> non default
            configs.append((bytes(cfg), extra_configs[tname]))
        for cfg_bytes, vals in configs:
            blob = b""
            offs = []
            for i, n in enumerate(names):
                if n not in vals:
                    offs.append(NONE)
                    continue
                offs.append(len(blob))
                vt, vd = encode(vals[n])
                blob += struct.pack("<HHI", 8, 0, keys.add(n)) + struct.pack("<HBBI", 8, 0, vt, vd)
                ids[f"@{tname}/{n}"] = (package_id << 24) | (ti << 16) | i
            if sparse:
                present = [(i, o) for i, o in enumerate(offs) if o != NONE]
                table = b"".join(struct.pack("<HH", i, o // 4) for i, o in present)
                n_entries = len(present)
                flags = 1
            else:
                table = b"".join(struct.pack("<I", o) for o in offs)
                n_entries = count
                flags = 0
            hsize = 84
            entries_start = hsize + len(table)
            cfg_full = struct.pack("<I", 64) + cfg_bytes
            size = entries_start + len(blob)
            type_chunks += struct.pack("<HHIBBHII", 0x0201, hsize, size, ti, flags, 0, n_entries, entries_start)
            type_chunks += cfg_full + b"\x00" * (hsize - 20 - len(cfg_full)) + table + blob
    type_pool = string_pool(type_names)
    key_pool = string_pool(keys.items)
    name_bytes = package_name.encode("utf-16-le")[:254].ljust(256, b"\x00")
    pkg_header = 288
    pkg_body = type_pool + key_pool + spec_chunks + type_chunks
    pkg_size = pkg_header + len(pkg_body)
    pkg = struct.pack("<HHII", 0x0200, pkg_header, pkg_size, package_id) + name_bytes
    pkg += struct.pack("<IIIII", pkg_header, len(type_names), pkg_header + len(type_pool), len(keys.items), 0)
    pkg += pkg_body
    vpool = string_pool(values.items)
    total = 12 + len(vpool) + len(pkg)
    out = struct.pack("<HHII", 0x0002, 12, total, 1) + vpool + pkg
    return out, ids


# --------------------------------------------------------------------------- DEX
INV = {"virtual": 0x6E, "super": 0x6F, "direct": 0x70, "static": 0x71, "interface": 0x72}
ACC_PRIVATE, ACC_STATIC, ACC_CONSTRUCTOR, ACC_PUBLIC = 0x2, 0x8, 0x10000, 0x1


def _uleb(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def _proto_parts(desc: str) -> tuple[list[str], str]:
    assert desc[0] == "("
    close = desc.index(")")
    params: list[str] = []
    i = 1
    while i < close:
        j = i
        while desc[j] == "[":
            j += 1
        if desc[j] == "L":
            j = desc.index(";", j)
        params.append(desc[i:j + 1])
        i = j + 1
    return params, desc[close + 1:]


def _shorty(desc: str) -> str:
    params, ret = _proto_parts(desc)

    def c(t: str) -> str:
        return "L" if t[0] in "L[" else t[0]

    return c(ret) + "".join(c(p) for p in params)


def build_dex(classes: list[dict]) -> bytes:
    """classes: [{name:'Lcom/a/B;', super:'Ljava/lang/Object;', interfaces:[], source:'B.java',
                  methods:[{name, desc, access, code:[ops...]}]}]

    ops: ('invoke','virtual',cls,name,desc) ('const-string','text') ('new-instance','Lx;')
         ('return-void',) ('nop',) ('const/4',) ('const-wide',) ('packed-switch',n) ('fill-array',w,n)
         ('sparse-switch',n) ('goto',) ('if-eqz',) ('const-string-jumbo','text')
    """
    strings: set[str] = set()
    types: set[str] = set()
    protos: set[str] = set()
    methods: set[tuple[str, str, str]] = set()

    def need_type(t: str) -> None:
        types.add(t)
        strings.add(t)

    def need_proto(d: str) -> None:
        protos.add(d)
        strings.add(_shorty(d))
        params, ret = _proto_parts(d)
        for t in params + [ret]:
            need_type(t)

    def need_method(c: str, n: str, d: str) -> None:
        need_type(c)
        strings.add(n)
        need_proto(d)
        methods.add((c, n, d))

    for cl in classes:
        need_type(cl["name"])
        need_type(cl.get("super", "Ljava/lang/Object;"))
        for i in cl.get("interfaces", []):
            need_type(i)
        if cl.get("source"):
            strings.add(cl["source"])
        for m in cl.get("methods", []):
            need_method(cl["name"], m["name"], m["desc"])
            for op in m.get("code", []):
                if op[0] == "invoke":
                    need_method(op[2], op[3], op[4])
                elif op[0] in ("const-string", "const-string-jumbo"):
                    strings.add(op[1])
                elif op[0] == "new-instance":
                    need_type(op[1])

    str_list = sorted(strings, key=lambda s: s.encode("utf-16-be"))
    str_idx = {s: i for i, s in enumerate(str_list)}
    type_list = sorted(types, key=lambda t: str_idx[t])
    type_idx = {t: i for i, t in enumerate(type_list)}
    proto_list = sorted(protos, key=lambda d: (type_idx[_proto_parts(d)[1]], d))
    proto_idx = {d: i for i, d in enumerate(proto_list)}
    meth_list = sorted(methods, key=lambda m: (type_idx[m[0]], str_idx[m[1]], proto_idx[m[2]]))
    meth_idx = {m: i for i, m in enumerate(meth_list)}

    n_str, n_type, n_proto, n_meth, n_cls = len(str_list), len(type_list), len(proto_list), len(meth_list), len(classes)
    off_str = 0x70
    off_type = off_str + 4 * n_str
    off_proto = off_type + 4 * n_type
    off_meth = off_proto + 12 * n_proto
    off_cls = off_meth + 8 * n_meth
    data_off = off_cls + 32 * n_cls
    data = bytearray()

    def here() -> int:
        return data_off + len(data)

    def align4() -> None:
        while len(data) % 4:
            data.append(0)

    # type lists for protos
    plist_off: dict[str, int] = {}
    for d in proto_list:
        params, _ = _proto_parts(d)
        if params:
            align4()
            plist_off[d] = here()
            data += struct.pack("<I", len(params)) + b"".join(struct.pack("<H", type_idx[p]) for p in params)
    iface_off: dict[int, int] = {}
    for ci, cl in enumerate(classes):
        if cl.get("interfaces"):
            align4()
            iface_off[ci] = here()
            ifs = cl["interfaces"]
            data += struct.pack("<I", len(ifs)) + b"".join(struct.pack("<H", type_idx[i]) for i in ifs)
    # strings
    str_off = []
    for s in str_list:
        str_off.append(here())
        raw = s.encode("utf-16-le", "surrogatepass")
        data += _uleb(len(raw) // 2) + s.replace("\x00", "\x00").encode("utf-8").replace(b"\x00", b"\xc0\x80") + b"\x00"
    # code items
    code_off: dict[tuple[str, str, str], int] = {}

    def assemble(code: list[tuple]) -> bytes:
        u: list[int] = []
        for op in code:
            k = op[0]
            if k == "invoke":
                u += [INV[op[1]], meth_idx[(op[2], op[3], op[4])], 0]
                u[-3] = INV[op[1]]
            elif k == "const-string":
                u += [0x1A | (0 << 8), str_idx[op[1]]]
            elif k == "const-string-jumbo":
                v = str_idx[op[1]]
                u += [0x1B, v & 0xFFFF, v >> 16]
            elif k == "new-instance":
                u += [0x22, type_idx[op[1]]]
            elif k == "return-void":
                u += [0x0E]
            elif k == "nop":
                u += [0x00]
            elif k == "const/4":
                u += [0x12]
            elif k == "const":
                u += [0x14, 0, 0]
            elif k == "const-wide":
                u += [0x18, 0, 0, 0, 0]
            elif k == "goto":
                u += [0x28]
            elif k == "if-eqz":
                u += [0x38, 0]
            elif k == "iget":
                u += [0x52, 0]
            elif k == "add-int":
                u += [0x90, 0]
            elif k == "move-result":
                u += [0x0A]
            elif k == "packed-switch":
                n = op[1]
                u += [0x2B, 0, 0] + [0x0100, n, 0, 0] + [0] * (2 * n)
            elif k == "sparse-switch":
                n = op[1]
                u += [0x2C, 0, 0] + [0x0200, n] + [0] * (4 * n)
            elif k == "fill-array":
                w, n = op[1], op[2]
                u += [0x26, 0, 0] + [0x0300, w, n & 0xFFFF, n >> 16] + [0] * ((n * w + 1) // 2)
            else:
                raise ValueError(f"unknown op {k}")
        return b"".join(struct.pack("<H", x & 0xFFFF) for x in u)

    for cl in classes:
        for m in cl.get("methods", []):
            if not m.get("code"):
                continue
            insns = assemble(m["code"])
            align4()
            code_off[(cl["name"], m["name"], m["desc"])] = here()
            data += struct.pack("<HHHHII", 4, 1, 1, 0, 0, len(insns) // 2) + insns
    # class data
    cdata_off: dict[int, int] = {}
    for ci, cl in enumerate(classes):
        ms = cl.get("methods", [])
        if not ms:
            continue
        direct, virtual = [], []
        for m in ms:
            acc = m.get("access", ACC_PUBLIC)
            (direct if acc & (ACC_STATIC | ACC_PRIVATE | ACC_CONSTRUCTOR) else virtual).append(m)
        blob = _uleb(0) + _uleb(0) + _uleb(len(direct)) + _uleb(len(virtual))
        for group in (direct, virtual):
            group.sort(key=lambda m: meth_idx[(cl["name"], m["name"], m["desc"])])
            last = 0
            for m in group:
                idx = meth_idx[(cl["name"], m["name"], m["desc"])]
                blob += _uleb(idx - last) + _uleb(m.get("access", ACC_PUBLIC))
                blob += _uleb(code_off.get((cl["name"], m["name"], m["desc"]), 0))
                last = idx
        cdata_off[ci] = here()
        data += blob

    head = bytearray(0x70)
    head[0:8] = b"dex\n035\x00"
    total = data_off + len(data)
    struct.pack_into("<III", head, 32, total, 0x70, 0x12345678)
    struct.pack_into("<12I", head, 56, n_str, off_str, n_type, off_type, n_proto, off_proto,
                     0, 0, n_meth, off_meth, n_cls, off_cls)
    struct.pack_into("<II", head, 104, len(data), data_off)
    out = bytes(head)
    out += b"".join(struct.pack("<I", o) for o in str_off)
    out += b"".join(struct.pack("<I", str_idx[t]) for t in type_list)
    for d in proto_list:
        params, ret = _proto_parts(d)
        out += struct.pack("<III", str_idx[_shorty(d)], type_idx[ret], plist_off.get(d, 0))
    for c, n, d in meth_list:
        out += struct.pack("<HHI", type_idx[c], proto_idx[d], str_idx[n])
    for ci, cl in enumerate(classes):
        sup = cl.get("super", "Ljava/lang/Object;")
        src = str_idx[cl["source"]] if cl.get("source") else NONE
        out += struct.pack("<8I", type_idx[cl["name"]], cl.get("access", ACC_PUBLIC),
                           type_idx[sup] if sup else NONE, iface_off.get(ci, 0), src, 0,
                           cdata_off.get(ci, 0), 0)
    return out + bytes(data)


# --------------------------------------------------------------------------- certificates + signing
def make_cert(cn: str = "Test Publisher", key_type: str = "ec", hash_name: str = "sha256",
              valid_days: int = 3650, start_offset_days: int = -1, self_signed: bool = True):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1()) if key_type == "ec" else rsa.generate_private_key(65537, 2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    issuer = name if self_signed else x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Some CA")])
    now = dt.datetime.now(dt.timezone.utc)
    nb = now + dt.timedelta(days=start_offset_days)
    na = nb + dt.timedelta(days=valid_days)
    h = {"sha256": hashes.SHA256, "sha1": hashes.SHA1}[hash_name]()
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(issuer).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(nb).not_valid_after(na)
            .sign(key, h))
    return cert, key


def pkcs7_der(cert, key) -> bytes:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.serialization import pkcs7

    return (pkcs7.PKCS7SignatureBuilder().set_data(b"manifest").add_signer(cert, key, hashes.SHA256())
            .sign(serialization.Encoding.DER, [pkcs7.PKCS7Options.DetachedSignature]))


def v2_block(cert_ders: list[bytes], scheme_id: int = 0x7109871A) -> bytes:
    def lp(b: bytes) -> bytes:
        return struct.pack("<I", len(b)) + b

    certs = lp(b"".join(lp(c) for c in cert_ders))
    signed_data = lp(lp(b"") + certs + lp(b""))
    signer = lp(signed_data + lp(b"") + lp(b""))
    value = lp(signer)
    pair = struct.pack("<I", scheme_id) + value
    pairs = struct.pack("<Q", len(pair)) + pair
    size = len(pairs) + 8 + 16
    return struct.pack("<Q", size) + pairs + struct.pack("<Q", size) + b"APK Sig Block 42"


def insert_signing_block(apk_bytes: bytes, block: bytes) -> bytes:
    eocd = apk_bytes.rfind(b"PK\x05\x06")
    cd_off = struct.unpack_from("<I", apk_bytes, eocd + 16)[0]
    new = bytearray(apk_bytes[:cd_off] + block + apk_bytes[cd_off:])
    new_eocd = eocd + len(block)
    struct.pack_into("<I", new, new_eocd + 16, cd_off + len(block))
    return bytes(new)


# --------------------------------------------------------------------------- APK
def build_apk(path, manifest_tree: tuple, resources: Optional[bytes] = None, dex: Optional[list[bytes]] = None,
              files: Optional[dict[str, bytes]] = None, v1_cert: Any = None, v2_certs: Optional[list] = None,
              v3_certs: Optional[list] = None, utf8: bool = False, strip_names: bool = False) -> str:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("AndroidManifest.xml", build_axml(manifest_tree, utf8=utf8, strip_names=strip_names))
        if resources is not None:
            z.writestr("resources.arsc", resources)
        for i, d in enumerate(dex or []):
            z.writestr("classes.dex" if i == 0 else f"classes{i + 1}.dex", d)
        for name, content in (files or {}).items():
            z.writestr(name, content)
        if v1_cert is not None:
            cert, key = v1_cert
            z.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")
            z.writestr("META-INF/CERT.SF", "Signature-Version: 1.0\n")
            z.writestr("META-INF/CERT.RSA", pkcs7_der(cert, key))
    data = buf.getvalue()
    from cryptography.hazmat.primitives.serialization import Encoding

    blocks = b""
    if v2_certs or v3_certs:
        pairs = []
        if v2_certs:
            pairs.append((0x7109871A, [c.public_bytes(Encoding.DER) for c in v2_certs]))
        if v3_certs:
            pairs.append((0xF05368C0, [c.public_bytes(Encoding.DER) for c in v3_certs]))
        # build one combined block with several pairs
        raw_pairs = b""
        for pid, ders in pairs:
            inner = v2_block(ders, pid)
            # reuse single-pair encoding: strip the 8-byte size header and 24-byte footer
            raw_pairs += inner[8:-24]
        size = len(raw_pairs) + 8 + 16
        blocks = struct.pack("<Q", size) + raw_pairs + struct.pack("<Q", size) + b"APK Sig Block 42"
    if blocks:
        data = insert_signing_block(data, blocks)
    with open(path, "wb") as fh:
        fh.write(data)
    return str(path)


# --------------------------------------------------------------------------- manifest helpers
def manifest_tree(package: str = "com.example.app", *, min_sdk: int = 21, target_sdk: int = 33,
                  app_attrs: Optional[dict] = None, components: Optional[list] = None,
                  permissions: Optional[list[str]] = None, extra: Optional[list] = None) -> tuple:
    kids: list = [("uses-sdk", {"android:minSdkVersion": min_sdk, "android:targetSdkVersion": target_sdk}, [])]
    for p in permissions or []:
        kids.append(("uses-permission", {"android:name": p}, []))
    kids += extra or []
    kids.append(("application", {"android:label": "Test", **(app_attrs or {})}, components or []))
    return ("manifest", {"package": package, "android:versionCode": 7, "android:versionName": "1.2.3"}, kids)


def intent_filter(actions=(), categories=(), data=(), auto_verify: bool = False, priority: Optional[int] = None):
    attrs: dict = {}
    if auto_verify:
        attrs["android:autoVerify"] = True
    if priority is not None:
        attrs["android:priority"] = priority
    kids = [("action", {"android:name": a}, []) for a in actions]
    kids += [("category", {"android:name": c}, []) for c in categories]
    for d in data:
        kids.append(("data", {f"android:{k}": v for k, v in d.items()}, []))
    return ("intent-filter", attrs, kids)


def activity(name: str, filters=(), tag: str = "activity", **attrs):
    return (tag, {"android:name": name, **{f"android:{k}": v for k, v in attrs.items()}}, list(filters))


VIEW = "android.intent.action.VIEW"
DEFAULT = "android.intent.category.DEFAULT"
BROWSABLE = "android.intent.category.BROWSABLE"
MAIN = "android.intent.action.MAIN"
LAUNCHER = "android.intent.category.LAUNCHER"
