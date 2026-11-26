from __future__ import annotations

import datetime as _dt
import hashlib
import os
import re
import struct
import zipfile
from pathlib import Path
from typing import Any, Optional

from ..errors import ApkError
from ..models import Manifest
from .arsc import ResourceTable
from .axml import Element, element_to_xml, is_binary_xml, parse_axml
from .manifest import parse_manifest

MAX_ENTRY_SIZE = 512 * 1024 * 1024
MAX_MANIFEST_SIZE = 32 * 1024 * 1024
MAX_RATIO = 2000
SIG_MAGIC = b"APK Sig Block 42"
SIG_IDS = {
    0x7109871A: "v2",
    0xF05368C0: "v3",
    0x1B93AD61: "v3.1",
    0x6DFF800D: "source-stamp",
    0x2146444E: "play-metadata",
    0x42726577: "padding",
}
DEBUG_CN = re.compile(r"CN=Android Debug", re.I)


def _hash_file(path: Path) -> dict[str, str]:
    md5, sha1, sha256 = hashlib.md5(), hashlib.sha1(), hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(1 << 20)
            if not chunk:
                break
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
    return {"md5": md5.hexdigest(), "sha1": sha1.hexdigest(), "sha256": sha256.hexdigest()}


def is_weak_signature_algorithm(name: str) -> bool:
    low = name.lower().replace("-", "")
    return "md5" in low or "sha1" in low


def analyze_certificate(der: bytes) -> dict[str, Any]:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa

    cert = x509.load_der_x509_certificate(der)
    pub = cert.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        key_type, key_bits = "RSA", pub.key_size
    elif isinstance(pub, ec.EllipticCurvePublicKey):
        key_type, key_bits = "EC", pub.key_size
    elif isinstance(pub, dsa.DSAPublicKey):
        key_type, key_bits = "DSA", pub.key_size
    else:
        key_type, key_bits = type(pub).__name__, 0
    try:
        sig_alg = cert.signature_algorithm_oid._name or cert.signature_algorithm_oid.dotted_string
    except Exception:  # pragma: no cover
        sig_alg = "unknown"
    try:
        nb, na = cert.not_valid_before_utc, cert.not_valid_after_utc
    except AttributeError:  # older cryptography
        nb = cert.not_valid_before.replace(tzinfo=_dt.timezone.utc)
        na = cert.not_valid_after.replace(tzinfo=_dt.timezone.utc)
    now = _dt.datetime.now(_dt.timezone.utc)
    subject = cert.subject.rfc4514_string()
    issuer = cert.issuer.rfc4514_string()
    return {
        "subject": subject,
        "issuer": issuer,
        "serial": format(cert.serial_number, "x"),
        "not_before": nb.isoformat(),
        "not_after": na.isoformat(),
        "expired": na < now,
        "not_yet_valid": nb > now,
        "signature_algorithm": sig_alg,
        "key_type": key_type,
        "key_bits": key_bits,
        "self_signed": subject == issuer,
        "debug": bool(DEBUG_CN.search(subject)),
        "sha256": cert.fingerprint(hashes.SHA256()).hex(),
        "sha1": cert.fingerprint(hashes.SHA1()).hex(),  # noqa: S303 - identification only
        "weak_hash": is_weak_signature_algorithm(sig_alg),
    }


def _lp(data: bytes, pos: int) -> tuple[bytes, int]:
    """read a u32 length-prefixed block"""
    if pos + 4 > len(data):
        raise ApkError("signing block: truncated")
    n = struct.unpack_from("<I", data, pos)[0]
    if pos + 4 + n > len(data):
        raise ApkError("signing block: length out of range")
    return data[pos + 4:pos + 4 + n], pos + 4 + n


def _certs_from_signature_scheme(value: bytes) -> list[bytes]:
    certs: list[bytes] = []
    signers, _ = _lp(value, 0)
    pos = 0
    while pos < len(signers):
        signer, pos = _lp(signers, pos)
        signed_data, _ = _lp(signer, 0)
        _digests, p = _lp(signed_data, 0)
        cert_seq, _ = _lp(signed_data, p)
        q = 0
        while q < len(cert_seq):
            cert, q = _lp(cert_seq, q)
            certs.append(cert)
    return certs


class Apk:
    def __init__(self, path: str | os.PathLike, max_entry_size: int = MAX_ENTRY_SIZE):
        self.path = Path(path)
        self.max_entry_size = max_entry_size
        self.warnings: list[str] = []
        if not self.path.is_file():
            raise ApkError(f"file not found: {self.path}")
        try:
            self._zip = zipfile.ZipFile(self.path)
        except zipfile.BadZipFile as exc:
            raise ApkError(f"not a valid APK/zip file: {exc}") from exc
        self._infos = {i.filename: i for i in self._zip.infolist()}
        self._check_bombs()
        if "AndroidManifest.xml" not in self._infos:
            raise ApkError("AndroidManifest.xml is missing, this is not an APK")
        self._hashes: Optional[dict] = None
        self._root: Optional[Element] = None
        self._manifest: Optional[Manifest] = None
        self._resources: Optional[ResourceTable] = None
        self._resources_loaded = False
        self._sign: Optional[dict] = None

    # ----- container -----
    def _check_bombs(self) -> None:
        for info in self._infos.values():
            if info.file_size > self.max_entry_size:
                raise ApkError(f"entry {info.filename} is larger than the safety limit")
            if info.compress_size and info.file_size / max(info.compress_size, 1) > MAX_RATIO \
                    and info.file_size > 50 * 1024 * 1024:
                raise ApkError(f"entry {info.filename} has a suspicious compression ratio")

    def close(self) -> None:
        self._zip.close()

    def __enter__(self) -> "Apk":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    @property
    def names(self) -> list[str]:
        return list(self._infos)

    @property
    def size(self) -> int:
        return self.path.stat().st_size

    @property
    def hashes(self) -> dict[str, str]:
        if self._hashes is None:
            self._hashes = _hash_file(self.path)
        return self._hashes

    def has(self, name: str) -> bool:
        return name in self._infos

    def read(self, name: str, limit: Optional[int] = None) -> bytes:
        info = self._infos.get(name)
        if info is None:
            raise ApkError(f"no such entry: {name}")
        cap = limit if limit is not None else self.max_entry_size
        if info.file_size > cap:
            raise ApkError(f"entry {name} exceeds the read limit")
        try:
            with self._zip.open(info) as fh:
                data = fh.read(cap + 1)
        except (zipfile.BadZipFile, RuntimeError, NotImplementedError, EOFError) as exc:
            raise ApkError(f"cannot read {name}: {exc}") from exc
        return data

    # ----- manifest / resources -----
    @property
    def resources(self) -> Optional[ResourceTable]:
        if not self._resources_loaded:
            self._resources_loaded = True
            if "resources.arsc" in self._infos:
                try:
                    self._resources = ResourceTable(self.read("resources.arsc"))
                except (ApkError, struct.error, IndexError) as exc:
                    self.warnings.append(f"resources.arsc could not be parsed: {exc}")
        return self._resources

    @property
    def manifest_root(self) -> Element:
        if self._root is None:
            data = self.read("AndroidManifest.xml", MAX_MANIFEST_SIZE)
            if not is_binary_xml(data):
                raise ApkError("AndroidManifest.xml is not binary xml")
            try:
                self._root = parse_axml(data)
            except (struct.error, IndexError) as exc:
                raise ApkError(f"AndroidManifest.xml is corrupt: {exc}") from exc
        return self._root

    @property
    def manifest(self) -> Manifest:
        if self._manifest is None:
            self._manifest = parse_manifest(self.manifest_root, self.resources)
        return self._manifest

    def manifest_xml(self) -> str:
        table = self.resources
        return element_to_xml(self.manifest_root, table.name_of if table else None)

    def read_xml(self, name: str) -> Optional[Element]:
        if name not in self._infos:
            return None
        data = self.read(name, MAX_MANIFEST_SIZE)
        if is_binary_xml(data):
            try:
                return parse_axml(data)
            except (ApkError, struct.error, IndexError) as exc:
                self.warnings.append(f"{name}: {exc}")
                return None
        return None

    def network_security_config(self) -> Optional[Element]:
        ref = self.manifest.network_security_config
        if not ref:
            return None
        path = ref
        if path.startswith("@"):  # unresolved symbolic name
            return None
        return self.read_xml(path)

    # ----- content -----
    @property
    def dex_names(self) -> list[str]:
        def key(n: str) -> int:
            m = re.match(r"classes(\d*)\.dex$", n)
            return int(m.group(1) or 1) if m else 0

        return sorted((n for n in self._infos if re.fullmatch(r"classes\d*\.dex", n)), key=key)

    def read_dex(self, name: str) -> bytes:
        return self.read(name)

    @property
    def native_abis(self) -> list[str]:
        abis = set()
        for n in self._infos:
            m = re.match(r"lib/([^/]+)/[^/]+\.so$", n)
            if m:
                abis.add(m.group(1))
        return sorted(abis)

    @property
    def native_libs(self) -> list[str]:
        return sorted(n for n in self._infos if re.match(r"lib/[^/]+/[^/]+\.so$", n))

    def assets(self, suffixes: tuple[str, ...] = ()) -> list[str]:
        out = [n for n in self._infos if n.startswith("assets/")]
        if suffixes:
            out = [n for n in out if n.lower().endswith(suffixes)]
        return sorted(out)

    # ----- signing -----
    def _signing_block(self) -> dict[int, bytes]:
        size = self.size
        with open(self.path, "rb") as fh:
            tail_len = min(size, 65557 + 22)
            fh.seek(size - tail_len)
            tail = fh.read(tail_len)
            idx = tail.rfind(b"PK\x05\x06")
            if idx < 0 or idx + 22 > len(tail):
                return {}
            cd_off = struct.unpack_from("<I", tail, idx + 16)[0]
            if cd_off < 32 or cd_off > size:
                return {}
            fh.seek(cd_off - 24)
            footer = fh.read(24)
            if footer[8:] != SIG_MAGIC:
                return {}
            block_size = struct.unpack_from("<Q", footer, 0)[0]
            if block_size < 24 or block_size + 8 > cd_off or block_size > 256 * 1024 * 1024:
                return {}
            start = cd_off - block_size - 8
            fh.seek(start)
            block = fh.read(block_size + 8)
        pairs: dict[int, bytes] = {}
        pos = 8
        end = len(block) - 24
        while pos + 12 <= end:
            plen = struct.unpack_from("<Q", block, pos)[0]
            if plen < 4 or pos + 8 + plen > end + 8:
                break
            pid = struct.unpack_from("<I", block, pos + 8)[0]
            pairs[pid] = block[pos + 12:pos + 8 + plen]
            pos += 8 + plen
        return pairs

    def signatures(self) -> dict[str, Any]:
        if self._sign is not None:
            return self._sign
        schemes: dict[str, bool] = {"v1": False, "v2": False, "v3": False, "v3.1": False}
        certs: dict[str, dict] = {}

        def add(der: bytes, scheme: str) -> None:
            try:
                info = analyze_certificate(der)
            except Exception as exc:  # cryptography raises many types
                self.warnings.append(f"certificate ({scheme}) could not be parsed: {exc}")
                return
            existing = certs.get(info["sha256"])
            if existing:
                existing["schemes"].append(scheme)
            else:
                info["schemes"] = [scheme]
                certs[info["sha256"]] = info

        meta = [n for n in self._infos if re.match(r"META-INF/[^/]+\.(RSA|DSA|EC)$", n, re.I)]
        if meta:
            schemes["v1"] = True
            from cryptography.hazmat.primitives.serialization import pkcs7

            for n in meta:
                try:
                    for c in pkcs7.load_der_pkcs7_certificates(self.read(n, 4 * 1024 * 1024)):
                        from cryptography.hazmat.primitives.serialization import Encoding

                        add(c.public_bytes(Encoding.DER), "v1")
                except Exception as exc:
                    self.warnings.append(f"{n}: {exc}")
        extra: list[str] = []
        try:
            pairs = self._signing_block()
        except (OSError, struct.error, ApkError) as exc:
            pairs = {}
            self.warnings.append(f"signing block unreadable: {exc}")
        for pid, value in pairs.items():
            label = SIG_IDS.get(pid)
            if label in ("v2", "v3", "v3.1"):
                schemes[label] = True
                try:
                    for der in _certs_from_signature_scheme(value):
                        add(der, label)
                except (ApkError, struct.error) as exc:
                    self.warnings.append(f"{label} signature block: {exc}")
            elif label:
                extra.append(label)
            else:
                extra.append(f"0x{pid:08x}")
        self._sign = {
            "schemes": schemes,
            "certificates": list(certs.values()),
            "block_entries": sorted(extra),
            "signed": any(schemes.values()),
        }
        return self._sign

    # ----- summary -----
    def info(self) -> dict[str, Any]:
        m = self.manifest
        sig = self.signatures()
        return {
            "file": str(self.path),
            "file_name": self.path.name,
            "size": self.size,
            "hashes": self.hashes,
            "package": m.package,
            "version_name": m.version_name,
            "version_code": m.version_code,
            "min_sdk": m.min_sdk,
            "target_sdk": m.target_sdk,
            "compile_sdk": m.compile_sdk,
            "app_label": m.app_label,
            "debuggable": m.debuggable,
            "allow_backup": m.allow_backup,
            "uses_cleartext": m.uses_cleartext,
            "dex_files": self.dex_names,
            "native_abis": self.native_abis,
            "entries": len(self._infos),
            "signing": {"schemes": sig["schemes"], "signed": sig["signed"],
                        "certificates": sig["certificates"]},
            "warnings": list(self.warnings),
        }


def open_apk(path: str | os.PathLike, **kwargs: Any) -> Apk:
    return Apk(path, **kwargs)
