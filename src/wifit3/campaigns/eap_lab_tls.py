"""Ephemeral TLS material for the PEAP EAP lab honeypot."""
from __future__ import annotations

import shutil
import ssl
import subprocess
from pathlib import Path

from wifit3.persist.private_files import ensure_private_directory

_DEFAULT_CN = "WiFiT3-EAP-Lab"
# Classic PEAP: RSA key transport, AES128-SHA first (0x002F). No ECDHE.
_PEAP_CIPHERS = "AES128-SHA:AES256-SHA:AES128-SHA256:AES256-SHA256:@SECLEVEL=0"


class LabTlsMaterial:
    def __init__(self, cert_path: Path, key_path: Path, *, request_client_cert: bool) -> None:
        self.cert_path = cert_path
        self.key_path = key_path
        self.request_client_cert = request_client_cert

    def server_context(self, *, request_client_cert: bool | None = None) -> ssl.SSLContext:
        want = self.request_client_cert if request_client_cert is None else request_client_cert
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.maximum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(str(self.cert_path), str(self.key_path))
        if want:
            context.verify_mode = ssl.CERT_OPTIONAL
        else:
            context.verify_mode = ssl.CERT_NONE
            try:
                context.set_ciphers(_PEAP_CIPHERS)
            except ssl.SSLError:
                pass
        return context


def _cn_from_names(names: tuple[str, ...]) -> str:
    for name in names:
        cleaned = "".join(
            ch for ch in name.strip() if ch.isprintable() and ch not in "/\\"
        )
        if cleaned:
            return cleaned[:64]
    return _DEFAULT_CN


def _san_dns(names: tuple[str, ...]) -> list[str]:
    seen: list[str] = []
    for name in names:
        cleaned = "".join(ch if ch.isalnum() or ch in ".-" else "-" for ch in name.strip())
        cleaned = cleaned.strip("-.")[:253]
        if cleaned and cleaned not in seen:
            seen.append(cleaned)
    if _DEFAULT_CN not in seen:
        seen.append(_DEFAULT_CN)
    return seen


def _leaf_server_cert_ok(cert_path: Path, openssl: str) -> bool:
    result = subprocess.run(
        [openssl, "x509", "-in", str(cert_path), "-noout", "-text"],
        check=False,
        capture_output=True,
        text=True,
    )
    text = result.stdout or ""
    if result.returncode != 0 or "CA:TRUE" in text:
        return False
    return "TLS Web Server Authentication" in text or "serverAuth" in text


def _write_lab_leaf_cert(
    openssl: str,
    cert_path: Path,
    key_path: Path,
    *,
    dns_names: tuple[str, ...],
) -> None:
    cn = _cn_from_names(dns_names)
    san = ",".join(f"DNS:{item}" for item in _san_dns((cn,) + dns_names))
    subprocess.run(
        [
            openssl,
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            str(key_path),
            "-out",
            str(cert_path),
            "-days",
            "365",
            "-nodes",
            "-subj",
            f"/CN={cn}",
            "-addext",
            "basicConstraints=CA:FALSE",
            "-addext",
            "keyUsage=critical,digitalSignature,keyEncipherment",
            "-addext",
            "extendedKeyUsage=serverAuth",
            "-addext",
            f"subjectAltName={san}",
        ],
        check=True,
        capture_output=True,
    )


def ensure_lab_tls_material(
    base_dir: Path,
    *,
    request_client_cert: bool = False,
    dns_names: tuple[str, ...] = (),
) -> LabTlsMaterial:
    ensure_private_directory(base_dir)
    cert_path = base_dir / "eap_lab.crt"
    key_path = base_dir / "eap_lab.key"
    openssl = shutil.which("openssl")
    if cert_path.is_file() and key_path.is_file():
        if openssl is None or _leaf_server_cert_ok(cert_path, openssl):
            return LabTlsMaterial(cert_path, key_path, request_client_cert=request_client_cert)
    if openssl is None:
        raise RuntimeError(
            "OpenSSL is required to generate the PEAP lab certificate "
            "(install openssl or pre-create eap_lab.crt/key)",
        )
    _write_lab_leaf_cert(openssl, cert_path, key_path, dns_names=dns_names)
    return LabTlsMaterial(cert_path, key_path, request_client_cert=request_client_cert)
