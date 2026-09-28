"""Ephemeral TLS material for the PEAP EAP lab honeypot."""
from __future__ import annotations

import shutil
import ssl
import subprocess
from pathlib import Path

from wifit3.persist.private_files import ensure_private_directory


class LabTlsMaterial:
    def __init__(self, cert_path: Path, key_path: Path, *, request_client_cert: bool) -> None:
        self.cert_path = cert_path
        self.key_path = key_path
        self.request_client_cert = request_client_cert

    def server_context(self) -> ssl.SSLContext:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(str(self.cert_path), str(self.key_path))
        if self.request_client_cert:
            context.verify_mode = ssl.CERT_OPTIONAL
        else:
            context.verify_mode = ssl.CERT_NONE
        return context


def ensure_lab_tls_material(
    base_dir: Path,
    *,
    request_client_cert: bool = True,
) -> LabTlsMaterial:
    ensure_private_directory(base_dir)
    cert_path = base_dir / "eap_lab.crt"
    key_path = base_dir / "eap_lab.key"
    if cert_path.is_file() and key_path.is_file():
        return LabTlsMaterial(cert_path, key_path, request_client_cert=request_client_cert)
    openssl = shutil.which("openssl")
    if openssl is None:
        raise RuntimeError(
            "OpenSSL is required to generate the PEAP lab certificate "
            "(install openssl or pre-create eap_lab.crt/key)",
        )
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
            "/CN=WiFiT3-EAP-Lab",
        ],
        check=True,
        capture_output=True,
    )
    return LabTlsMaterial(cert_path, key_path, request_client_cert=request_client_cert)
