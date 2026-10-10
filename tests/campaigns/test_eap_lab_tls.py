import shutil
import subprocess
from pathlib import Path

import pytest

from wifit3.campaigns.eap_lab_tls import ensure_lab_tls_material


openssl = shutil.which("openssl")


def _cert_text(path: Path) -> str:
    return subprocess.run(
        [openssl, "x509", "-in", str(path), "-noout", "-text"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout


@pytest.mark.skipif(openssl is None, reason="openssl required")
def test_lab_cert_is_server_leaf_not_ca(tmp_path):
    material = ensure_lab_tls_material(tmp_path, dns_names=("EAP-TEST-LAB",))
    text = _cert_text(material.cert_path)
    assert "CA:TRUE" not in text
    assert "CA:FALSE" in text
    assert "TLS Web Server Authentication" in text
    assert "EAP-TEST-LAB" in text


@pytest.mark.skipif(openssl is None, reason="openssl required")
def test_lab_cert_refreshes_legacy_ca_true_leaf(tmp_path):
    cert = tmp_path / "eap_lab.crt"
    key = tmp_path / "eap_lab.key"
    subprocess.run(
        [
            openssl,
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            str(key),
            "-out",
            str(cert),
            "-days",
            "1",
            "-nodes",
            "-subj",
            "/CN=WiFiT3-EAP-Lab",
        ],
        check=True,
        capture_output=True,
    )
    assert "CA:TRUE" in _cert_text(cert)
    material = ensure_lab_tls_material(tmp_path, dns_names=("EAP-TEST-LAB",))
    text = _cert_text(material.cert_path)
    assert "CA:TRUE" not in text
    assert "CA:FALSE" in text
    assert "EAP-TEST-LAB" in text
