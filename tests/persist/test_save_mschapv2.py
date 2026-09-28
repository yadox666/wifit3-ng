from types import SimpleNamespace

from wifit3.crack.mschapv2 import MsChapV2Capture, hashcat5500_line
from wifit3.persist.save import save_mschapv2


def test_save_mschapv2_writes_hashcat_line(tmp_path, monkeypatch):
    monkeypatch.setattr("wifit3.persist.save.Config.captures_dir", str(tmp_path))
    ap = SimpleNamespace(ssid="CorpNet", bssid="aa:bb:cc:dd:ee:ff")
    capture = MsChapV2Capture(
        username="user",
        server_challenge=b"\x01" * 16,
        peer_challenge=b"\x02" * 16,
        nt_response=b"\x03" * 24,
        flags=0,
    )
    result = save_mschapv2(ap, capture, lab_bssid="02:aa:bb:cc:dd:01")
    assert result is not None and result.mschapv2.was_new
    mschap = result.mschapv2.path.read_text(encoding="utf-8").strip()
    ntlm = result.netntlmv2.path.read_text(encoding="utf-8").strip()
    assert mschap == hashcat5500_line(capture)
    assert ntlm.count(":") >= 4
