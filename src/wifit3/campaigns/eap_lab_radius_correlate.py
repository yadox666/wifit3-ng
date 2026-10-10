"""Match Enterprise probe windows to tail excerpts from the home EAP lab radiusd.log."""
from __future__ import annotations

import re
from pathlib import Path

from wifit3.crack.mschapv2 import parse_mschapv2_challenge_payload
from wifit3.dot11.eap import EAP_REQUEST, EAP_TYPE_MSCHAPV2

_KEY_LINE_RE = re.compile(
    r"(?i)(eap_peap|eap_ttls|eap_tls|ms-chap|access-reject|access-challenge|"
    r"access-accept|unexpected|tunneled data|waiting for inner|"
    r"failed to authenticate|user-name|called-station|calling-station|error:|"
    r"certificate|client certificate)",
)
_REQUEST_START_RE = re.compile(r"^\((\d+)\) Received Access-Request")
_EAP_MESSAGE_RE = re.compile(r"EAP-Message = 0x([0-9a-fA-F]+)")
_USER_RE = re.compile(r'User-Name = "([^"]*)"')
_CALLED_RE = re.compile(r'Called-Station-Id = "([^"]*)"')
_CALLING_RE = re.compile(r'Calling-Station-Id = "([^"]*)"')


def default_eap_lab_radius_log() -> Path | None:
    candidate = Path.home() / "Downloads/To_Test/eap-lab/logs/radiusd.log"
    return candidate if candidate.is_file() else None


def _mac_dashed(mac: str) -> str:
    parts = mac.replace("-", ":").lower().split(":")
    if len(parts) == 6:
        return "-".join(part.zfill(2).upper() for part in parts)
    return mac.upper()


def correlate_probe_with_radius_log(
    *,
    log_path: Path,
    client_mac: str | None,
    ssid: str,
    started_at: float,
    ended_at: float,
    tail_bytes: int = 320_000,
) -> dict | None:
    """Return sanitized RADIUS excerpts grouped per Access-Request for this STA."""
    if not log_path.is_file() or client_mac is None:
        return None
    try:
        raw = log_path.read_bytes()
    except OSError:
        return None
    if len(raw) > tail_bytes:
        raw = raw[-tail_bytes:]
    text = raw.decode("utf-8", errors="replace")
    mac_token = _mac_dashed(client_mac)
    if mac_token not in text and mac_token.replace("-", ":") not in text:
        return None

    blocks: list[list[str]] = []
    current: list[str] = []
    for line in text.splitlines():
        if _REQUEST_START_RE.match(line):
            if current and any(mac_token in item for item in current):
                blocks.append(current)
            current = [line]
            continue
        if current:
            current.append(line)
            if line.startswith("Ready to process requests") or line.startswith("Waking up"):
                if any(mac_token in item for item in current):
                    blocks.append(current)
                current = []
    if current and any(mac_token in item for item in current):
        blocks.append(current)

    if not blocks:
        return None

    requests = [_summarize_request(block, mac_token, ssid) for block in blocks]
    last = requests[-1]
    highlights = last["highlights"]
    mschap_challenge_hex = None
    for item in reversed(requests):
        if item.get("mschap_challenge_hex"):
            mschap_challenge_hex = item["mschap_challenge_hex"]
            break
    diagnosis = _diagnose(last["highlights"], mschap_challenge_hex)
    return {
        "log_path": str(log_path),
        "client_mac": mac_token,
        "ssid": ssid,
        "probe_started_at": started_at,
        "probe_ended_at": ended_at,
        "request_blocks_matched": len(requests),
        "requests": requests,
        "highlights": highlights,
        "mschap_challenge_hex": mschap_challenge_hex,
        "diagnosis": diagnosis,
        "note": (
            "Each requests[] entry is one RADIUS Access-Request for this "
            "Calling-Station-Id. Contrast with the probe phase that used that User-Name."
        ),
    }


def _summarize_request(block: list[str], mac_token: str, fallback_ssid: str) -> dict:
    user_name = None
    called = None
    calling = mac_token
    radius_id = None
    start = _REQUEST_START_RE.match(block[0]) if block else None
    if start:
        radius_id = int(start.group(1))
    highlights: list[str] = []
    for line in block:
        match = _USER_RE.search(line)
        if match and user_name is None:
            user_name = match.group(1)
        match = _CALLED_RE.search(line)
        if match and called is None:
            called = match.group(1)
        match = _CALLING_RE.search(line)
        if match:
            calling = match.group(1)
        if not _KEY_LINE_RE.search(line):
            continue
        cleaned = line.strip()
        if cleaned and cleaned not in highlights:
            highlights.append(cleaned[:240])
    ssid = fallback_ssid
    if called and ":" in called:
        ssid = called.rsplit(":", 1)[-1]
    joined = "\n".join(highlights).lower()
    if "access-accept" in joined:
        outcome = "accept"
    elif "access-reject" in joined:
        outcome = "reject"
    elif "access-challenge" in joined:
        outcome = "challenge"
    else:
        outcome = "other"
    return {
        "radius_id": radius_id,
        "user_name": user_name,
        "ssid": ssid,
        "calling_station": calling,
        "outcome": outcome,
        "highlights": highlights[-12:],
        "mschap_challenge_hex": _mschap_challenge_from_highlights(highlights),
    }


def _mschap_challenge_from_highlights(highlights: list[str]) -> str | None:
    for line in highlights:
        match = _EAP_MESSAGE_RE.search(line)
        if match is None:
            continue
        try:
            raw = bytes.fromhex(match.group(1))
        except ValueError:
            continue
        payload = b""
        if len(raw) >= 5 and raw[0] == EAP_REQUEST and raw[4] == EAP_TYPE_MSCHAPV2:
            payload = raw[5:]
        elif raw[:1] == bytes([EAP_TYPE_MSCHAPV2]):
            payload = raw[1:]
        parsed = parse_mschapv2_challenge_payload(payload)
        if parsed is not None:
            return parsed.server_challenge.hex()
    return None


def _diagnose(highlights: list[str], mschap_challenge_hex: str | None) -> str | None:
    if mschap_challenge_hex:
        return (
            "RADIUS issued an MS-CHAPv2 server challenge in the PEAP/TTLS tunnel "
            "(inner method reached MS-CHAPv2)."
        )
    joined = "\n".join(highlights).lower()
    if "tunneled data is invalid" in joined or "unexpected eap-response" in joined:
        return (
            "RADIUS rejected PEAP tunnel payload (invalid inner EAP framing), "
            "not a missing MS-CHAPv2 user yet."
        )
    if "ms-chap" in joined and "access-reject" in joined:
        return "RADIUS reached MS-CHAP but rejected the client (check lab user/password policy)."
    if "waiting for inner identity" in joined and "access-reject" in joined:
        return "RADIUS expected inner Identity; probe/RADIUS inner EAP did not match."
    if "access-accept" in joined:
        return "RADIUS accepted an EAP exchange during the probe window."
    return None
