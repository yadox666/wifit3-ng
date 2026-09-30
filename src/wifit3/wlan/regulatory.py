"""User-selected Wi-Fi regulatory country (ISO 3166-1 alpha-2) for drivers without cfg80211.

Ships the Linux wireless-regdb ``db.txt`` and applies it to Mediatek connac channel
domains and TX-power SKU limits. ``00`` / empty keeps the existing world tables.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources
from typing import Iterable

logger = logging.getLogger(__name__)

# ieee80211_channel_flags (cfg80211.h) - shared by MT7921/MT7925 MCU domain payloads.
CHAN_NO_IR = 0x00000002
CHAN_RADAR = 0x00000008
CHAN_NO_HT40PLUS = 0x00000010
CHAN_NO_HT40MINUS = 0x00000020
CHAN_NO_OFDM = 0x00000040
CHAN_NO_80MHZ = 0x00000080
CHAN_NO_160MHZ = 0x00000100
CHAN_NO_320MHZ = 0x00080000

WORLD_MAX_EIRP_DBM = 20

_RULE_RE = re.compile(
    r"^\(\s*(\d+)\s*-\s*(\d+)\s*@\s*(\d+)\s*\)\s*,\s*\(\s*(\d+)\s*\)"
    r"(?:\s*,\s*(.+))?$"
)
_COUNTRY_RE = re.compile(r"^country\s+([A-Z0-9]{2})\s*:")


@dataclass(frozen=True, slots=True)
class RegRule:
    freq_start_mhz: int
    freq_end_mhz: int
    max_bw_mhz: int
    max_eirp_dbm: int
    dfs: bool
    no_ir: bool


@dataclass(frozen=True, slots=True)
class ConnacDomain:
    """Channel domain handed to Mediatek connac SET_CHAN_DOMAIN / SET_DOMAIN_INFO."""

    alpha2: bytes  # 4 bytes, e.g. b"US\\0\\0"
    channels_2ghz: tuple[tuple[int, int], ...]  # (hw_value, flags)
    channels_5ghz: tuple[tuple[int, int], ...]


def normalize_country(code: str | None) -> str:
    """Return ``00`` (world) or an upper-case ISO alpha-2 code."""
    raw = (code or "").strip().upper()
    if raw in ("", "0", "00", "WORLD"):
        return "00"
    if len(raw) == 2 and raw.isalpha():
        return raw
    logger.warning("Invalid wifi_regulatory_country %r; using world (00)", code)
    return "00"


def configured_country() -> str:
    from wifit3.persist.config import Config

    return normalize_country(getattr(Config, "wifi_regulatory_country", "00"))


def txpower_conf_units() -> int:
    """Kernel-style ``txpower_conf``: twice the band ceiling in dBm (clamped)."""
    c = configured_country()
    if c == "00":
        return min(127, 2 * WORLD_MAX_EIRP_DBM)
    rules = _rules_for_country(c)
    wifi = [r for r in rules if r.freq_start_mhz < 5900]
    if not wifi:
        return min(127, 2 * WORLD_MAX_EIRP_DBM)
    peak = max(r.max_eirp_dbm for r in wifi)
    return min(127, max(2, 2 * peak))


def channel_frequency_mhz(channel: int) -> int | None:
    if 1 <= channel <= 13:
        return 2407 + 5 * channel
    if channel == 14:
        return 2484
    if 36 <= channel <= 177:
        return 5000 + 5 * channel
    if 1 <= channel <= 233:
        return 5950 + 5 * channel
    return None


def ath9k_chan_max_power_dbm(channel: int) -> int:
    """``ieee80211_channel.max_power`` (dBm) for a 2.4 GHz primary channel."""
    c = configured_country()
    if c == "00":
        eirp = _world_max_eirp(channel)
        return eirp if eirp > 0 else WORLD_MAX_EIRP_DBM
    eirp = max_eirp_dbm(c, channel)
    return max(0, eirp)


def ath9k_txpowlimit_half_db(channel: int) -> int:
    """``ath9k`` regulatory limit in half-dBm units (``update_txpow`` / ``power_level * 2``)."""
    return min(254, max(0, 2 * ath9k_chan_max_power_dbm(channel)))


def clamp_realtek_txagc_index(index: int, channel: int) -> int:
    """Apply ``wifi_regulatory_country`` to Realtek 8814-style txagc indices (0..63).

    EFUSE PG indices assume the morrownr/vendor build with regulatory *limits* disabled
    (~world 20 dBm reference). We only *lower* indices when the configured country cap
    is below that reference; never boost above EFUSE."""
    c = configured_country()
    if c == "00":
        return max(0, min(63, index))
    limit_dbm = max_eirp_dbm(c, channel)
    if limit_dbm <= 0:
        return 0
    ref_dbm = _world_max_eirp(channel)
    if ref_dbm <= 0:
        ref_dbm = WORLD_MAX_EIRP_DBM
    if limit_dbm >= ref_dbm:
        return max(0, min(63, index))
    # Vendor index steps track ~0.5 dBm (same convention as mt76 ``2 * dBm``).
    drop = (ref_dbm - limit_dbm) * 2
    return max(0, min(63, index - drop))


def max_eirp_dbm(country: str, channel: int) -> int:
    """Regulatory EIRP ceiling for a primary channel; 0 means disabled."""
    c = normalize_country(country)
    if c == "00":
        return _world_max_eirp(channel)
    mhz = channel_frequency_mhz(channel)
    if mhz is None:
        return 0
    rule = _rule_for_frequency(_rules_for_country(c), mhz)
    if rule is None:
        return 0
    return rule.max_eirp_dbm


def connac_domain(country: str | None = None) -> ConnacDomain:
    """Build the MT7921/MT7925 channel-domain table for ``country``."""
    c = normalize_country(country) if country is not None else configured_country()
    if c == "00":
        return _world_connac_domain()
    rules = _rules_for_country(c)
    if not rules:
        logger.warning("No regdb entry for %s; using world (00)", c)
        return _world_connac_domain()
    alpha2 = c.encode("ascii") + b"\x00\x00"
    ch2 = _build_band_domain(_W00_2G_TEMPLATE, rules, band="2g")
    ch5 = _build_band_domain(_W00_5G_TEMPLATE, rules, band="5g")
    return ConnacDomain(alpha2=alpha2, channels_2ghz=ch2, channels_5ghz=ch5)


def mt7921_enabled(band_idx: int, hw_value: int, country: str | None = None) -> bool:
    c = normalize_country(country) if country is not None else configured_country()
    if c == "00":
        from wifit3.chips.mt7921au import regdomain as rd

        table = rd.CHANNELS_2GHZ if band_idx == 0 else rd.CHANNELS_5GHZ
        return any(hw == hw_value for hw, _ in table)
    dom = connac_domain(c)
    table = dom.channels_2ghz if band_idx == 0 else dom.channels_5ghz
    return any(hw == hw_value for hw, _ in table)


def mt7925_chan_power(band_code: int, channel: int, country: str | None = None) -> int:
    """Regulatory power in 0.5 dBm units for MT7925 SKU tables."""
    from wifit3.chips.mt7925au import txpower as tp

    c = normalize_country(country) if country is not None else configured_country()
    if c == "00":
        return tp._chan_power(band_code, channel)
    if band_code == 3:
        return tp.TX_UNSET_POWER
    eirp = max_eirp_dbm(c, channel)
    if eirp <= 0:
        return tp.TX_UNSET_POWER
    return min(tp.TX_UNSET_POWER, 2 * eirp)


def _world_max_eirp(channel: int) -> int:
    from wifit3.chips.mt7921au import regdomain as rd

    if any(hw == channel for hw, _ in rd.CHANNELS_2GHZ):
        return WORLD_MAX_EIRP_DBM
    if any(hw == channel for hw, _ in rd.CHANNELS_5GHZ):
        return WORLD_MAX_EIRP_DBM
    return 0


def _world_connac_domain() -> ConnacDomain:
    from wifit3.chips.mt7921au import regdomain as rd

    return ConnacDomain(
        alpha2=rd.WORLD_ALPHA2,
        channels_2ghz=tuple(rd.CHANNELS_2GHZ),
        channels_5ghz=tuple(rd.CHANNELS_5GHZ),
    )


# World "00" templates (MT7925 mcu.W00_*), used as HT40/DFS shape when applying regdb.
_B = CHAN_NO_320MHZ
_2G_40 = CHAN_NO_160MHZ | CHAN_NO_80MHZ
_DFS = CHAN_RADAR | CHAN_NO_IR

_W00_2G_TEMPLATE: tuple[tuple[int, int], ...] = (
    (1, _B | _2G_40 | CHAN_NO_HT40MINUS),
    (2, _B | _2G_40 | CHAN_NO_HT40MINUS),
    (3, _B | _2G_40 | CHAN_NO_HT40MINUS),
    (4, _B | _2G_40 | CHAN_NO_HT40MINUS),
    (5, _B | _2G_40),
    (6, _B | _2G_40),
    (7, _B | _2G_40),
    (8, _B | _2G_40),
    (9, _B | _2G_40),
    (10, _B | _2G_40 | CHAN_NO_HT40PLUS),
    (11, _B | _2G_40 | CHAN_NO_HT40PLUS),
    (12, _B | CHAN_NO_160MHZ | CHAN_NO_HT40PLUS | CHAN_NO_IR),
    (13, _B | CHAN_NO_160MHZ | CHAN_NO_HT40PLUS | CHAN_NO_IR),
    (14, _B | _2G_40 | CHAN_NO_OFDM | CHAN_NO_HT40MINUS | CHAN_NO_HT40PLUS | CHAN_NO_IR),
)

_W00_5G_TEMPLATE: tuple[tuple[int, int], ...] = (
    (36, _B | CHAN_NO_HT40MINUS),
    (40, _B),
    (44, _B),
    (48, _B),
    (52, _B | _DFS),
    (56, _B | _DFS),
    (60, _B | _DFS),
    (64, _B | CHAN_NO_HT40PLUS | _DFS),
    (100, _B | CHAN_NO_HT40MINUS | _DFS),
    (104, _B | _DFS),
    (108, _B | _DFS),
    (112, _B | _DFS),
    (116, _B | _DFS),
    (120, _B | _DFS),
    (124, _B | _DFS),
    (128, _B | _DFS),
    (132, _B | _DFS),
    (136, _B | _DFS),
    (140, _B | _DFS),
    (144, _B | CHAN_NO_HT40PLUS | _DFS),
    (149, _B | CHAN_NO_160MHZ | CHAN_NO_HT40MINUS),
    (153, _B | CHAN_NO_160MHZ),
    (157, _B | CHAN_NO_160MHZ),
    (161, _B | CHAN_NO_160MHZ),
    (165, _B | CHAN_NO_160MHZ | CHAN_NO_HT40PLUS),
)


def _build_band_domain(
    template: Iterable[tuple[int, int]],
    rules: tuple[RegRule, ...],
    *,
    band: str,
) -> tuple[tuple[int, int], ...]:
    out: list[tuple[int, int]] = []
    for hw, w00_flags in template:
        mhz = channel_frequency_mhz(hw)
        if mhz is None:
            continue
        if band == "2g" and hw > 14:
            continue
        if band == "5g" and hw <= 14:
            continue
        rule = _rule_for_frequency(rules, mhz)
        if rule is None or rule.max_eirp_dbm <= 0:
            continue
        flags = w00_flags & ~CHAN_NO_IR
        if rule.dfs:
            flags |= CHAN_RADAR
        if rule.no_ir:
            flags |= CHAN_NO_IR
        out.append((hw, flags))
    return tuple(out)


def _rule_for_frequency(rules: tuple[RegRule, ...], mhz: int) -> RegRule | None:
    matches = [r for r in rules if r.freq_start_mhz <= mhz <= r.freq_end_mhz]
    if not matches:
        return None
    return min(matches, key=lambda r: r.max_eirp_dbm)


def _parse_db(text: str) -> dict[str, tuple[RegRule, ...]]:
    countries: dict[str, list[RegRule]] = {}
    current: str | None = None
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = _COUNTRY_RE.match(line)
        if m:
            current = m.group(1)
            countries.setdefault(current, [])
            continue
        if current is None:
            continue
        rm = _RULE_RE.match(line)
        if not rm:
            continue
        start, end, bw, pwr = (int(rm.group(i)) for i in range(1, 5))
        tail = (rm.group(5) or "").upper()
        countries[current].append(
            RegRule(
                freq_start_mhz=start,
                freq_end_mhz=end,
                max_bw_mhz=bw,
                max_eirp_dbm=pwr,
                dfs="DFS" in tail,
                no_ir="NO-IR" in tail,
            )
        )
    return {k: tuple(v) for k, v in countries.items()}


@lru_cache(maxsize=1)
def _regdb() -> dict[str, tuple[RegRule, ...]]:
    raw = resources.files("wifit3.wlan").joinpath("regdb_db.txt").read_text("utf-8")
    return _parse_db(raw)


def _rules_for_country(code: str) -> tuple[RegRule, ...]:
    return _regdb().get(code, ())


@dataclass(frozen=True, slots=True)
class RegulatoryStatus:
    """How ``wifi_regulatory_country`` relates to this card after bring-up."""

    configured: str
    domain_pushed: bool = False
    warm_skip: bool = False
    applies_per_channel: bool = False

    def chip_hint(self, chip: str) -> str:
        """One short fragment for the splash adapter panel (after bring-up)."""
        if self.domain_pushed:
            return f"{chip}: applied"
        if self.warm_skip:
            return f"{chip}: warm (replug if country changed)"
        if self.applies_per_channel:
            return f"{chip}: on tune"
        return f"{chip}: config only"


def display_country(code: str) -> str:
    """User-facing label for a normalized or raw country code."""
    normalized = normalize_country(code)
    return "World" if normalized == "00" else normalized


def set_driver_regulatory_status(
    driver: object,
    *,
    domain_pushed: bool = False,
    warm_skip: bool = False,
    applies_per_channel: bool = False,
) -> RegulatoryStatus:
    """Record what happened during ``connect()`` for splash / diagnostics."""
    status = RegulatoryStatus(
        configured=configured_country(),
        domain_pushed=domain_pushed,
        warm_skip=warm_skip,
        applies_per_channel=applies_per_channel,
    )
    driver.regulatory_status = status
    return status


def finalize_driver_regulatory_status(driver: object) -> RegulatoryStatus:
    """Default status when the driver did not record one explicitly."""
    existing = getattr(driver, "regulatory_status", None)
    if isinstance(existing, RegulatoryStatus):
        return existing
    return set_driver_regulatory_status(driver)


def splash_regulatory_subtitle(
    attached: Iterable[object] | None = None,
) -> str:
    """Subtitle for the splash Wi‑Fi adapter panel."""
    base = f"{display_country(configured_country())} (reg)"
    if not attached:
        return base
    hints: list[str] = []
    for iface in attached:
        driver = getattr(iface, "driver", None)
        status = getattr(driver, "regulatory_status", None) if driver else None
        if not isinstance(status, RegulatoryStatus):
            continue
        chip = (
            getattr(iface, "chipset", None)
            or getattr(iface, "product_name", None)
            or getattr(iface, "name", None)
            or "card"
        )
        hints.append(status.chip_hint(str(chip)))
    if hints:
        return f"{base} · " + " · ".join(hints)
    return base
