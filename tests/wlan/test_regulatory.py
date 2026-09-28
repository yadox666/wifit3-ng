import copy

import pytest

from wifit3.persist.config import Config
from wifit3.wlan import regulatory as reg


@pytest.fixture(autouse=True)
def _country_default():
    prev = Config.wifi_regulatory_country
    Config.wifi_regulatory_country = "00"
    yield
    Config.wifi_regulatory_country = prev


def test_normalize_country_world_aliases():
    assert reg.normalize_country("") == "00"
    assert reg.normalize_country("00") == "00"
    assert reg.normalize_country("0") == "00"
    assert reg.normalize_country("world") == "00"
    assert reg.normalize_country("US") == "US"


def test_configured_country_empty_config_is_world():
    Config.wifi_regulatory_country = ""
    assert reg.configured_country() == "00"
    Config.wifi_regulatory_country = "00"
    assert reg.configured_country() == "00"


def test_us_max_eirp_unii1_vs_unii3():
    assert reg.max_eirp_dbm("US", 36) == 23
    assert reg.max_eirp_dbm("US", 149) == 30
    assert reg.max_eirp_dbm("US", 1) == 30


def test_us_connac_domain_drops_passive_only_world_edges():
    dom = reg.connac_domain("US")
    assert dom.alpha2[:2] == b"US"
    ch2 = {hw for hw, _ in dom.channels_2ghz}
    assert 1 in ch2 and 11 in ch2
    assert 14 not in ch2
    ch5 = dict(dom.channels_5ghz)
    assert ch5[36] & reg.CHAN_NO_IR == 0
    assert ch5[52] & reg.CHAN_RADAR


def test_world_connac_matches_mt7921_regdomain():
    from wifit3.chips.mt7921au import regdomain as rd

    dom = reg.connac_domain("00")
    assert dom.alpha2 == rd.WORLD_ALPHA2
    assert dom.channels_2ghz == tuple(rd.CHANNELS_2GHZ)
    assert dom.channels_5ghz == tuple(rd.CHANNELS_5GHZ)


def test_mt7921_txpower_unchanged_for_world():
    from wifit3.chips.mt7921au import txpower
    from wifit3.chips.mt7921au.mcu import NicCaps

    ref = NicCaps(has_2ghz=True, has_5ghz=True, has_6ghz=True)
    Config.wifi_regulatory_country = "00"
    baseline = txpower.rate_txpower_payloads(ref)
    assert txpower.rate_txpower_payloads(ref) == baseline


def test_mt7921_txpower_us_raises_unii3():
    from wifit3.chips.mt7921au import txpower
    from wifit3.chips.mt7921au.mcu import NicCaps

    caps = NicCaps(has_2ghz=True, has_5ghz=True, has_6ghz=False)
    Config.wifi_regulatory_country = "00"
    world = txpower.rate_txpower_payloads(caps)
    Config.wifi_regulatory_country = "US"
    us = txpower.rate_txpower_payloads(caps)
    assert world != us


def test_txpower_conf_units_us():
    Config.wifi_regulatory_country = "US"
    assert reg.txpower_conf_units() == 60


def test_ath9k_txpowlimit_world_and_us():
    Config.wifi_regulatory_country = "00"
    assert reg.ath9k_txpowlimit_half_db(1) == 40
    Config.wifi_regulatory_country = "US"
    assert reg.ath9k_txpowlimit_half_db(1) == 60


def test_clamp_realtek_txagc_world_unchanged():
    Config.wifi_regulatory_country = "00"
    assert reg.clamp_realtek_txagc_index(40, 1) == 40


def test_clamp_realtek_txagc_lowers_when_country_cap_below_world():
    Config.wifi_regulatory_country = "CF"
    idx = reg.clamp_realtek_txagc_index(40, 36)
    assert idx == 34  # world 20 dBm vs CF UNII-1 17 dBm -> drop 6 index steps
