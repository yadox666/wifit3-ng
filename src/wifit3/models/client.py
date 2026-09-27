"""The wireless-client scan model."""
from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field
from functools import cached_property
from typing import TYPE_CHECKING, Dict, Optional, Set

from .capabilities import AdvertisedCapabilities
from .enterprise import EnterpriseProfile

if TYPE_CHECKING:
    from wifit3.id import Fingerprint


@dataclass
class ProbeObservation:
    """Latest channel and timing evidence for one directed probe SSID."""

    channel: int
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    count: int = 1
    historical: bool = False


@dataclass
class Client:
    """A wireless client (e.g. a phone or laptop)."""
    mac: str
    bssid: Optional[str] = None  # The AP it is currently connected to or probing for
    packets: int = 0
    is_fake: bool = False  # Temporary station created by an active campaign
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    probed_ssids: Set[str] = field(default_factory=set)  # SSIDs this client is actively searching for
    probe_observations: Dict[str, ProbeObservation] = field(default_factory=dict)
    # AKM suite chosen by this client, read from the RSN IE in its (Re)Assoc Request. Latest-wins.
    akm_selected: Optional[int] = None
    capabilities: AdvertisedCapabilities = field(default_factory=AdvertisedCapabilities)
    enterprise: EnterpriseProfile = field(default_factory=EnterpriseProfile)
    # Smoothed RSSI per receiving card (card name -> dBm), written by WlanSink.
    signal_by_card: Dict[str, int] = field(default_factory=dict)
    signal_history: Dict[str, deque[int]] = field(default_factory=dict, repr=False)

    @property
    def signal(self) -> int:
        """Strongest smoothed RSSI (dBm) across the cards that hear this client; -100 if none yet."""
        return max(self.signal_by_card.values(), default=-100)

    @cached_property
    def fingerprint(self) -> Optional[Fingerprint]:
        """OUI vendor for this client; looked up once, then cached on the instance."""
        from wifit3.id import fingerprint_client
        return fingerprint_client(self.mac)
