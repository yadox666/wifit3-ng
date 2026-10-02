from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class AdvertisedCapabilities:
    """Capabilities explicitly carried by 802.11 management information elements."""

    phy_modes: set[str] = field(default_factory=set)
    channel_widths_mhz: set[int] = field(default_factory=set)
    operating_width_mhz: int | None = None
    secondary_channel_offset: int | None = None
    center_channel_0: int | None = None
    center_channel_1: int | None = None
    channel_conflict: bool = False
    max_spatial_streams: int | None = None
    supported_rates_mbps: set[float] = field(default_factory=set)
    capability_flags: set[str] = field(default_factory=set)
    beacon_interval_tu: int | None = None
    listen_interval: int | None = None
    dtim_period: int | None = None
    station_count: int | None = None
    channel_utilization: int | None = None
    admission_capacity: int | None = None
    power_constraint_db: int | None = None
    power_min_dbm: int | None = None
    power_max_dbm: int | None = None
    country_channels: list[tuple[int, int, int]] = field(default_factory=list)
    country_environment: str | None = None
    supported_channel_ranges: list[tuple[int, int]] = field(default_factory=list)
    radio_measurement: bool = False
    fast_transition: bool = False
    bss_transition: bool = False
    wmm: bool = False
    multi_bssid: bool = False
    reduced_neighbor_report: bool = False
    multi_link: bool = False
    vendor_ouis: set[str] = field(default_factory=set)
    pmf_capable: bool = False
    pmf_required: bool = False
    wps_manufacturer: str | None = None
    wps_model: str | None = None
    wps_device_name: str | None = None
    wps_device_type: str | None = None
    remote_id: str | None = None
    signature_label: str | None = None
    signature_watch: bool = False

    def merge(self, newer: "AdvertisedCapabilities") -> None:
        """Merge newly advertised evidence without erasing previously observed fields."""
        self.phy_modes.update(newer.phy_modes)
        self.channel_widths_mhz.update(newer.channel_widths_mhz)
        self.supported_rates_mbps.update(newer.supported_rates_mbps)
        self.capability_flags.update(newer.capability_flags)
        self.vendor_ouis.update(newer.vendor_ouis)
        if newer.max_spatial_streams is not None:
            self.max_spatial_streams = newer.max_spatial_streams
        operation_fields = (
            "operating_width_mhz", "secondary_channel_offset",
            "center_channel_0", "center_channel_1",
        )
        if any(getattr(newer, name) is not None for name in operation_fields):
            for name in operation_fields:
                setattr(self, name, getattr(newer, name))
        self.channel_conflict = newer.channel_conflict
        for name in (
            "beacon_interval_tu", "listen_interval", "dtim_period", "station_count", "channel_utilization",
            "admission_capacity", "power_constraint_db", "power_min_dbm", "power_max_dbm",
            "country_environment",
            "wps_manufacturer", "wps_model", "wps_device_name", "wps_device_type",
            "remote_id", "signature_label",
        ):
            value = getattr(newer, name)
            if value is not None:
                setattr(self, name, value)
        self.signature_watch = self.signature_watch or newer.signature_watch
        if newer.country_channels:
            self.country_channels = list(newer.country_channels)
        if newer.supported_channel_ranges:
            self.supported_channel_ranges = list(newer.supported_channel_ranges)
        for name in (
            "radio_measurement", "fast_transition", "bss_transition", "wmm",
            "multi_bssid", "reduced_neighbor_report", "multi_link",
            "pmf_capable", "pmf_required",
        ):
            setattr(self, name, getattr(self, name) or getattr(newer, name))
