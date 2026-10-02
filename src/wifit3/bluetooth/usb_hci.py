from __future__ import annotations

import asyncio
import os
import sys
import logging
import struct
import threading
import time
from collections import deque
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Any, Callable

if TYPE_CHECKING:
    from wifit3.persist.bluetooth_bonds import BluetoothBondStore

import libusb_package
import usb.core
import usb.util

from wifit3.bluetooth.hci_protocol import (
    hci_status_message,
    HCI_CREATE_CONNECTION,
    HCI_CREATE_CONNECTION_CANCEL,
    HCI_DISCONNECT,
    HCI_IO_CAPABILITY_REQUEST_NEG_REPLY,
    HCI_LINK_KEY_REQUEST_NEG_REPLY,
    HCI_PIN_CODE_REQUEST_NEG_REPLY,
    EVENT_INQUIRY_COMPLETE,
    EVENT_REMOTE_NAME_REQUEST_COMPLETE,
    HCI_INQUIRY,
    HCI_INQUIRY_CANCEL,
    HCI_LE_SET_EVENT_MASK,
    CLASSIC_INQUIRY_LENGTH_FULL,
    CLASSIC_INQUIRY_LENGTH_SHORT,
    classic_inquiry_parameters,
    classic_inquiry_timeout_ms,
    LE_EVENT_MASK_SCAN_AND_CONNECT,
    LE_SCAN_PARAMETERS,
    HCI_LE_SET_SCAN_ENABLE,
    HCI_LE_SET_SCAN_PARAMETERS,
    HCI_READ_LOCAL_VERSION,
    HCI_LE_READ_BUFFER_SIZE,
    HCI_READ_BUFFER_SIZE,
    HCI_REMOTE_OOB_DATA_REQUEST_NEG_REPLY,
    HCI_USER_CONFIRMATION_REQUEST_NEG_REPLY,
    HCI_USER_PASSKEY_REQUEST_NEG_REPLY,
    HCI_REMOTE_NAME_REQUEST,
    HCI_REMOTE_NAME_REQUEST_CANCEL,
    HCI_RESET,
    HCI_SET_EVENT_MASK,
    HCI_WRITE_INQUIRY_MODE,
    HCI_AUTHENTICATION_REQUESTED,
    HCI_LINK_KEY_REQUEST_REPLY,
    HCI_SET_CONNECTION_ENCRYPTION,
    EVENT_AUTHENTICATION_COMPLETE,
    EVENT_DISCONNECTION_COMPLETE,
    EVENT_ENCRYPTION_CHANGE,
    EVENT_LINK_KEY_REQUEST,
    EVENT_LINK_KEY_NOTIFICATION,
    DiscoveryObservation,
    command_packet,
    command_result,
    parse_discovery_event,
    parse_event,
    parse_remote_name_event,
)
from wifit3.bluetooth.analytics import (
    ble_advertisement_matches_target,
    discovery_names_match,
    normalized_bluetooth_name,
)
from wifit3.bluetooth.classic_sdp import (
    L2CAP_CONFIGURATION_REQUEST,
    L2CAP_CONFIGURATION_RESPONSE,
    L2CAP_CONNECTION_REQUEST,
    L2CAP_CONNECTION_RESPONSE,
    L2CAP_DISCONNECTION_REQUEST,
    L2CAP_DISCONNECTION_RESPONSE,
    L2CAP_ECHO_REQUEST,
    L2CAP_ECHO_RESPONSE,
    L2CAP_INFORMATION_REQUEST,
    L2CAP_INFORMATION_RESPONSE,
    L2CAP_SIGNALING_CID,
    SDP_PSM,
    SDP_SERVICE_SEARCH_ATTRIBUTE_REQUEST,
    SDP_SERVICE_SEARCH_ATTRIBUTE_RESPONSE,
    SdpProtocolError,
    SdpService,
    iter_signaling_commands,
    l2cap_packet,
    parse_service_records,
    parse_service_search_attribute_response,
    service_search_attribute_request,
    signaling_command,
)
from wifit3.models.bluetooth_device import BLE_RADIO, CLASSIC_RADIO, BluetoothDevice
from wifit3.bluetooth.rtl8761_firmware import (
    RTL_DOWNLOAD_OPCODE,
    RTL_FIRMWARE_COMMAND_TIMEOUT_MS,
    RTL_ROM_VERSION_OPCODE,
    RTL8761BU_HCI_VERSION,
    RTL8761BU_MANUFACTURER,
    RTL8761BU_PATCHED_LMP,
    RTL8761BU_STOCK_LMP,
    download_fragments,
    load_download_image,
)

logger = logging.getLogger(__name__)


def _device_supports_classic_sdp(device: BluetoothDevice) -> bool:
    if CLASSIC_RADIO in device.radio_types:
        return True
    return device.class_of_device is not None


def classic_observation_from_device(
    device: BluetoothDevice,
) -> DiscoveryObservation | None:
    """Rebuild inquiry parameters after a scanner restart cleared the USB cache."""
    if not _device_supports_classic_sdp(device):
        return None
    return DiscoveryObservation(
        identifier=device.identifier,
        radio_type=CLASSIC_RADIO,
        rssi=device.rssi,
        name=device.name or "<Unknown>",
        service_uuids=tuple(device.service_uuids),
        service_data_uuids=tuple(device.service_data_uuids),
        manufacturer_ids=tuple(device.manufacturer_ids),
        manufacturer_data_bytes=device.manufacturer_data_bytes,
        service_data_bytes=device.service_data_bytes,
        tx_power=device.tx_power,
        class_of_device=device.class_of_device,
        appearance=device.appearance,
        address_type=device.address_type,
        payload_fingerprint=device.payload_fingerprint,
        protocol_category=device.protocol_category,
        protocol_type=device.protocol_type,
        protocol_source=device.protocol_source,
        protocol_confidence=device.protocol_confidence,
        page_scan_repetition_mode=device.page_scan_repetition_mode or 1,
        clock_offset=device.clock_offset or 0,
        decode_state=device.decode_state,
        signature_watch="1" if device.signature_watch else "",
    )


HCI_MAX_EVENT_SIZE = 257
HCI_MAX_ACL_SIZE = 4096
EVENT_CONNECTION_COMPLETE = 0x03
EVENT_NUMBER_OF_COMPLETED_PACKETS = 0x13
_REMOTE_NAME_STALL_S = 6.0
# Dual-mode dongles share a single radio between BR/EDR inquiry and LE scanning.
# A running inquiry hops the BR/EDR channels and blacks out LE advertisement
# reception for its whole window, so back-to-back inquiry makes the adapter
# "deaf" to BLE. Leave a dedicated LE dwell between inquiry cycles so nearby
# BLE devices are still heard.
_LE_SCAN_DWELL_S = 4.0
# Recover if an inquiry never reports completion (e.g. the controller wedged or
# the device was unplugged mid-cycle) so Classic discovery does not stall.
_CLASSIC_INQUIRY_STUCK_S = 18.0


def classic_remote_names_enabled() -> bool:
    """Optional slow Classic remote-name resolution (off by default for scan throughput)."""
    return os.environ.get("WIFIT3_BT_CLASSIC_REMOTE_NAMES", "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }

_PAIRING_NEGATIVE_REPLIES = {
    0x16: HCI_PIN_CODE_REQUEST_NEG_REPLY,
    0x17: HCI_LINK_KEY_REQUEST_NEG_REPLY,
    0x31: HCI_IO_CAPABILITY_REQUEST_NEG_REPLY,
    0x33: HCI_USER_CONFIRMATION_REQUEST_NEG_REPLY,
    0x34: HCI_USER_PASSKEY_REQUEST_NEG_REPLY,
    0x35: HCI_REMOTE_OOB_DATA_REQUEST_NEG_REPLY,
}


_SUPPORTED_CONTROLLERS = {
    (0x0A12, 0x0001): ("BlueCore4-ROM", "Sena", "Parani-UD100", True, False),
    (0x0BDA, 0x8771): ("RTL8761BU", "Realtek", "Bluetooth 5 USB Adapter", True, True),
    (0x0BDA, 0xA728): ("RTL8761BU", "Realtek", "Bluetooth USB Adapter", True, True),
    (0x2357, 0x0604): ("RTL8761BU", "TP-Link", "Bluetooth USB Adapter", True, True),
    (0x2357, 0x0607): ("RTL8761BU", "TP-Link", "Bluetooth USB Adapter", True, True),
    (0x0B05, 0x190E): ("RTL8761BU", "ASUS", "Bluetooth USB Adapter", True, True),
    (0x2C4E, 0x0115): ("RTL8761BU", None, "Bluetooth USB Adapter", True, True),
    (0x2550, 0x8761): ("RTL8761BU", None, "Bluetooth USB Adapter", True, True),
    (0x6655, 0x8771): ("RTL8761BU", None, "Bluetooth USB Adapter", True, True),
    (0x7392, 0xC611): ("RTL8761BU", None, "Bluetooth USB Adapter", True, True),
    (0x2B89, 0x8761): ("RTL8761BU", "UGREEN", "Bluetooth USB Adapter", True, True),
    (0x2B89, 0x6275): ("RTL8761BU", "UGREEN", "Bluetooth USB Adapter", True, True),
}


class UsbBluetoothError(RuntimeError):
    def __init__(self, message: str, *, hci_status: int | None = None) -> None:
        super().__init__(message)
        self.hci_status = hci_status


@dataclass(slots=True)
class HciScannerHealth:
    event_packets: int = 0
    malformed_events: int = 0
    classic_observations: int = 0
    ble_observations: int = 0
    inquiry_completions: int = 0
    remote_name_requests: int = 0
    remote_name_successes: int = 0
    remote_name_failures: int = 0
    read_errors: int = 0
    last_event_at: float | None = None


@dataclass(frozen=True, slots=True)
class HciCaptureRecord:
    timestamp: float
    packet_type: int
    incoming: bool
    payload: bytes


@dataclass(frozen=True, slots=True)
class UsbBluetoothController:
    vid: int
    pid: int
    chipset: str
    vendor: str | None
    product_name: str
    bus: int | None
    address: int | None
    supports_classic: bool = True
    supports_le: bool = True

    @property
    def instance_key(self) -> tuple:
        return self.vid, self.pid, self.bus, self.address

    @property
    def label(self) -> str:
        brand = " ".join(part for part in (self.vendor, self.product_name) if part)
        return f"{self.chipset} · {brand}" if brand else self.chipset


def _device_exposes_bluetooth_hci(device) -> bool:
    """True when the USB device presents a Bluetooth primary HCI interface."""
    try:
        configuration = device.get_active_configuration()
    except (usb.core.USBError, AttributeError, ValueError):
        try:
            device.set_configuration()
            configuration = device.get_active_configuration()
        except (usb.core.USBError, AttributeError, ValueError):
            return False
    try:
        interfaces = tuple(configuration)
    except TypeError:
        return False
    return any(
        intf.bInterfaceClass == 0xE0
        and intf.bInterfaceSubClass == 0x01
        and intf.bInterfaceProtocol == 0x01
        for intf in interfaces
    )


def find_usb_bluetooth_controllers() -> list[UsbBluetoothController]:
    backend = libusb_package.get_libusb1_backend()
    try:
        devices = usb.core.find(find_all=True, backend=backend)
    except usb.core.NoBackendError:
        return []
    controllers = []
    for device in devices or ():
        identity = _SUPPORTED_CONTROLLERS.get((device.idVendor, device.idProduct))
        if identity is None:
            continue
        if not _device_exposes_bluetooth_hci(device):
            continue
        chipset, vendor, product, supports_classic, supports_le = identity
        controllers.append(UsbBluetoothController(
            vid=device.idVendor,
            pid=device.idProduct,
            chipset=chipset,
            vendor=vendor,
            product_name=product,
            bus=getattr(device, "bus", None),
            address=getattr(device, "address", None),
            supports_classic=supports_classic,
            supports_le=supports_le,
        ))
    return controllers


class UsbHciScanner:
    def __init__(
        self,
        controller: UsbBluetoothController,
        detection_callback: Callable[[DiscoveryObservation], None],
        *,
        bond_store: "BluetoothBondStore | None" = None,
    ) -> None:
        self.controller = controller
        self._detection_callback = detection_callback
        self._lab_facade = None
        self._gatt_access = None
        self._device = None
        self._event_endpoint = None
        self._acl_in_endpoint = None
        self._acl_out_endpoint = None
        self._interface_number = 0
        self._detached_kernel_driver = False
        self._running = False
        self._scan_task: asyncio.Task | None = None
        self.health = HciScannerHealth()
        self.sdp_trace: list[str] = []
        self._capture_records: deque[HciCaptureRecord] = deque(maxlen=50_000)
        self._lab_debug: Any = None
        self._pairing_context: Any = None
        self._bias_posture_context: Any = None
        self._session_link_keys: dict[str, bytes] = {}
        if bond_store is None:
            from wifit3.persist.bluetooth_bonds import BluetoothBondStore

            bond_store = BluetoothBondStore()
        self._bond_store = bond_store
        self._classic_acl_handles: dict[str, int] = {}
        self._hci_lock = threading.RLock()
        self._classic_observations: dict[str, DiscoveryObservation] = {}
        self._remote_name_queue: deque[str] = deque()
        self._remote_name_queued: set[str] = set()
        self._remote_name_resolved: set[str] = set()
        self._remote_name_pending: str | None = None
        self._remote_name_started_at: float | None = None
        self._last_inquiry_complete_at: float | None = None
        self._classic_inquiry_active: bool = False
        self._classic_inquiry_started_at: float | None = None
        self._scan_event_ticks: int = 0
        self._pending_events: deque[tuple[int, bytes]] = deque()
        self._acl_stream = bytearray()
        self._acl_mtu = 0
        self._acl_credits = 0
        self._acl_credit_limit = 0
        # LE-U links must use PB flag 0b00 (non-flushable); BR/EDR uses 0b10
        # (auto-flushable). Track LE handles so _send_l2cap picks the right one.
        self._le_acl_handles: set[int] = set()
        # When OS Bleak scans BLE, USB HCI skips legacy LE scan so Classic inquiry
        # does not fight the same radio (and extended advertising stays on the OS path).
        self._usb_le_scan_enabled = controller.supports_le
        self._load_persisted_bonds()

    def _load_persisted_bonds(self) -> None:
        """Seed the session link-key cache from the persistent bond store.

        Lets the lab reconnect to an authorized target in a future session
        without re-pairing. Link keys are secrets and are never logged.
        """
        if self._bond_store is None:
            return
        try:
            bonds = self._bond_store.load()
        except OSError as exc:
            logger.warning("Could not load Bluetooth bonds: %s", exc)
            return
        for folded, bond in bonds.items():
            self._session_link_keys.setdefault(folded, bond.link_key)
        if bonds:
            logger.info(
                "Loaded %d persisted Bluetooth bond(s) for reconnect", len(bonds)
            )

    def use_os_ble_for_le_discovery(self) -> None:
        """Classic BR/EDR on USB; let the OS adapter run BLE discovery."""
        self._usb_le_scan_enabled = False

    def _classic_inquiry_length(self) -> int:
        if self._usb_le_scan_enabled and self.controller.supports_le:
            return CLASSIC_INQUIRY_LENGTH_SHORT
        return CLASSIC_INQUIRY_LENGTH_FULL

    def _classic_inquiry_command(self) -> tuple[bytes, int]:
        length = self._classic_inquiry_length()
        return (
            classic_inquiry_parameters(length),
            classic_inquiry_timeout_ms(length),
        )

    def _run_classic_inquiry(self) -> None:
        parameters, timeout_ms = self._classic_inquiry_command()
        self._command(HCI_INQUIRY, parameters, timeout_ms=timeout_ms)
        self._mark_classic_inquiry_started()

    @property
    def is_scanning(self) -> bool:
        return self._running

    @property
    def capture_records(self) -> tuple[HciCaptureRecord, ...]:
        return tuple(self._capture_records)

    @property
    def capture_record_count(self) -> int:
        return len(self._capture_records)

    def capture_records_since(self, start_index: int) -> tuple[HciCaptureRecord, ...]:
        if start_index <= 0:
            return self.capture_records
        return tuple(list(self._capture_records)[start_index:])

    def set_lab_debug(self, session: Any | None) -> None:
        self._lab_debug = session

    def lab_debug_event(self, phase: str, name: str, **details: Any) -> None:
        session = self._lab_debug
        if session is not None:
            session.event(phase, name, **details)

    def lab_step(self, message: str) -> None:
        session = self._lab_debug
        if session is not None:
            session.step(message)

    def ensure_le_connection_events(self) -> None:
        """LE Create Connection needs Connection Complete (mask bit 0), not scan-only 0x02."""
        if self._device is None or not self.controller.supports_le:
            return
        try:
            self._command(HCI_LE_SET_EVENT_MASK, LE_EVENT_MASK_SCAN_AND_CONNECT)
        except UsbBluetoothError:
            logger.debug("Could not refresh LE event mask", exc_info=True)

    def prepare_le_acl_buffers(self) -> None:
        """Seed ACL MTU/credit accounting for an LE link.

        The Classic path seeds ``_acl_credits``/``_acl_mtu`` from Read Buffer Size,
        but an LE-only connection never ran that path, so any L2CAP write would
        stall until "ACL transmit credits timed out". LE controllers report their
        own buffer pool via LE Read Buffer Size; when that pool is zero the spec
        says the BR/EDR pool is shared, so fall back to Read Buffer Size.
        """
        mtu = 0
        credits = 0
        try:
            le_buffer = self._command(HCI_LE_READ_BUFFER_SIZE)
        except UsbBluetoothError:
            le_buffer = b""
        if len(le_buffer) >= 4 and le_buffer[0] == 0:
            mtu = int.from_bytes(le_buffer[1:3], "little")
            credits = le_buffer[3]
        if mtu <= 0 or credits <= 0:
            # Shared buffer pool (LE values zero) — use the BR/EDR buffers.
            try:
                buffer_size = self._command(HCI_READ_BUFFER_SIZE)
            except UsbBluetoothError:
                buffer_size = b""
            if len(buffer_size) >= 8 and buffer_size[0] == 0:
                mtu = int.from_bytes(buffer_size[1:3], "little")
                credits = int.from_bytes(buffer_size[4:6], "little")
        if mtu <= 0 or credits <= 0:
            raise UsbBluetoothError("Controller reported no usable LE ACL buffers")
        self._acl_mtu = mtu
        self._acl_credits = credits
        self._acl_credit_limit = credits

    def wait_for_ble_advertisement(
        self,
        identifier: str,
        timeout_s: float = 3.0,
        *,
        alternate_identifiers: tuple[str, ...] = (),
        name: str = "",
    ) -> DiscoveryObservation | None:
        """Enable LE scan briefly and return the first matching advertisement, if any."""
        if self._device is None or not self.controller.supports_le:
            return None
        self.ensure_le_connection_events()
        try:
            self._command(
                HCI_LE_SET_SCAN_PARAMETERS,
                LE_SCAN_PARAMETERS,
            )
            self._command(HCI_LE_SET_SCAN_ENABLE, b"\x01\x00")
        except UsbBluetoothError:
            logger.debug("Could not start LE scan for lab prewarm", exc_info=True)
            return None
        deadline = time.monotonic() + max(0.5, timeout_s)
        found: DiscoveryObservation | None = None
        while time.monotonic() < deadline:
            if self._pending_events:
                event_code, parameters = self._pending_events.popleft()
            else:
                packet = self._read_event(
                    max(1, int((deadline - time.monotonic()) * 1000)),
                )
                if packet is None:
                    continue
                parsed = self._parse_event_packet(packet)
                if parsed is None:
                    continue
                event_code, parameters = parsed
            for observation in parse_discovery_event(event_code, parameters):
                if observation.radio_type != BLE_RADIO:
                    continue
                if not ble_advertisement_matches_target(
                    observation.identifier,
                    observation.name,
                    identifier,
                    alternate_identifiers=alternate_identifiers,
                    target_name=name,
                ):
                    continue
                found = observation
                break
            if found is not None:
                break
        try:
            self._command(HCI_LE_SET_SCAN_ENABLE, b"\x00\x00")
        except UsbBluetoothError:
            pass
        if found is not None:
            self.lab_debug_event(
                "le",
                "adv_seen",
                address=found.identifier,
                rssi=found.rssi,
                address_type=found.address_type,
            )
        else:
            self.lab_debug_event("le", "adv_timeout", address=identifier)
        return found

    def remember_session_link_key(
        self,
        identifier: str,
        link_key: bytes,
        *,
        key_type: int | None = None,
        name: str | None = None,
        persist: bool = True,
    ) -> None:
        if len(link_key) != 16:
            return
        self._session_link_keys[identifier.casefold()] = bytes(link_key)
        self.lab_debug_event(
            "pairing",
            "bond_cached",
            address=identifier,
            note="session link key cached in RAM (key value not logged)",
        )
        if not (persist and self._bond_store is not None):
            return
        if name is None:
            observation = self._classic_observations.get(identifier.casefold())
            name = getattr(observation, "name", None)
        try:
            self._bond_store.save_bond(
                identifier, link_key, key_type=key_type, name=name
            )
        except OSError as exc:
            logger.warning("Could not persist Bluetooth bond: %s", exc)
            return
        self.lab_debug_event(
            "pairing",
            "bond_persisted",
            address=identifier,
            note="link key written to bond store (0600); key value not logged",
        )

    def has_session_link_key(self, identifier: str) -> bool:
        return identifier.casefold() in self._session_link_keys

    def forget_bond(self, identifier: str) -> bool:
        """Drop a bond from RAM and the persistent store. Returns True if removed."""
        self._session_link_keys.pop(identifier.casefold(), None)
        if self._bond_store is None:
            return False
        try:
            return self._bond_store.forget(identifier)
        except OSError as exc:
            logger.warning("Could not forget Bluetooth bond: %s", exc)
            return False

    @staticmethod
    def _identifier_from_bd_addr(raw: bytes) -> str:
        return ":".join(f"{part:02X}" for part in reversed(raw[:6]))

    def _reply_stored_link_key(self, bd_addr: bytes) -> bool:
        identifier = self._identifier_from_bd_addr(bd_addr)
        key = self._session_link_keys.get(identifier.casefold())
        if key is None:
            return False
        self._command(HCI_LINK_KEY_REQUEST_REPLY, bd_addr + key)
        self.lab_debug_event("pairing", "link_key_reused", address=identifier)
        return True

    def classic_prepare_bonded_acl(self, handle: int, identifier: str) -> None:
        """Authenticate + encrypt when a session link key exists from pairing lab."""
        if not self.has_session_link_key(identifier):
            return
        try:
            self._command(
                HCI_AUTHENTICATION_REQUESTED,
                struct.pack("<H", handle),
                8_000,
            )
        except UsbBluetoothError:
            pass
        deadline = time.monotonic() + 8.0
        encrypted = False
        while time.monotonic() < deadline:
            if self._pending_events:
                code, parameters = self._pending_events.popleft()
            else:
                packet = self._read_event(
                    max(1, int((deadline - time.monotonic()) * 1000)),
                )
                if packet is None:
                    continue
                parsed = self._parse_event_packet(packet)
                if parsed is None:
                    continue
                code, parameters = parsed
            if not self._handle_aux_hci_event(code, parameters, handle):
                if code == EVENT_ENCRYPTION_CHANGE and len(parameters) >= 4:
                    status = parameters[0]
                    event_handle = int.from_bytes(parameters[1:3], "little") & 0x0FFF
                    if event_handle == handle and status == 0 and parameters[3] == 1:
                        encrypted = True
                        break
        if not encrypted:
            try:
                self._command(
                    HCI_SET_CONNECTION_ENCRYPTION,
                    struct.pack("<HB", handle, 0x01),
                    8_000,
                )
            except UsbBluetoothError:
                pass

    def run_classic_pairing_session(
        self,
        acl_handle: int,
        identifier: str,
        timeout_s: float = 45.0,
        *,
        pin_entry=None,
        ssp_only: bool = False,
        io_capability: int | None = None,
        mitm: bool = False,
        passkey_provider=None,
        confirm_provider=None,
    ):
        from wifit3.bluetooth.lab.pairing import ClassicPairingContext
        from wifit3.bluetooth.hci_protocol import IO_CAPABILITY_NO_INPUT_NO_OUTPUT

        if io_capability is None:
            io_capability = IO_CAPABILITY_NO_INPUT_NO_OUTPUT
        ctx = ClassicPairingContext(
            self,
            acl_handle,
            identifier,
            pin_entry=pin_entry,
            ssp_only=ssp_only,
            io_capability=io_capability,
            mitm=mitm,
            passkey_provider=passkey_provider,
            confirm_provider=confirm_provider,
        )
        self._pairing_context = ctx
        ctx.request_authentication()
        deadline = time.monotonic() + max(5.0, timeout_s)
        try:
            while time.monotonic() < deadline and not ctx.done:
                if self._pending_events:
                    code, parameters = self._pending_events.popleft()
                else:
                    packet = self._read_event(
                        max(1, int((deadline - time.monotonic()) * 1000)),
                    )
                    if packet is None:
                        continue
                    parsed = self._parse_event_packet(packet)
                    if parsed is None:
                        continue
                    code, parameters = parsed
                if code == EVENT_DISCONNECTION_COMPLETE:
                    self._handle_aux_hci_event(code, parameters, acl_handle)
                    if ctx.done:
                        break
                    continue
                if not self._handle_aux_hci_event(code, parameters, acl_handle):
                    if code in (
                        EVENT_AUTHENTICATION_COMPLETE,
                        EVENT_ENCRYPTION_CHANGE,
                    ):
                        ctx.handle_event(code, parameters)
            summary = ctx.finalize()
            if ctx._link_key is not None:
                self.remember_session_link_key(
                    identifier,
                    ctx._link_key,
                    key_type=getattr(ctx, "_link_key_type", None),
                )
            return summary
        finally:
            self._pairing_context = None
            ctx._link_key = None

    def run_bias_posture_session(
        self,
        acl_handle: int,
        identifier: str,
        timeout_s: float = 10.0,
    ):
        from wifit3.bluetooth.lab.bias_posture import BiasPostureContext

        bonded = self.has_session_link_key(identifier)
        ctx = BiasPostureContext(
            self,
            acl_handle,
            identifier,
            session_bond_available=bonded,
        )
        self._bias_posture_context = ctx
        ctx.request_authentication()
        deadline = time.monotonic() + max(4.0, timeout_s)
        try:
            while time.monotonic() < deadline and not ctx.done:
                if self._pending_events:
                    code, parameters = self._pending_events.popleft()
                else:
                    packet = self._read_event(
                        max(1, int((deadline - time.monotonic()) * 1000)),
                    )
                    if packet is None:
                        continue
                    parsed = self._parse_event_packet(packet)
                    if parsed is None:
                        continue
                    code, parameters = parsed
                if code == EVENT_DISCONNECTION_COMPLETE:
                    self._handle_aux_hci_event(code, parameters, acl_handle)
                    if ctx.done:
                        break
                    continue
                if not self._handle_aux_hci_event(code, parameters, acl_handle):
                    if code in (
                        EVENT_AUTHENTICATION_COMPLETE,
                        EVENT_ENCRYPTION_CHANGE,
                    ):
                        ctx.handle_event(code, parameters)
            return ctx.finalize()
        finally:
            self._bias_posture_context = None

    def _parse_event_packet(self, packet: bytes) -> tuple[int, bytes] | None:
        try:
            return parse_event(packet)
        except ValueError:
            self.health.malformed_events += 1
            self.lab_debug_event(
                "hci",
                "malformed_event",
                length=len(packet),
                head=packet[:8].hex() if packet else "",
            )
            logger.warning(
                "Skipping malformed HCI event (%d bytes, head=%s)",
                len(packet),
                packet[:4].hex() if packet else "",
            )
            return None

    def _classic_observation_for_sdp(
        self,
        identifier: str,
        fallback_device: BluetoothDevice | None = None,
    ) -> DiscoveryObservation | None:
        observation = self._classic_observations.get(identifier)
        if observation is None:
            folded = identifier.casefold()
            for key, candidate in self._classic_observations.items():
                if key.casefold() == folded:
                    observation = candidate
                    break
        if observation is None and fallback_device is not None:
            if fallback_device.identifier.casefold() == identifier.casefold():
                observation = classic_observation_from_device(fallback_device)
            else:
                for related in fallback_device.related_identifiers:
                    if related.casefold() == identifier.casefold():
                        observation = classic_observation_from_device(fallback_device)
                        break
        if observation is not None:
            self._classic_observations[observation.identifier] = observation
        return observation

    def _discover_classic_target(
        self,
        identifier: str,
        *,
        timeout_s: float = 12.0,
    ) -> DiscoveryObservation | None:
        """Run Classic inquiry until ``identifier`` is seen or the window expires."""
        if self._device is None or not self.controller.supports_classic:
            return None
        folded = identifier.casefold()
        try:
            self._command(HCI_INQUIRY_CANCEL)
        except UsbBluetoothError:
            pass
        deadline = time.monotonic() + timeout_s
        try:
            self._run_classic_inquiry()
        except UsbBluetoothError:
            logger.debug("Classic inquiry for SDP failed to start", exc_info=True)
            return None
        while time.monotonic() < deadline:
            remaining_ms = max(1, int((deadline - time.monotonic()) * 1000))
            packet = self._read_event(min(remaining_ms, 2000))
            if packet is None:
                continue
            parsed = self._parse_event_packet(packet)
            if parsed is None:
                continue
            event_code, parameters = parsed
            for candidate in parse_discovery_event(event_code, parameters):
                if candidate.radio_type != CLASSIC_RADIO:
                    continue
                self._classic_observations[candidate.identifier] = candidate
                if candidate.identifier.casefold() == folded:
                    return candidate
            if event_code == EVENT_CONNECTION_COMPLETE:
                # A page from a previous ACL attempt may complete late while we
                # re-inquire. Preserve it so _classic_acl_connect can adopt the
                # link instead of looping on HCI 0x0b (ACL already exists).
                self._pending_events.append((event_code, parameters))
                continue
            if event_code == EVENT_INQUIRY_COMPLETE:
                if time.monotonic() >= deadline - 2.0:
                    break
                try:
                    self._run_classic_inquiry()
                except UsbBluetoothError:
                    break
        for key, candidate in self._classic_observations.items():
            if key.casefold() == folded:
                return candidate
        return None

    def _discover_classic_by_name(
        self,
        name: str,
        *,
        timeout_s: float = 14.0,
    ) -> DiscoveryObservation | None:
        """Run Classic inquiry until an EIR name matches ``name`` (BLE-only row fallback)."""
        if self._device is None or not self.controller.supports_classic:
            return None
        if not normalized_bluetooth_name(name):
            return None
        try:
            self._command(HCI_INQUIRY_CANCEL)
        except UsbBluetoothError:
            pass
        deadline = time.monotonic() + timeout_s
        try:
            self._run_classic_inquiry()
        except UsbBluetoothError:
            logger.debug("Classic inquiry by name failed to start", exc_info=True)
            return None
        while time.monotonic() < deadline:
            remaining_ms = max(1, int((deadline - time.monotonic()) * 1000))
            packet = self._read_event(min(remaining_ms, 2000))
            if packet is None:
                continue
            parsed = self._parse_event_packet(packet)
            if parsed is None:
                continue
            event_code, parameters = parsed
            for candidate in parse_discovery_event(event_code, parameters):
                if candidate.radio_type != CLASSIC_RADIO:
                    continue
                self._classic_observations[candidate.identifier] = candidate
                if discovery_names_match(candidate.name, name):
                    return candidate
            if event_code == EVENT_CONNECTION_COMPLETE:
                self._pending_events.append((event_code, parameters))
                continue
            if event_code == EVENT_INQUIRY_COMPLETE:
                if time.monotonic() >= deadline - 2.0:
                    break
                try:
                    self._run_classic_inquiry()
                except UsbBluetoothError:
                    break
        for candidate in self._classic_observations.values():
            if discovery_names_match(candidate.name, name):
                return candidate
        return None

    async def browse_sdp(
        self,
        identifier: str,
        *,
        fallback_device: BluetoothDevice | None = None,
    ) -> tuple[SdpService, ...]:
        """Browse public SDP records without pairing or profile writes."""
        self.sdp_trace = [
            f"SDP browse started for {identifier}",
        ]
        observation = self._classic_observation_for_sdp(identifier, fallback_device)
        if observation is None and fallback_device is not None:
            observation = classic_observation_from_device(fallback_device)
            if observation is not None:
                self._classic_observations[observation.identifier] = observation
        was_running = self._running
        self._running = False
        if self._scan_task is not None:
            await self._scan_task
            self._scan_task = None
        if observation is None and self._device is not None:
            observation = await asyncio.to_thread(
                self._discover_classic_target, identifier,
            )
        if observation is None:
            self.sdp_trace.append("Inquiry result: target not visible")
            raise UsbBluetoothError(
                "Classic device is not visible to USB inquiry; keep it in range, "
                "wait for a BT observation in the scanner, then retry SDP"
            )
        try:
            services = await asyncio.to_thread(self._browse_sdp, observation)
            self.sdp_trace.append(
                f"SDP browse complete: {len(services)} public service class(es)",
            )
            return services
        except Exception as exc:
            status = getattr(exc, "hci_status", None)
            code = f" (HCI status 0x{status:02x})" if status is not None else ""
            self.sdp_trace.append(f"Browse failed{code}: {exc}")
            raise
        finally:
            self._remote_name_pending = None
            self._remote_name_queue.clear()
            self._remote_name_queued.clear()
            if was_running and self._device is not None:
                try:
                    await asyncio.to_thread(self._run_classic_inquiry)
                except UsbBluetoothError:
                    logger.debug("Could not resume inquiry after SDP browse", exc_info=True)
                else:
                    self._running = True
                    self._scan_task = asyncio.create_task(self._scan_loop())

    async def start(self) -> None:
        if self._running:
            return
        try:
            await asyncio.to_thread(self._open_and_start)
        except Exception:
            await asyncio.to_thread(self._close)
            raise
        self._running = True
        self._scan_task = asyncio.create_task(self._scan_loop())

    def reserve(self, *, recover: bool = False) -> None:
        if self._device is None:
            self._open(recover=recover)

    def reclaim_from_os(self) -> None:
        """Release from the OS (if needed) and hold the HCI interface for wifit3."""
        self._close()
        self._open(recover=True)

    async def stop(self) -> None:
        self._running = False
        if self._scan_task is not None:
            await self._scan_task
            self._scan_task = None
        await asyncio.to_thread(self._stop_and_close)

    async def pause(self) -> None:
        self._running = False
        if self._scan_task is not None:
            await self._scan_task
            self._scan_task = None
        await asyncio.to_thread(self._stop_and_close, False)

    async def suspend_background_scan(self) -> bool:
        """Stop the async scan loop and quiet inquiry/LE scan for exclusive HCI lab work."""
        was_running = self._running or self._scan_task is not None
        self._running = False
        if self._scan_task is not None:
            await self._scan_task
            self._scan_task = None
        await asyncio.to_thread(self._quiet_rf_discovery)
        return was_running

    async def resume_background_scan(self, was_running: bool) -> None:
        if not was_running or self._device is None:
            return
        await asyncio.to_thread(self._resume_rf_discovery)
        self._running = True
        self._scan_task = asyncio.create_task(self._scan_loop())

    def _quiet_rf_discovery(self) -> None:
        if self._device is None:
            return
        if self.controller.supports_le and self._usb_le_scan_enabled:
            try:
                self._command(HCI_LE_SET_SCAN_ENABLE, b"\x00\x00")
            except UsbBluetoothError:
                pass
        if self.controller.supports_classic:
            try:
                self._command(HCI_INQUIRY_CANCEL)
            except UsbBluetoothError:
                pass

    def _resume_rf_discovery(self) -> None:
        if self.controller.supports_le and self._usb_le_scan_enabled:
            try:
                self._command(HCI_LE_SET_SCAN_ENABLE, b"\x01\x00")
            except UsbBluetoothError:
                logger.debug("Could not resume LE scan after lab", exc_info=True)
        if self.controller.supports_classic:
            try:
                self._run_classic_inquiry()
            except UsbBluetoothError:
                logger.debug("Could not resume inquiry after lab", exc_info=True)

    def release(self) -> None:
        self._close()

    @property
    def gatt(self):
        if self._gatt_access is None:
            from wifit3.bluetooth.usb_gatt import UsbHciGattAccess

            self._gatt_access = UsbHciGattAccess(self)
        return self._gatt_access

    @property
    def lab(self):
        if self._lab_facade is None:
            from wifit3.bluetooth.lab.facade import UsbHciLabFacade

            self._lab_facade = UsbHciLabFacade(self)
        return self._lab_facade

    def _open_and_start(self) -> None:
        if self._device is None:
            self._open()
        self._remote_name_pending = None
        self._remote_name_queue.clear()
        self._remote_name_queued.clear()
        self._reset_controller()
        version = self._command(HCI_READ_LOCAL_VERSION)
        self._load_realtek_firmware(version)
        event_mask = (
            bytes.fromhex("fffffbff07f8bf3d")
            if self.controller.supports_le else
            bytes.fromhex("fffffbff03000000")
        )
        self._command(HCI_SET_EVENT_MASK, event_mask)
        if self.controller.supports_classic:
            inquiry_mode = b"\x02" if self.controller.supports_le else b"\x01"
            self._command(HCI_WRITE_INQUIRY_MODE, inquiry_mode)
        if self.controller.supports_le and self._usb_le_scan_enabled:
            self._command(HCI_LE_SET_EVENT_MASK, LE_EVENT_MASK_SCAN_AND_CONNECT)
            self._command(HCI_LE_SET_SCAN_PARAMETERS, LE_SCAN_PARAMETERS)
            self._command(HCI_LE_SET_SCAN_ENABLE, b"\x01\x00")
        if self.controller.supports_classic:
            self._run_classic_inquiry()

    def _reset_controller(self) -> None:
        """Reset HCI, retrying once when the USB event endpoint misses completion."""
        for attempt in range(2):
            try:
                self._command(HCI_RESET)
                return
            except UsbBluetoothError as exc:
                timed_out = "timed out" in str(exc).casefold()
                if not timed_out:
                    raise
                if attempt == 1:
                    raise UsbBluetoothError(
                        "Bluetooth controller did not acknowledge HCI Reset "
                        "(0x0c03) after 2 attempts. The USB transport/controller "
                        "is likely wedged; reclaim or unplug/replug the adapter.",
                    ) from exc
                logger.warning(
                    "HCI Reset timed out; clearing stale events and retrying once",
                )
                self._pending_events.clear()
                self._acl_stream.clear()
                time.sleep(0.25)

    def _mark_classic_inquiry_started(self) -> None:
        self._classic_inquiry_active = True
        self._classic_inquiry_started_at = time.monotonic()

    def _open(self, *, recover: bool = False) -> None:
        last_error: UsbBluetoothError | None = None
        attempts = 3 if recover else 1
        for attempt in range(attempts):
            try:
                self._open_once()
                return
            except UsbBluetoothError as exc:
                last_error = exc
                if not recover or attempt >= attempts - 1:
                    raise
                from wifit3.bluetooth.usb_claim import (
                    claim_error_is_recoverable,
                    release_os_bluetooth_for_usb_hci,
                )
                if not claim_error_is_recoverable(str(exc)):
                    raise
                release_os_bluetooth_for_usb_hci(self.controller)
                time.sleep(0.35 * (attempt + 1))
        if last_error is not None:
            raise last_error

    def _open_once(self) -> None:
        backend = libusb_package.get_libusb1_backend()
        device = usb.core.find(
            idVendor=self.controller.vid,
            idProduct=self.controller.pid,
            bus=self.controller.bus,
            address=self.controller.address,
            backend=backend,
        )
        if device is None:
            raise UsbBluetoothError("The selected Bluetooth USB controller was disconnected")
        try:
            configuration = device.get_active_configuration()
        except usb.core.USBError:
            device.set_configuration()
            configuration = device.get_active_configuration()
        interface = next(
            (
                candidate for candidate in configuration
                if candidate.bInterfaceClass == 0xE0
                and candidate.bInterfaceSubClass == 0x01
                and candidate.bInterfaceProtocol == 0x01
            ),
            None,
        )
        if interface is None:
            raise UsbBluetoothError(f"{self.controller.chipset} Bluetooth HCI interface was not found")
        self._interface_number = interface.bInterfaceNumber
        try:
            if device.is_kernel_driver_active(self._interface_number):
                device.detach_kernel_driver(self._interface_number)
                self._detached_kernel_driver = True
        except (AttributeError, NotImplementedError):
            pass
        except usb.core.USBError as exc:
            errno = getattr(exc, "errno", None)
            if errno == 2:
                pass
            elif sys.platform == "darwin":
                # macOS does not allow user detach of the Bluetooth driver; claim_interface
                # often still succeeds while bluetoothd holds the device.
                logger.debug(
                    "Skipping Bluetooth USB driver detach on macOS (%s)",
                    exc,
                )
            else:
                raise UsbBluetoothError(
                    f"Could not detach {self.controller.chipset} from the OS Bluetooth driver; "
                    "click ⎋ on the adapter in the startup Bluetooth list to release it from the OS, replug after "
                    "stopping OS use, or bind it to WinUSB on Windows"
                ) from exc
        try:
            usb.util.claim_interface(device, self._interface_number)
        except usb.core.USBError as exc:
            raise UsbBluetoothError(
                f"Could not claim {self.controller.chipset}; click ⎋ on the adapter in the "
                "startup Bluetooth list to release it from the OS, use a dedicated adapter, "
                "or bind it to WinUSB on Windows"
            ) from exc
        endpoint = next(
            (
                candidate for candidate in interface
                if usb.util.endpoint_direction(candidate.bEndpointAddress) == usb.util.ENDPOINT_IN
                and usb.util.endpoint_type(candidate.bmAttributes) == usb.util.ENDPOINT_TYPE_INTR
            ),
            None,
        )
        if endpoint is None:
            raise UsbBluetoothError("RTL8761BU HCI event endpoint was not found")
        acl_in_endpoint = next(
            (
                candidate for candidate in interface
                if usb.util.endpoint_direction(candidate.bEndpointAddress) == usb.util.ENDPOINT_IN
                and usb.util.endpoint_type(candidate.bmAttributes) == usb.util.ENDPOINT_TYPE_BULK
            ),
            None,
        )
        acl_out_endpoint = next(
            (
                candidate for candidate in interface
                if usb.util.endpoint_direction(candidate.bEndpointAddress) == usb.util.ENDPOINT_OUT
                and usb.util.endpoint_type(candidate.bmAttributes) == usb.util.ENDPOINT_TYPE_BULK
            ),
            None,
        )
        self._device = device
        self._event_endpoint = endpoint
        self._acl_in_endpoint = acl_in_endpoint
        self._acl_out_endpoint = acl_out_endpoint

    def _load_realtek_firmware(self, version_result: bytes) -> None:
        if self.controller.chipset != "RTL8761BU":
            return
        if len(version_result) < 9 or version_result[0] != 0:
            raise UsbBluetoothError("RTL8761BU returned an invalid local-version response")
        if self._rtl8761bu_firmware_active(version_result):
            return
        if not self._rtl8761bu_stock_rom(version_result):
            lmp_subversion, hci_revision, hci_version, manufacturer = (
                self._rtl8761bu_identity(version_result)
            )
            raise UsbBluetoothError(
                "Unsupported RTL8761BU controller identity "
                f"(HCI 0x{hci_version:02x}, revision 0x{hci_revision:04x}, "
                f"manufacturer {manufacturer}, LMP subversion "
                f"0x{lmp_subversion:04x})"
            )
        fw_timeout = RTL_FIRMWARE_COMMAND_TIMEOUT_MS
        rom_result = self._command(
            RTL_ROM_VERSION_OPCODE, timeout_ms=fw_timeout,
        )
        if len(rom_result) != 2 or rom_result[0] != 0:
            raise UsbBluetoothError("RTL8761BU ROM-version command failed")
        image = load_download_image(rom_result[1])
        for fragment in download_fragments(image):
            response = self._command(
                RTL_DOWNLOAD_OPCODE, fragment, timeout_ms=fw_timeout,
            )
            if len(response) != 2 or response[0] != 0:
                raise UsbBluetoothError("RTL8761BU rejected a firmware fragment")
        self._pending_events.clear()
        updated = self._command(
            HCI_READ_LOCAL_VERSION, timeout_ms=fw_timeout,
        )
        if not self._rtl8761bu_firmware_active(updated):
            raise UsbBluetoothError(
                "RTL8761BU firmware identity was not active after upload"
            )

    @staticmethod
    def _rtl8761bu_firmware_active(version_result: bytes) -> bool:
        """Patched RAM firmware (Linux reports fw version 0xdfc6d922)."""
        if len(version_result) < 9 or version_result[0] != 0:
            return False
        lmp_subversion, _hci_revision, hci_version, manufacturer = (
            UsbHciScanner._rtl8761bu_identity(version_result)
        )
        return (
            lmp_subversion == RTL8761BU_PATCHED_LMP
            and hci_version == RTL8761BU_HCI_VERSION
            and manufacturer == RTL8761BU_MANUFACTURER
        )

    @staticmethod
    def _rtl8761bu_stock_rom(version_result: bytes) -> bool:
        if len(version_result) < 9 or version_result[0] != 0:
            return False
        lmp_subversion, _hci_revision, hci_version, manufacturer = (
            UsbHciScanner._rtl8761bu_identity(version_result)
        )
        return (
            lmp_subversion == RTL8761BU_STOCK_LMP
            and hci_version == RTL8761BU_HCI_VERSION
            and manufacturer == RTL8761BU_MANUFACTURER
        )

    @staticmethod
    def _rtl8761bu_identity(version_result: bytes) -> tuple[int, int, int, int]:
        return (
            int.from_bytes(version_result[7:9], "little"),
            int.from_bytes(version_result[2:4], "little"),
            version_result[1],
            int.from_bytes(version_result[5:7], "little"),
        )

    def _command(self, opcode: int, parameters: bytes = b"", timeout_ms: int = 5000) -> bytes:
        with self._hci_lock:
            return self._command_locked(opcode, parameters, timeout_ms)

    def _command_locked(
        self,
        opcode: int,
        parameters: bytes,
        timeout_ms: int,
    ) -> bytes:
        if self._device is None:
            raise UsbBluetoothError("Bluetooth USB controller is not open")
        packet = command_packet(opcode, parameters)
        self._capture_records.append(HciCaptureRecord(time.time(), 0x01, False, packet))
        try:
            self._device.ctrl_transfer(
                0x20, 0, 0, 0, packet, timeout=timeout_ms,
            )
        except usb.core.USBError as exc:
            raise UsbBluetoothError(f"HCI command 0x{opcode:04x} failed") from exc
        deadline = time.monotonic() + timeout_ms / 1000
        while time.monotonic() < deadline:
            remaining_ms = max(1, int((deadline - time.monotonic()) * 1000))
            packet = self._read_event_unlocked(remaining_ms)
            if packet is None:
                continue
            parsed = self._parse_event_packet(packet)
            if parsed is None:
                continue
            event_code, event_parameters = parsed
            result = command_result(event_code, event_parameters)
            if result is None or result[0] != opcode:
                self._pending_events.append((event_code, event_parameters))
                continue
            if result[1] != 0:
                status = result[1]
                raise UsbBluetoothError(
                    f"HCI command 0x{opcode:04x} failed: "
                    f"{hci_status_message(status)}",
                    hci_status=status,
                )
            return result[2]
        raise UsbBluetoothError(f"HCI command 0x{opcode:04x} timed out")

    def _read_event(self, timeout_ms: int = 500) -> bytes | None:
        with self._hci_lock:
            return self._read_event_unlocked(timeout_ms)

    def _read_event_unlocked(self, timeout_ms: int = 500) -> bytes | None:
        if self._device is None:
            return None
        try:
            packet = bytes(self._device.read(
                self._event_endpoint.bEndpointAddress,
                HCI_MAX_EVENT_SIZE,
                timeout=timeout_ms,
            ))
            self._capture_records.append(
                HciCaptureRecord(time.time(), 0x04, True, packet)
            )
            self.health.event_packets += 1
            self.health.last_event_at = time.time()
            return packet
        except usb.core.USBError as exc:
            if getattr(exc, "errno", None) in {60, 110} or "timed out" in str(exc).lower():
                return None
            self.health.read_errors += 1
            raise

    async def _scan_loop(self) -> None:
        while self._running:
            if self._pending_events:
                event_code, parameters = self._pending_events.popleft()
            else:
                try:
                    packet = await asyncio.to_thread(self._read_event)
                except usb.core.USBError:
                    logger.debug("Bluetooth USB event read failed", exc_info=True)
                    self._running = False
                    break
                if packet is None:
                    await self._service_classic_schedule()
                    continue
                parsed = self._parse_event_packet(packet)
                if parsed is None:
                    continue
                event_code, parameters = parsed
            observations = parse_discovery_event(event_code, parameters)
            for observation in observations:
                if observation.radio_type == "BT":
                    self.health.classic_observations += 1
                    previous = self._classic_observations.get(observation.identifier)
                    if (
                        observation.name == "<Unknown>"
                        and previous is not None
                        and previous.name != "<Unknown>"
                    ):
                        observation = replace(observation, name=previous.name)
                    self._classic_observations[observation.identifier] = observation
                    if observation.name == "<Unknown>":
                        self._queue_remote_name(observation.identifier)
                    else:
                        self._remote_name_resolved.add(observation.identifier)
                else:
                    self.health.ble_observations += 1
                self._detection_callback(observation)
            if event_code == EVENT_INQUIRY_COMPLETE:
                self.health.inquiry_completions += 1
                self._classic_inquiry_active = False
                self._last_inquiry_complete_at = time.monotonic()
                await self._advance_classic_discovery()
            elif event_code == EVENT_REMOTE_NAME_REQUEST_COMPLETE:
                self._handle_remote_name(parameters)
                await self._advance_classic_discovery()
            self._scan_event_ticks += 1
            if self._scan_event_ticks % 64 == 0:
                self._maybe_recover_stalled_remote_name()
            await self._service_classic_schedule()

    def _queue_remote_name(self, identifier: str) -> None:
        if not classic_remote_names_enabled():
            self._remote_name_resolved.add(identifier)
            return
        if (
            identifier in self._remote_name_resolved
            or identifier in self._remote_name_queued
            or identifier == self._remote_name_pending
            or len(self._remote_name_queue) >= 16
        ):
            return
        self._remote_name_queue.append(identifier)
        self._remote_name_queued.add(identifier)

    def _cancel_pending_remote_name(self) -> None:
        pending = self._remote_name_pending
        self._remote_name_pending = None
        self._remote_name_started_at = None
        if pending is None:
            return
        try:
            address = bytes.fromhex(pending.replace(":", ""))[::-1]
            self._command(HCI_REMOTE_NAME_REQUEST_CANCEL, address)
        except UsbBluetoothError:
            pass
        self._remote_name_resolved.add(pending)

    def _maybe_recover_stalled_remote_name(self) -> None:
        if self._remote_name_pending is None or self._remote_name_started_at is None:
            return
        if time.monotonic() - self._remote_name_started_at < _REMOTE_NAME_STALL_S:
            return
        logger.warning(
            "Classic remote name for %s stalled; resuming inquiry",
            self._remote_name_pending,
        )
        self._cancel_pending_remote_name()

    async def _service_classic_schedule(self) -> None:
        """Re-arm Classic inquiry, but only after LE scanning has had its dwell.

        On a dual-mode dongle BR/EDR inquiry and LE scanning share one radio, so
        running inquiry continuously starves LE advertisement reception. Between
        inquiry cycles we leave the LE scan (already enabled) a dedicated window.
        """
        if not self._running or not self.controller.supports_classic:
            return
        if self._remote_name_pending is not None:
            return
        now = time.monotonic()
        if self._classic_inquiry_active:
            started = self._classic_inquiry_started_at
            if started is None or now - started < _CLASSIC_INQUIRY_STUCK_S:
                return
            logger.debug("Classic inquiry did not complete in time; restarting")
            try:
                await asyncio.to_thread(self._command, HCI_INQUIRY_CANCEL)
            except UsbBluetoothError:
                logger.debug("Inquiry cancel before restart failed", exc_info=True)
            self._classic_inquiry_active = False
        if (
            self._usb_le_scan_enabled
            and self.controller.supports_le
            and self._last_inquiry_complete_at is not None
            and now - self._last_inquiry_complete_at < _LE_SCAN_DWELL_S
        ):
            return
        await self._start_classic_inquiry()

    async def _start_classic_inquiry(self) -> None:
        try:
            await asyncio.to_thread(self._run_classic_inquiry)
        except UsbBluetoothError:
            logger.debug("Could not restart Bluetooth inquiry", exc_info=True)

    async def _advance_classic_discovery(self) -> None:
        """Drain the optional remote-name queue after an inquiry/name completes.

        Inquiry re-arming is handled by :meth:`_service_classic_schedule` so LE
        scanning keeps its dwell; here we only issue one queued remote-name
        request (when remote-name resolution is explicitly enabled).
        """
        if not self._running or not self.controller.supports_classic:
            return
        self._maybe_recover_stalled_remote_name()
        if self._remote_name_pending is not None:
            return
        if not classic_remote_names_enabled():
            return
        while self._remote_name_queue:
            identifier = self._remote_name_queue.popleft()
            self._remote_name_queued.discard(identifier)
            observation = self._classic_observations.get(identifier)
            if observation is None:
                continue
            address = bytes.fromhex(identifier.replace(":", ""))[::-1]
            parameters = (
                address
                + bytes((observation.page_scan_repetition_mode, 0))
                + struct.pack("<H", observation.clock_offset | 0x8000)
            )
            try:
                await asyncio.to_thread(
                    self._command, HCI_REMOTE_NAME_REQUEST, parameters,
                )
            except UsbBluetoothError:
                self.health.remote_name_failures += 1
                self._remote_name_resolved.add(identifier)
                logger.debug(
                    "Could not request the Bluetooth remote name for %s",
                    identifier,
                    exc_info=True,
                )
                continue
            self.health.remote_name_requests += 1
            self._remote_name_pending = identifier
            self._remote_name_started_at = time.monotonic()
            return

    def _handle_remote_name(self, parameters: bytes) -> None:
        pending = self._remote_name_pending
        self._remote_name_pending = None
        self._remote_name_started_at = None
        if len(parameters) >= 7:
            identifier = ":".join(f"{part:02X}" for part in reversed(parameters[1:7]))
        else:
            identifier = pending
        if identifier:
            self._remote_name_resolved.add(identifier)
        result = parse_remote_name_event(parameters)
        if result is None:
            self.health.remote_name_failures += 1
            return
        identifier, name = result
        observation = self._classic_observations.get(identifier)
        if observation is None:
            self.health.remote_name_failures += 1
            return
        named = replace(observation, name=name)
        self._classic_observations[identifier] = named
        self.health.remote_name_successes += 1
        self._detection_callback(named)

    def _browse_sdp(
        self,
        observation: DiscoveryObservation,
    ) -> tuple[SdpService, ...]:
        if self._acl_in_endpoint is None or self._acl_out_endpoint is None:
            raise UsbBluetoothError("The Bluetooth controller has no ACL bulk endpoints")
        handle: int | None = None
        try:
            self.sdp_trace.append(
                "HCI Create Connection request: opcode 0x0405",
            )
            handle = self._classic_acl_connect(observation)
            return self._sdp_session(handle)
        finally:
            if handle is not None:
                self._classic_acl_disconnect(handle)

    def _classic_acl_prepare(self, observation: DiscoveryObservation) -> bytes:
        if self._remote_name_pending is not None:
            pending_address = bytes.fromhex(
                self._remote_name_pending.replace(":", ""),
            )[::-1]
            try:
                self._command(HCI_REMOTE_NAME_REQUEST_CANCEL, pending_address)
            except UsbBluetoothError:
                pass
            self._remote_name_pending = None
        try:
            self._command(HCI_INQUIRY_CANCEL)
        except UsbBluetoothError:
            pass
        self._classic_inquiry_active = False
        address = bytes.fromhex(observation.identifier.replace(":", ""))[::-1]
        buffer_size = self._command(HCI_READ_BUFFER_SIZE)
        if len(buffer_size) < 8 or buffer_size[0] != 0:
            raise UsbBluetoothError("Controller returned an invalid ACL buffer size")
        self._acl_mtu = int.from_bytes(buffer_size[1:3], "little")
        self._acl_credits = int.from_bytes(buffer_size[4:6], "little")
        self._acl_credit_limit = self._acl_credits
        if self._acl_mtu <= 0 or self._acl_credits <= 0:
            raise UsbBluetoothError("Controller reported no usable ACL buffers")
        self._acl_stream.clear()
        # Preserve any late Connection Complete so a 0x0b adoption can find it;
        # drop every other stale event before paging.
        self._pending_events = deque(
            (code, params)
            for code, params in self._pending_events
            if code == EVENT_CONNECTION_COMPLETE
        )
        return address

    def _classic_acl_connect(
        self,
        observation: DiscoveryObservation,
        *,
        paging_clock_valid: bool = True,
        allow_role_switch: bool = True,
    ) -> int:
        if self._acl_in_endpoint is None or self._acl_out_endpoint is None:
            raise UsbBluetoothError("The Bluetooth controller has no ACL bulk endpoints")
        address = self._classic_acl_prepare(observation)
        clock_field = (
            struct.pack("<H", observation.clock_offset | 0x8000)
            if paging_clock_valid
            else struct.pack("<H", 0)
        )
        parameters = (
            address
            + struct.pack("<H", 0xCC18)
            + bytes((observation.page_scan_repetition_mode, 0))
            + clock_field
            + (b"\x01" if allow_role_switch else b"\x00")
        )
        try:
            self._command(HCI_CREATE_CONNECTION, parameters, 15_000)
        except UsbBluetoothError as exc:
            if exc.hci_status != 0x0B:
                raise
            # ACL Connection Already Exists: a prior page completed late (or the
            # target is still linked). Prefer adopting that live link over
            # destroying it and re-paging (which can loop forever on HCI 0x0b).
            adopted = self._adopt_existing_classic_acl(address)
            if adopted is not None:
                self.lab_step(
                    "Classic ACL: adopted the existing link "
                    f"(handle 0x{adopted:04x}) instead of re-paging.",
                )
                self._classic_acl_handles[observation.identifier.casefold()] = adopted
                self.lab_debug_event(
                    "hci",
                    "classic_acl_adopted",
                    address=observation.identifier,
                    handle=adopted,
                )
                return adopted
            self.lab_step(
                "Classic ACL: controller reports an existing link — "
                "tearing down stale ACL and re-paging (HCI 0x0b)…",
            )
            self._recover_stale_classic_acl(address)
            time.sleep(0.5)
            # Recovery disconnected the stale link, which zeroed the ACL buffer
            # accounting; re-prepare so the new link has valid MTU/credits.
            self._classic_acl_prepare(observation)
            self._command(HCI_CREATE_CONNECTION, parameters, 15_000)
        try:
            connection = self._wait_event(EVENT_CONNECTION_COMPLETE, 18_000)
        except UsbBluetoothError:
            try:
                self._command(HCI_CREATE_CONNECTION_CANCEL, address)
                late = self._wait_event(EVENT_CONNECTION_COMPLETE, 2_000)
                if len(late) >= 3 and late[0] == 0:
                    late_handle = int.from_bytes(late[1:3], "little") & 0x0FFF
                    self._command(
                        HCI_DISCONNECT,
                        struct.pack("<HB", late_handle, 0x13),
                    )
            except UsbBluetoothError:
                pass
            raise
        if len(connection) < 11 or connection[0] != 0:
            status = connection[0] if connection else 0xFF
            detail = hci_status_message(status)
            self.lab_debug_event(
                "hci",
                "classic_connect_failed",
                address=observation.identifier,
                status=status,
                message=detail,
                page_scan_repetition_mode=observation.page_scan_repetition_mode,
                clock_offset=observation.clock_offset,
            )
            logger.warning(
                "Classic ACL connect to %s failed (0x%02x): %s",
                observation.identifier,
                status,
                detail,
            )
            raise UsbBluetoothError(
                f"Classic connection failed: {detail}",
                hci_status=status,
            )
        if connection[3:9] != address or connection[9] != 0x01:
            raise UsbBluetoothError("Unexpected Bluetooth connection completed")
        handle = int.from_bytes(connection[1:3], "little") & 0x0FFF
        self.sdp_trace.append(
            f"HCI Connection Complete: status 0x00 (Success), handle 0x{handle:04x}",
        )
        self._classic_acl_handles[observation.identifier.casefold()] = handle
        return handle

    def _adopt_existing_classic_acl(self, address: bytes) -> int | None:
        """Handle of an already-open ACL to ``address`` (late Connection Complete).

        When ``Create Connection`` returns HCI 0x0b the controller still holds a
        link whose ``Connection Complete`` arrived after an earlier attempt gave
        up. The ACL buffers were just re-read by ``_classic_acl_prepare``, so if
        we can find that handle we can use the live link directly.
        """
        return self._drain_connection_complete_for(address, 2_500)

    def _recover_stale_classic_acl(self, address: bytes) -> bool:
        """Disconnect an ACL the controller still holds for ``address`` (HCI 0x0b).

        Handles both a page we tracked and a Connection Complete that arrived
        after we gave up waiting (and so leaked its handle).
        """
        recovered = False
        identifier = self._identifier_from_bd_addr(address)
        tracked = self._classic_acl_handles.pop(identifier.casefold(), None)
        if tracked is not None:
            self._classic_acl_disconnect(tracked)
            recovered = True
        leaked = self._drain_connection_complete_for(address, 1_500)
        if leaked is not None:
            self._classic_acl_disconnect(leaked)
            recovered = True
        try:
            self._command(HCI_CREATE_CONNECTION_CANCEL, address)
        except UsbBluetoothError:
            pass
        self.lab_debug_event(
            "hci",
            "stale_acl_recovery",
            address=identifier,
            recovered=recovered,
        )
        return recovered

    def _drain_connection_complete_for(
        self,
        address: bytes,
        timeout_ms: int,
    ) -> int | None:
        """Look for a (possibly missed) Connection Complete for ``address``."""
        def _match(code: int, params: bytes) -> int | None:
            if (
                code == EVENT_CONNECTION_COMPLETE
                and len(params) >= 9
                and params[0] == 0
                and params[3:9] == address
            ):
                return int.from_bytes(params[1:3], "little") & 0x0FFF
            return None

        requeue: list[tuple[int, bytes]] = []
        found: int | None = None
        while self._pending_events:
            code, params = self._pending_events.popleft()
            if found is None:
                handle = _match(code, params)
                if handle is not None:
                    found = handle
                    continue
            requeue.append((code, params))
        self._pending_events.extend(requeue)
        if found is not None:
            return found
        deadline = time.monotonic() + timeout_ms / 1000
        while time.monotonic() < deadline:
            packet = self._read_event(
                max(1, int((deadline - time.monotonic()) * 1000)),
            )
            if packet is None:
                continue
            parsed = self._parse_event_packet(packet)
            if parsed is None:
                continue
            code, params = parsed
            handle = _match(code, params)
            if handle is not None:
                return handle
            self._pending_events.append((code, params))
        return None

    def _classic_acl_disconnect(self, handle: int) -> None:
        try:
            self._command(
                HCI_DISCONNECT, struct.pack("<HB", handle, 0x13),
            )
            self._wait_event(
                EVENT_DISCONNECTION_COMPLETE, 5_000, handle=handle,
            )
        except UsbBluetoothError:
            pass
        self._classic_acl_handles = {
            ident: tracked
            for ident, tracked in self._classic_acl_handles.items()
            if tracked != handle
        }
        self._acl_stream.clear()
        self._acl_mtu = 0
        self._acl_credits = 0
        self._acl_credit_limit = 0

    def _sdp_session(self, handle: int) -> tuple[SdpService, ...]:
        session_deadline = time.monotonic() + 20
        local_cid = 0x0040
        signal_id = 1
        self.sdp_trace.append(
            f"L2CAP Connection Request: code 0x{L2CAP_CONNECTION_REQUEST:02x}, "
            f"PSM 0x{SDP_PSM:04x}, source CID 0x{local_cid:04x}",
        )
        self._send_l2cap(
            handle,
            L2CAP_SIGNALING_CID,
            signaling_command(
                L2CAP_CONNECTION_REQUEST,
                signal_id,
                struct.pack("<HH", SDP_PSM, local_cid),
            ),
        )
        remote_cid = self._wait_l2cap_connection(
            handle, signal_id, session_deadline,
        )
        signal_id += 1
        self._send_l2cap(
            handle,
            L2CAP_SIGNALING_CID,
            signaling_command(
                L2CAP_CONFIGURATION_REQUEST,
                signal_id,
                struct.pack("<HH", remote_cid, 0),
            ),
        )
        self._complete_l2cap_configuration(
            handle, local_cid, remote_cid, signal_id, session_deadline,
        )

        fragments = bytearray()
        continuation = b""
        previous_continuation = None
        for transaction_id in range(1, 33):
            self.sdp_trace.append(
                f"SDP request: PDU 0x{SDP_SERVICE_SEARCH_ATTRIBUTE_REQUEST:02x}, "
                f"transaction 0x{transaction_id:04x}, "
                f"continuation {len(continuation)} B",
            )
            self._send_l2cap(
                handle,
                remote_cid,
                service_search_attribute_request(transaction_id, continuation),
            )
            response = self._wait_sdp_response(
                handle, local_cid, session_deadline,
            )
            if not response or response[0] != SDP_SERVICE_SEARCH_ATTRIBUTE_RESPONSE:
                opcode = response[0] if response else None
                shown = f"0x{opcode:02x}" if opcode is not None else "empty"
                self.sdp_trace.append(
                    f"SDP response: unexpected PDU {shown}",
                )
                raise SdpProtocolError("Unexpected packet on the SDP channel")
            attributes, continuation = parse_service_search_attribute_response(
                response, transaction_id,
            )
            self.sdp_trace.append(
                f"SDP response: PDU 0x{response[0]:02x}, "
                f"transaction 0x{transaction_id:04x}, "
                f"attributes {len(attributes)} B, continuation {len(continuation)} B",
            )
            fragments.extend(attributes)
            if len(fragments) > 0xFFFF:
                raise SdpProtocolError("SDP attribute response is too large")
            if not continuation:
                break
            if continuation == previous_continuation:
                raise SdpProtocolError("SDP continuation state did not advance")
            previous_continuation = continuation
        else:
            raise SdpProtocolError("Too many SDP continuation responses")

        signal_id += 1
        self._send_l2cap(
            handle,
            L2CAP_SIGNALING_CID,
            signaling_command(
                L2CAP_DISCONNECTION_REQUEST,
                signal_id,
                struct.pack("<HH", remote_cid, local_cid),
            ),
        )
        try:
            self._wait_l2cap_disconnect(
                handle, signal_id, remote_cid, local_cid,
            )
        except UsbBluetoothError:
            pass
        return parse_service_records(bytes(fragments))

    def _wait_l2cap_disconnect(
        self,
        handle: int,
        identifier: int,
        remote_cid: int,
        local_cid: int,
    ) -> None:
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            cid, payload = self._read_l2cap(handle, deadline)
            if cid != L2CAP_SIGNALING_CID:
                continue
            for code, response_id, body in iter_signaling_commands(payload):
                if (
                    code == L2CAP_DISCONNECTION_RESPONSE
                    and response_id == identifier
                    and body[:4] == struct.pack("<HH", remote_cid, local_cid)
                ):
                    return
                self._respond_aux_signaling(
                    handle, code, response_id, body,
                    local_cid=local_cid,
                    remote_cid=remote_cid,
                )
        raise UsbBluetoothError("SDP L2CAP disconnect timed out")

    def _wait_l2cap_connection(
        self,
        handle: int,
        identifier: int,
        deadline: float,
    ) -> int:
        while time.monotonic() < deadline:
            cid, payload = self._read_l2cap(handle, deadline)
            if cid != L2CAP_SIGNALING_CID:
                continue
            for code, response_id, body in iter_signaling_commands(payload):
                if self._respond_aux_signaling(
                    handle, code, response_id, body,
                ):
                    continue
                if (
                    code != L2CAP_CONNECTION_RESPONSE
                    or response_id != identifier
                    or len(body) < 8
                ):
                    continue
                destination_cid, source_cid, result, _status = struct.unpack_from(
                    "<HHHH", body,
                )
                self.sdp_trace.append(
                    f"L2CAP Connection Response: code 0x{code:02x}, "
                    f"result 0x{result:04x}, status 0x{_status:04x}",
                )
                if source_cid != 0x0040:
                    raise UsbBluetoothError(
                        "SDP L2CAP response used an unexpected source CID"
                    )
                if result == 0:
                    return destination_cid
                if result != 1:
                    raise UsbBluetoothError(
                        f"SDP L2CAP connection rejected with result 0x{result:04x}"
                    )
        raise UsbBluetoothError("SDP L2CAP connection timed out")

    def _complete_l2cap_configuration(
        self,
        handle: int,
        local_cid: int,
        remote_cid: int,
        request_id: int,
        deadline: float,
    ) -> None:
        local_configured = False
        peer_configured = False
        while (
            time.monotonic() < deadline
            and not (local_configured and peer_configured)
        ):
            cid, payload = self._read_l2cap(handle, deadline)
            if cid != L2CAP_SIGNALING_CID:
                continue
            for code, identifier, body in iter_signaling_commands(payload):
                if self._respond_aux_signaling(
                    handle, code, identifier, body,
                    local_cid=local_cid,
                    remote_cid=remote_cid,
                ):
                    continue
                if code == L2CAP_CONFIGURATION_REQUEST and len(body) >= 4:
                    destination_cid = int.from_bytes(body[:2], "little")
                    if destination_cid == local_cid:
                        unknown_options = self._unknown_l2cap_config_options(
                            body[4:],
                        )
                        result = 0x0003 if unknown_options else 0
                        self.sdp_trace.append(
                            f"L2CAP Configuration Request: code 0x{code:02x}; "
                            f"response result 0x{result:04x}",
                        )
                        self._send_l2cap(
                            handle,
                            L2CAP_SIGNALING_CID,
                            signaling_command(
                                L2CAP_CONFIGURATION_RESPONSE,
                                identifier,
                                struct.pack(
                                    "<HHH", remote_cid,
                                    int.from_bytes(body[2:4], "little") & 0x0001,
                                    result,
                                ) + unknown_options,
                            ),
                        )
                        peer_configured = not unknown_options and not (
                            int.from_bytes(body[2:4], "little") & 0x0001
                        )
                elif (
                    code == L2CAP_CONFIGURATION_RESPONSE
                    and identifier == request_id
                    and len(body) >= 6
                ):
                    source_cid, flags, result = struct.unpack_from("<HHH", body)
                    self.sdp_trace.append(
                        f"L2CAP Configuration Response: code 0x{code:02x}, "
                        f"result 0x{result:04x}, flags 0x{flags:04x}",
                    )
                    if source_cid != local_cid or result != 0:
                        raise UsbBluetoothError(
                            f"SDP L2CAP configuration failed with result 0x{result:04x}"
                        )
                    local_configured = not (flags & 0x0001)
        if not (local_configured and peer_configured):
            raise UsbBluetoothError("SDP L2CAP configuration timed out")

    @staticmethod
    def _unknown_l2cap_config_options(options: bytes) -> bytes:
        offset = 0
        unknown = bytearray()
        supported = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}
        while offset < len(options):
            if offset + 2 > len(options):
                raise UsbBluetoothError("Truncated L2CAP configuration option")
            option_type, length = options[offset], options[offset + 1]
            end = offset + 2 + length
            if end > len(options):
                raise UsbBluetoothError("Truncated L2CAP configuration option")
            if (option_type & 0x7F) not in supported and not (option_type & 0x80):
                unknown.extend(options[offset:end])
            offset = end
        return bytes(unknown)

    def _wait_sdp_response(
        self,
        handle: int,
        local_cid: int,
        deadline: float,
    ) -> bytes:
        while time.monotonic() < deadline:
            cid, payload = self._read_l2cap(handle, deadline)
            if cid == local_cid:
                return payload
            if cid == L2CAP_SIGNALING_CID:
                for code, identifier, body in iter_signaling_commands(payload):
                    if self._respond_aux_signaling(
                        handle, code, identifier, body,
                        local_cid=local_cid,
                    ):
                        continue
                    if code == L2CAP_CONFIGURATION_REQUEST and len(body) >= 4:
                        self._send_l2cap(
                            handle,
                            L2CAP_SIGNALING_CID,
                            signaling_command(
                                L2CAP_CONFIGURATION_RESPONSE,
                                identifier,
                                struct.pack("<HHH", 0x0040, 0, 0),
                            ),
                        )
                    elif code == L2CAP_DISCONNECTION_REQUEST and len(body) >= 4:
                        self._send_l2cap(
                            handle,
                            L2CAP_SIGNALING_CID,
                            signaling_command(
                                L2CAP_DISCONNECTION_RESPONSE, identifier, body[:4],
                            ),
                        )
        raise UsbBluetoothError("SDP response timed out")

    def _respond_aux_signaling(
        self,
        handle: int,
        code: int,
        identifier: int,
        body: bytes,
        *,
        local_cid: int = 0x0040,
        remote_cid: int = 0,
    ) -> bool:
        if code == L2CAP_ECHO_REQUEST:
            response_code = L2CAP_ECHO_RESPONSE
            response_body = body
        elif code == L2CAP_INFORMATION_REQUEST and len(body) >= 2:
            response_code = L2CAP_INFORMATION_RESPONSE
            response_body = body[:2] + struct.pack("<H", 0x0001)
        elif code == L2CAP_DISCONNECTION_REQUEST and len(body) >= 4:
            response_code = L2CAP_DISCONNECTION_RESPONSE
            response_body = body[:4]
        else:
            return False
        self._send_l2cap(
            handle,
            L2CAP_SIGNALING_CID,
            signaling_command(response_code, identifier, response_body),
        )
        if code == L2CAP_DISCONNECTION_REQUEST:
            raise UsbBluetoothError(
                f"Peer disconnected SDP channel 0x{remote_cid or local_cid:04x}"
            )
        return True

    def _send_l2cap(self, handle: int, cid: int, payload: bytes) -> None:
        body = l2cap_packet(cid, payload)
        mtu = self._acl_mtu or HCI_MAX_ACL_SIZE - 4
        # LE-U links only support PB flags 0b00/0b01 (Core Vol 4 Part E §5.4.2);
        # the auto-flushable 0b10 start flag is BR/EDR-only and an LE controller
        # silently drops it, so the PDU never reaches the peer.
        first_boundary = 0x00 if handle in self._le_acl_handles else 0x02
        for offset in range(0, len(body), mtu):
            boundary = first_boundary if offset == 0 else 0x01
            self._send_acl_fragment(handle, boundary, body[offset:offset + mtu])

    def register_le_acl_handle(self, handle: int) -> None:
        self._le_acl_handles.add(handle)

    def unregister_le_acl_handle(self, handle: int) -> None:
        self._le_acl_handles.discard(handle)

    def _send_acl_fragment(
        self,
        handle: int,
        boundary: int,
        fragment: bytes,
    ) -> None:
        deadline = time.monotonic() + 5
        self._drain_hci_events(handle)
        while self._acl_credits <= 0:
            self._drain_hci_events(handle)
            if self._acl_credits > 0:
                break
            if time.monotonic() >= deadline:
                raise UsbBluetoothError("Bluetooth ACL transmit credits timed out")
            packet = self._read_event(100)
            if packet is not None:
                parsed = self._parse_event_packet(packet)
                if parsed is not None:
                    code, parameters = parsed
                    self._handle_aux_hci_event(code, parameters, handle)
        packet = (
            struct.pack("<HH", handle | (boundary << 12), len(fragment))
            + fragment
        )
        try:
            self._device.write(
                self._acl_out_endpoint.bEndpointAddress,
                packet,
                timeout=5_000,
            )
        except usb.core.USBError as exc:
            raise UsbBluetoothError("Could not write Bluetooth ACL data") from exc
        self._acl_credits -= 1
        self._capture_records.append(HciCaptureRecord(time.time(), 0x02, False, packet))

    def _read_l2cap(self, handle: int, deadline: float) -> tuple[int, bytes]:
        reassembly = bytearray()
        expected = 0
        while time.monotonic() < deadline:
            packet = self._next_acl_packet(deadline, handle)
            handle_flags, data_length = struct.unpack_from("<HH", packet)
            if (handle_flags & 0x0FFF) != handle:
                continue
            boundary = (handle_flags >> 12) & 0x03
            fragment = packet[4:4 + data_length]
            if boundary in {0, 2, 3}:
                if reassembly:
                    raise UsbBluetoothError("Interleaved Bluetooth ACL fragments")
                reassembly = bytearray(fragment)
                expected = (
                    4 + int.from_bytes(reassembly[:2], "little")
                    if len(reassembly) >= 4 else 0
                )
            elif boundary == 1 and reassembly:
                reassembly.extend(fragment)
            else:
                continue
            if expected and len(reassembly) >= expected:
                if len(reassembly) != expected:
                    raise UsbBluetoothError("Bluetooth ACL data exceeded L2CAP length")
                length, cid = struct.unpack_from("<HH", reassembly)
                return cid, bytes(reassembly[4:4 + length])
        raise UsbBluetoothError("Bluetooth ACL response timed out")

    def _next_acl_packet(self, deadline: float, handle: int) -> bytes:
        while time.monotonic() < deadline:
            if len(self._acl_stream) >= 4:
                data_length = int.from_bytes(self._acl_stream[2:4], "little")
                if data_length > HCI_MAX_ACL_SIZE - 4:
                    self._acl_stream.clear()
                    raise UsbBluetoothError("Bluetooth ACL packet length is invalid")
                packet_length = 4 + data_length
                if len(self._acl_stream) >= packet_length:
                    packet = bytes(self._acl_stream[:packet_length])
                    del self._acl_stream[:packet_length]
                    self._capture_records.append(
                        HciCaptureRecord(time.time(), 0x02, True, packet)
                    )
                    return packet
            remaining_ms = max(1, int((deadline - time.monotonic()) * 1000))
            try:
                chunk = bytes(self._device.read(
                    self._acl_in_endpoint.bEndpointAddress,
                    HCI_MAX_ACL_SIZE,
                    timeout=min(remaining_ms, 100),
                ))
            except usb.core.USBError as exc:
                if getattr(exc, "errno", None) in {60, 110} or "timed out" in str(exc).lower():
                    self._drain_hci_events(handle)
                    continue
                raise UsbBluetoothError("Could not read Bluetooth ACL data") from exc
            self._acl_stream.extend(chunk)
        raise UsbBluetoothError("Bluetooth ACL packet timed out")

    def _drain_hci_events(self, handle: int) -> None:
        deferred = []
        while self._pending_events:
            code, parameters = self._pending_events.popleft()
            if not self._handle_aux_hci_event(code, parameters, handle):
                deferred.append((code, parameters))
        self._pending_events.extend(deferred)
        for _ in range(8):
            packet = self._read_event(1)
            if packet is None:
                return
            parsed = self._parse_event_packet(packet)
            if parsed is None:
                continue
            code, parameters = parsed
            if not self._handle_aux_hci_event(code, parameters, handle):
                self._pending_events.append((code, parameters))

    def _handle_aux_hci_event(
        self,
        event_code: int,
        parameters: bytes,
        handle: int,
    ) -> bool:
        disconnect_reason: int | None = None
        if event_code == EVENT_DISCONNECTION_COMPLETE:
            event_status = parameters[0] if parameters else 0xFF
            event_handle = (
                int.from_bytes(parameters[1:3], "little") & 0x0FFF
                if len(parameters) >= 3
                else None
            )
            disconnect_reason = parameters[3] if len(parameters) >= 4 else None
            self.lab_debug_event(
                "hci",
                "disconnection_complete",
                handle=event_handle,
                status=event_status,
                status_message=hci_status_message(event_status),
                reason=disconnect_reason,
                reason_message=(
                    hci_status_message(disconnect_reason)
                    if disconnect_reason is not None
                    else "reason unavailable"
                ),
            )
        if event_code == EVENT_NUMBER_OF_COMPLETED_PACKETS and parameters:
            count = parameters[0]
            offset = 1
            for _ in range(count):
                if offset + 4 > len(parameters):
                    raise UsbBluetoothError(
                        "Malformed completed-packets HCI event"
                    )
                completed_handle, completed = struct.unpack_from(
                    "<HH", parameters, offset,
                )
                offset += 4
                if (completed_handle & 0x0FFF) == handle:
                    self._acl_credits = min(
                        self._acl_credit_limit,
                        self._acl_credits + completed,
                    )
            return True
        if self._pairing_context is not None:
            if event_code == EVENT_DISCONNECTION_COMPLETE:
                self._pairing_context.on_disconnection(disconnect_reason)
                return True
            if self._pairing_context.handle_event(event_code, parameters):
                return True
        if self._bias_posture_context is not None:
            if event_code == EVENT_DISCONNECTION_COMPLETE:
                self._bias_posture_context.on_disconnection()
                return True
            if self._bias_posture_context.handle_event(event_code, parameters):
                return True
        if self._bias_posture_context is not None:
            return False
        if (
            event_code == EVENT_LINK_KEY_REQUEST
            and len(parameters) >= 6
            and self._reply_stored_link_key(parameters[:6])
        ):
            return True
        negative_opcode = _PAIRING_NEGATIVE_REPLIES.get(event_code)
        if negative_opcode is not None and len(parameters) >= 6:
            from wifit3.bluetooth.lab.pairing import pairing_event_label

            self.lab_debug_event(
                "pairing",
                "declined_read_only",
                hci_event=event_code,
                request=pairing_event_label(event_code),
            )
            reply = parameters[:6]
            if event_code == 0x31:
                reply += b"\x18"
            self._command(negative_opcode, reply)
            return True
        if event_code == EVENT_LINK_KEY_NOTIFICATION:
            raise UsbBluetoothError(
                "Unexpected link key notification during read-only SDP browse"
            )
        if event_code == EVENT_DISCONNECTION_COMPLETE:
            detail = (
                hci_status_message(disconnect_reason)
                if disconnect_reason is not None
                else "reason unavailable"
            )
            raise UsbBluetoothError(f"Bluetooth ACL link disconnected: {detail}")
        return False

    def _wait_event(
        self,
        event_code: int,
        timeout_ms: int,
        *,
        handle: int = 0,
    ) -> bytes:
        deadline = time.monotonic() + timeout_ms / 1000
        while time.monotonic() < deadline:
            if self._pending_events:
                code, parameters = self._pending_events.popleft()
            else:
                packet = self._read_event(
                    max(1, int((deadline - time.monotonic()) * 1000)),
                )
                if packet is None:
                    continue
                parsed = self._parse_event_packet(packet)
                if parsed is None:
                    continue
                code, parameters = parsed
            if code == event_code:
                return parameters
            if not self._handle_aux_hci_event(code, parameters, handle):
                self._pending_events.append((code, parameters))
        raise UsbBluetoothError(f"HCI event 0x{event_code:02x} timed out")

    def _stop_and_close(self, close: bool = True) -> None:
        if self._device is not None:
            if self.controller.supports_classic:
                try:
                    self._command(HCI_INQUIRY_CANCEL)
                except Exception:
                    pass
            if self.controller.supports_le and self._usb_le_scan_enabled:
                try:
                    self._command(HCI_LE_SET_SCAN_ENABLE, b"\x00\x00")
                except Exception:
                    pass
        if close:
            self._close()

    def _close(self) -> None:
        device, self._device = self._device, None
        self._event_endpoint = None
        self._acl_in_endpoint = None
        self._acl_out_endpoint = None
        self._remote_name_pending = None
        self._remote_name_queue.clear()
        self._remote_name_queued.clear()
        if device is None:
            return
        try:
            usb.util.release_interface(device, self._interface_number)
        except Exception:
            pass
        if self._detached_kernel_driver:
            try:
                device.attach_kernel_driver(self._interface_number)
            except Exception:
                pass
        self._detached_kernel_driver = False
        usb.util.dispose_resources(device)
