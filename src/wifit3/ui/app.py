import logging
import os
import sys
import time
from textual import events, work
from textual.app import App
from textual.binding import Binding
from textual.widgets import Header
from textual.widgets._header import HeaderClock, HeaderIcon, HeaderTitle
from typing import Optional

from wifit3 import __version__
from wifit3.chips import log_trace
from textual.reactive import reactive
from typing import List
from wifit3.models.jobs import JobState, ToolCapability, ToolStatus
from wifit3.persist.config import Config, ConfigError
from wifit3.persist.hidden_ssids import HiddenSsidStore, HiddenSsidStoreError
from wifit3.persist.wifi_profiles import WifiProfileStore, WifiProfileStoreError
from wifit3.persist.enterprise_sessions import (
    EnterpriseSessionStore,
    EnterpriseSessionStoreError,
)
from wifit3.persist.ap_history import ApHistoryStore
from wifit3.persist.bluetooth_history import (
    BluetoothHistoryStore,
    BluetoothHistoryStoreError,
)
from wifit3.persist.notifications import NotificationStore, NotificationStoreError
from wifit3.persist.targets import SavedTarget, TargetStore, TargetStoreError
from wifit3.persist.locations import LocationStore
from wifit3.persist.scan_sessions import (
    ScanSession,
    allocate_session_name,
    collect_session_metadata,
    new_scan_session,
    persisted_session_names,
    session_end_metadata_patch,
)
from wifit3.persist.vault import Vault
from wifit3.errors import WifiteDeviceLostError, WifiteFatalError
from wifit3.bluetooth import BluetoothManager
from wifit3.gps import GpsManager
from wifit3.bluetooth.capture import BluetoothEventCapture
from wifit3.device.manager import DeviceManager, Status
from wifit3.device.watch import DeviceWatch
from wifit3.wlan.array import WlanArray
from wifit3.models import AccessPoint, Client

from .screens.splash import SplashView
from .screens.scanner import ScannerView
from .screens.spectrum import RfSpectrumView
from .screens.bluetooth_scanner import BluetoothScannerView
from .screens.bluetooth_focus import BluetoothFocusView
from .screens.bluetooth_classic_focus import BluetoothClassicFocusView
from .screens.client_focus import ClientFocusView
from .screens.offline import OfflineDatabaseView
from .screens.about import AboutModal, UpdateAvailableModal
from .screens.diagnostics import AdapterDiagnosticsModal
from .screens.focus_v2 import FocusViewV2
from .screens.error_modals import FatalErrorModal, RecoverableErrorModal
from .screens.new_device import NewDeviceDialog
from .screens.vault_drawer import VaultDrawer
from .screens.vault_table import VaultTable
from .notification_center import NotificationHistoryModal
from .screens.session_start_modal import SessionStartInput, SessionStartModal
from .pref import PreferencesModal
from .themes import register_app_themes
from wifit3.updates import check_for_update

logger = logging.getLogger(__name__)


def _notification_plain_text(value: object) -> str:
    if value is None:
        return ""
    if hasattr(value, "plain"):
        return str(value.plain)
    return str(value)


def _notification_severity(value: object) -> str:
    if value is None:
        return "information"
    if hasattr(value, "value"):
        return str(value.value).casefold()
    return str(value).casefold()


def _notification_should_persist(severity: object, persist: bool | None) -> bool:
    """Only warnings/errors go to notification history unless explicitly opted in."""
    if persist is not None:
        return persist
    level = _notification_severity(severity)
    return level in {"warning", "error"}


Header.ALLOW_SELECT = False
HeaderTitle.ALLOW_SELECT = False
HeaderIcon.ALLOW_SELECT = False
HeaderClock.ALLOW_SELECT = False


class WifiteApp(App):
    """wifit3 TUI Main App."""

    TITLE = f"wifit3-ng v{__version__} - yadox666"
    unread_notifications = reactive(0)

    ENABLE_COMMAND_PALETTE = False
    BINDINGS = [
        Binding("ctrl+q", "quit", "Quit"),
        Binding("ctrl+p", "preferences", "Prefs"),
        Binding("ctrl+d", "diagnostics", "Diagnostics"),
        Binding("v", "toggle_vault", "Vault"),
    ]

    CSS = """
    /* Force single-line header to avoid Textual's "click to expand" behavior */
    Header { height: 1 !important; }
    NotificationBell { height: 1; dock: right; min-width: 7; }
    WifiteHeader > _ChannelReadout {
        dock: right;
        max-width: 55%;
        text-overflow: ellipsis;
    }

    #ascii-art {
        content-align: center middle;
        margin-bottom: 2;
    }
    #device-row {
        width: auto;
        height: auto;
        align: center middle;
        margin-top: 1;
    }
    #splash-container #device-picker,
    #splash-container #os-ble-picker,
    #splash-container #bluetooth-picker,
    #splash-container #sdr-picker,
    #splash-container #gps-picker {
        margin-top: 1;
        width: auto;
        max-width: 80;
    }
    #primary-actions {
        width: auto;
        height: auto;
        align: center middle;
        margin-top: 1;
    }
    #bluetooth-btn, #background-btn {
        margin-left: 2;
    }
    #primary-actions #background-btn {
        width: 16;
    }
    #offline-btn {
        margin-left: 2;
        background: $surface-lighten-2;
        color: $text-muted;
        border: tall $surface-lighten-3;
    }
    #offline-btn:hover {
        background: $surface-lighten-3;
        color: $text;
    }
    #offline-btn:focus {
        background: $surface-lighten-3;
        color: $text;
    }
    #primary-actions Button, #uninstall-btn {
        width: 13;
        height: 3;
    }
    #bluetooth-usb-btn {
        width: 22;
        margin-left: 2;
    }
    #spectrum-btn {
        width: 17;
        margin-left: 2;
    }
    #primary-actions Button:focus, #uninstall-btn:focus {
        text-style: bold reverse;   /* clear cue when Tab lands on START / Uninstall */
    }
    #start-btn {
        color: white;
        text-style: bold;
    }
    #uninstall-btn { margin-top: 1; }
    #status-label {
        content-align: center middle;
        margin-bottom: 1;
    }
    DataTable {
        width: 100%;
        height: 1fr;
    }
    RichLog, SelectableRichLog {
        height: 10;
        border-top: solid $primary;
    }
    Button {
        margin-right: 1;
        min-width: 12;
    }
    /* App CSS outranks a widget's DEFAULT_CSS, so lower the global min-width for the
       EvilTwin modal's compact BSSID buttons from here, not the modal. */
    EvilTwinInputModal #bssid-btns Button { min-width: 4; }
    ClientsList #clear-client-web-search { min-width: 3; margin: 0; }
    """

    active_jobs: reactive[List[JobState]] = reactive([], always_update=True)
    vault_open: reactive[bool] = reactive(False)


    def __init__(self, cli_log_level=None, *, background: bool = False, background_all: bool = False):
        super().__init__()
        self.background_autostart = background
        self.background_all = background_all
        self._config_error: Optional[str] = None
        try:
            Config.load()
        except ConfigError as e:
            self._config_error = str(e)
        _configure_file_logging(cli_log_level)
        self.array: Optional[WlanArray] = None
        # Per physical card (instance_key): "all" | "2g" | "5g" — scanner hop only.
        self.scan_band_by_instance: dict[tuple, str] = {}
        self.location_store = LocationStore()
        self.gps_manager = GpsManager(
            port=Config.gps_port,
            on_error=self._gps_error,
        )
        self.bluetooth_history_store = BluetoothHistoryStore()
        self.bluetooth_manager = BluetoothManager(
            history=self.bluetooth_history_store,
            location_store=self.location_store,
            fix_provider=lambda: self.gps_manager.latest_fix,
            movement_provider=lambda: Config.gps_movement_threshold_m,
            accuracy_provider=lambda: Config.gps_max_accuracy_m,
            os_ble_enabled=Config.os_ble_enabled,
        )
        self.bluetooth_target_capture: BluetoothEventCapture | None = None
        self.device_manager = DeviceManager(self)
        self.device_watch = DeviceWatch(device_manager=self.device_manager,
                                        on_change=self._on_devices_changed,
                                        on_fatal=self._on_usb_fatal)
        self.target_ap: Optional[AccessPoint] = None
        self.target_client: Optional[Client] = None
        self.resume_clients_view: bool = False
        self.vault = Vault()
        self.target_store = TargetStore()
        self.notification_store = NotificationStore()
        self.unread_notifications = self.notification_store.unread_count()
        self.hidden_ssid_store = HiddenSsidStore()
        self.wifi_profile_store = WifiProfileStore()
        self.enterprise_session_store = EnterpriseSessionStore()
        self.ap_history_store = ApHistoryStore()
        self.active_scan_session: ScanSession | None = None
        self.locked_target_id: str | None = None
        self.target_missing_since: float | None = None
        self.auto_lock_armed = True
        self._target_sightings_notified: set[str] = set()
        self._job_status: dict[str, ToolStatus] = {}
        self.pbc_enabled: bool = Config.auto_wps_pbc
        register_app_themes(self)
        self.theme = Config.theme

    def notify(
        self,
        message: str,
        *,
        title: str = "",
        severity: str = "information",
        timeout: float | None = None,
        persist: bool | None = None,
        **kwargs,
    ):
        if _notification_should_persist(severity, persist):
            try:
                self.notification_store.append(
                    _notification_plain_text(message),
                    title=_notification_plain_text(title),
                    severity=_notification_severity(severity),
                )
                self.unread_notifications = self.notification_store.unread_count()
            except NotificationStoreError:
                logger.warning("Could not persist notification", exc_info=True)
        return super().notify(
            message,
            title=title,
            severity=severity,
            timeout=timeout,
            **kwargs,
        )

    def action_notification_history(self) -> None:
        self.push_screen(NotificationHistoryModal())

    def on_text_selected(self, event: events.TextSelected) -> None:
        selected = self.screen.get_selected_text()
        if not selected:
            return
        self.copy_to_clipboard(selected)
        chars = len(selected)
        noun = "char" if chars == 1 else "chars"
        self.notify(f"Copied {chars} {noun} to clipboard")

    def persist_config(self) -> None:
        try:
            Config.save()
        except ConfigError as e:
            self.notify(str(e), severity="error", title="Config")

    def _existing_session_names(self) -> set[str]:
        return persisted_session_names(
            self.ap_history_store,
            self.bluetooth_history_store,
        )

    def start_scan_session(
        self,
        media: set[str],
        *,
        mode: str,
        name: str | None = None,
        description: str = "",
        notify: bool = False,
    ) -> ScanSession:
        if self.active_scan_session is not None:
            self.end_scan_session()
        started_at = time.time()
        gps_fix = self.gps_manager.latest_fix
        gps_port = (
            self.gps_manager.status.port
            if self.gps_manager.status is not None
            else ""
        )
        metadata = collect_session_metadata(
            mode=mode,
            wifit3_version=__version__,
            started_at=started_at,
            gps_fix=gps_fix,
            gps_port=gps_port,
        )
        session = new_scan_session(
            media,
            mode=mode,
            existing_names=self._existing_session_names(),
            name=name,
            description=description,
            metadata=metadata,
            started_at=started_at,
        )
        if "wifi" in session.media:
            self.ap_history_store.start_scan_session(session)
        if "bluetooth" in session.media:
            self.bluetooth_history_store.start_scan_session(session)
        self.active_scan_session = session
        if notify:
            self.notify(
                session.name,
                title="Scan session started",
                timeout=4,
            )
        return session

    def end_scan_session(self) -> None:
        session = self.active_scan_session
        if session is None:
            return
        ended_at = time.time()
        patch = session_end_metadata_patch(
            ended_at,
            gps_fix=self.gps_manager.latest_fix,
        )
        if "wifi" in session.media:
            self.ap_history_store.end_scan_session(
                session.id,
                ended_at=ended_at,
                metadata_patch=patch,
            )
        if "bluetooth" in session.media:
            self.bluetooth_history_store.end_scan_session(
                session.id,
                ended_at=ended_at,
                metadata_patch=patch,
            )
        self.active_scan_session = None

    def _prompt_scan_session(self) -> None:
        default_name = allocate_session_name(
            None,
            self._existing_session_names(),
        )
        gps_fix = self.gps_manager.latest_fix
        self.push_screen(
            SessionStartModal(
                default_name,
                gps_fix=gps_fix,
                gps_status=self.gps_manager.status,
                gps_configured_port=self.gps_manager.configured_port,
            ),
            self._on_scan_session_start,
        )

    def _on_scan_session_start(self, result: SessionStartInput | None) -> None:
        existing = self._existing_session_names()
        if result is None:
            result = SessionStartInput(
                name=allocate_session_name(None, existing),
                description="",
            )
        requested = result.name.strip()
        final_name = allocate_session_name(requested, existing)
        if requested and final_name.casefold() != requested.casefold():
            self.notify(
                f"“{requested}” is already in session history; using “{final_name}”.",
                title="Scan session",
                severity="warning",
                timeout=5,
            )
        self.start_scan_session(
            {"wifi", "bluetooth"},
            mode="app",
            name=final_name,
            description=result.description,
        )

    @property
    def locked_target(self) -> SavedTarget | None:
        return self.target_store.get(self.locked_target_id)

    def mark_target_locked(self, target: SavedTarget) -> bool:
        try:
            self.target_store.mark_locked(target)
        except TargetStoreError as exc:
            self.notify(str(exc), title="Targets", severity="error")
            return False
        self.locked_target_id = target.id
        self.target_missing_since = None
        self.auto_lock_armed = False
        self.notify(f"Target {target.alias} locked", title="Target lock", persist=True)
        return True

    def clear_target_sighting(self, target_id: str) -> None:
        self._target_sightings_notified.discard(target_id)

    def record_target_sighting(self, target: SavedTarget, where: str) -> None:
        if not target.enabled:
            return
        if target.id in self._target_sightings_notified:
            return
        self._target_sightings_notified.add(target.id)
        label = "Whitelist" if target.role == "whitelist" else "Target"
        self.notify(
            f"«{target.alias}» ({target.identifier}) — {where}",
            title=f"{label} in range",
            persist=True,
        )

    def open_targets_editor(self, **kwargs) -> None:
        from wifit3.ui.screens.targets_editor import open_targets_editor

        open_targets_editor(self, **kwargs)

    def start_bluetooth_target_capture(
        self, target: SavedTarget, device,
    ) -> BluetoothEventCapture | None:
        self.stop_bluetooth_target_capture()
        try:
            capture = BluetoothEventCapture(
                self.bluetooth_history_store,
                device.identifier,
                target.alias,
            )
        except BluetoothHistoryStoreError as exc:
            self.notify(str(exc), title="Bluetooth capture failed", severity="error")
            return None
        self.bluetooth_target_capture = capture
        self.bluetooth_manager.register_advertisement_callback(capture.record_advertisement)
        self.bluetooth_manager.register_inspection_callback(capture.record_inspection)
        capture.record_advertisement(device)
        return capture

    def stop_bluetooth_target_capture(self) -> None:
        capture, self.bluetooth_target_capture = self.bluetooth_target_capture, None
        if capture is None:
            return
        self.bluetooth_manager.unregister_advertisement_callback(capture.record_advertisement)
        self.bluetooth_manager.unregister_inspection_callback(capture.record_inspection)
        capture.close()

    def on_mount(self) -> None:
        """Register screens, push the splash, and start the always-on device watch."""
        if self._config_error:
            self.notify(self._config_error, severity="error", title="Config")
        for msg in self.vault.errors:
            self.notify(msg, severity="warning", title="Vault")
        for msg in self.target_store.errors:
            self.notify(msg, severity="warning", title="Targets")
        for msg in self.hidden_ssid_store.errors:
            self.notify(msg, severity="warning", title="Hidden SSIDs")
        for msg in self.wifi_profile_store.errors:
            self.notify(msg, severity="warning", title="Wi-Fi profiles")
        for msg in self.enterprise_session_store.errors:
            self.notify(msg, severity="warning", title="Enterprise history")
        for msg in self.ap_history_store.errors:
            self.notify(msg, severity="warning", title="AP history")
        for msg in self.bluetooth_history_store.errors:
            self.notify(msg, severity="warning", title="Bluetooth history")
        for msg in self.location_store.errors:
            self.notify(msg, severity="warning", title="Location history")
        from wifit3.observe.signature_pack import ensure_stock

        signature_status = ensure_stock()
        if not signature_status.ok:
            self.notify(signature_status.message, severity="warning", title="Signatures")
        self.install_screen(SplashView(), name="splash")
        self.install_screen(ScannerView(), name="scanner")
        self.install_screen(RfSpectrumView(), name="spectrum")
        self.install_screen(BluetoothScannerView(), name="bluetooth")
        self.install_screen(BluetoothFocusView(), name="bluetooth-focus")
        self.install_screen(BluetoothClassicFocusView(), name="bluetooth-classic-focus")
        self.install_screen(ClientFocusView(), name="client-focus")
        self.install_screen(FocusViewV2(), name="focus")
        self.install_screen(OfflineDatabaseView(), name="offline")
        
        self.push_screen("splash")
        self._device_timer = self.set_interval(0.5, self.device_watch.poll)
        self.set_interval(2.0, self._poll_jobs)
        self.call_after_refresh(self.device_watch.poll)
        self.call_after_refresh(self._poll_jobs)
        self.gps_manager.start()
        self.call_after_refresh(self._prompt_scan_session)
        if Config.auto_check_updates:
            self.check_updates()

    def _gps_error(self, message: str) -> None:
        self.notify(message, title="GPS unavailable", severity="warning")

    def reconfigure_gps(self, port: str) -> None:
        self.run_worker(
            self.gps_manager.reconfigure(port),
            exclusive=True,
            group="gps-reconfigure",
        )

    def _poll_jobs(self) -> None:
        self.vault.manager.poll_jobs()
        self.active_jobs = self.vault.manager.get_active_jobs()
        self._notify_completions()

    def _notify_completions(self) -> None:
        """Toast each job the first time it finishes this session; jobs already terminal when
        the app started are recorded silently rather than re-announced."""
        terminal = (ToolStatus.SUCCESS, ToolStatus.FAILURE, ToolStatus.ERROR)
        cracked = False
        for job in self.active_jobs:
            prev = self._job_status.get(job.job_id)
            if job.status in terminal and prev is not None and prev not in terminal:
                self._toast_job(job)
                cracked = cracked or job.status == ToolStatus.SUCCESS
            self._job_status[job.job_id] = job.status
        live = {job.job_id for job in self.active_jobs}
        self._job_status = {k: v for k, v in self._job_status.items() if k in live}
        if cracked:
            self._refresh_vault_table()

    def _refresh_vault_table(self) -> None:
        """Reload the vault table if its drawer is open."""
        if isinstance(self.screen, VaultDrawer):
            try:
                self.screen.query_one("#vault-table", VaultTable).reload_table()
            except Exception:
                logger.debug("Vault table refresh skipped", exc_info=True)

    def _toast_job(self, job: JobState) -> None:
        if job.status == ToolStatus.SUCCESS:
            msg = job.progress_msg
            key = msg.split("Key:", 1)[1].strip() if "Key:" in msg else msg
            self.notify(
                f"SUCCESS  PSK: {key}",
                title=job.display_name,
                severity="information",
                persist=True,
            )
        elif job.status == ToolStatus.FAILURE:
            self.notify(f"NOT FOUND  {job.progress_msg}", title=job.display_name, severity="warning")
        else:
            self.notify(f"ERROR  {job.progress_msg}", title=job.display_name, severity="error")

    def kill_job(self, job_id: str) -> None:
        """Kill a running job, then refresh the tracker immediately."""
        job = self.vault.manager.jobs.get(job_id)
        if job is None:
            return
        tool = self.vault.manager.tools.get(job.tool_name)
        if tool is not None and ToolCapability.KILLABLE in tool.capabilities:
            tool.kill({
                "pid": job.pid,
                "log_path": job.log_path,
                "api_id": job.api_id,
                "config": job.config,
            })
        self._poll_jobs()

    def clear_job(self, job_id: str) -> None:
        """Remove a finished job, then refresh the tracker immediately."""
        self.vault.manager.clear_job(job_id)
        self.active_jobs = self.vault.manager.get_active_jobs()

    def _on_devices_changed(self, current, arrived, departed) -> None:
        """DeviceWatch fired. On Splash, refresh the card list; mid-session, prompt to bring up
        each newly-plugged card."""
        if any(isinstance(s, SplashView) for s in self.screen_stack):
            self.get_screen("splash", SplashView).render_devices(current)
            return
        # Ignore already-attached devices
        fresh = [d for d in arrived if not (self.array and self.array.contains(d))]
        if fresh:
            if isinstance(self.screen, RecoverableErrorModal):
                self.screen.dismiss()
            self.device_watch.pause()     # pause synchronously so the next tick can't stack a prompt
            self._prompt_hotplug(fresh)

    @work(exclusive=True)
    async def _prompt_hotplug(self, arrived) -> None:
        """Mid-session: ask per new card, and bring up the ones the user confirms (only that card,
        and on Windows never a disruptive mid-session install)."""
        try:
            for dev in arrived:
                if await self.push_screen_wait(NewDeviceDialog(dev.description)):
                    res = await self.device_manager.bringup(
                        dev, bail_at_permissions=(sys.platform == "win32"))
                    if res.status is Status.FAILED:
                        self.notify(res.message, severity="error")
                    elif res.status is Status.READY:
                        self.notify(f"{dev.description} added", severity="information")
        finally:
            self.device_watch.resume()

    def _on_usb_fatal(self, err: WifiteFatalError) -> None:
        """The bus scan hit an unrecoverable backend error: stop watching + show the Quit-only modal."""
        self._device_timer.stop()
        self.push_screen(FatalErrorModal(err))

    def notify_device_lost(self, exc: Exception, remaining: int) -> None:
        """A pooled card vanished mid-run (the array re-emits this with the surviving card count).

        Arrives on the event-loop thread via the RX reader's ``call_soon_threadsafe`` hop, which
        runs OUTSIDE Textual's message-pump context (``active_app`` unset), so a direct
        ``push_screen`` here crashes in the modal's compose (NoActiveAppError). Defer it onto the
        app's message queue via ``call_later``; that callback runs in-context."""
        self.call_later(self._show_device_lost, exc, remaining)

    def _show_device_lost(self, exc: Exception, remaining: int) -> None:
        # Survivors remain: keep running, just toast how many are left.
        if remaining > 0:
            self.notify(f"A wireless card was lost. {remaining} still active.",
                        title="Card unplugged", severity="warning")
            return
        # Last card gone: fall back to the recoverable modal → splash.
        if isinstance(self.screen, (FatalErrorModal, RecoverableErrorModal)):
            return
        self.push_screen(RecoverableErrorModal(WifiteDeviceLostError("the wireless adapter")))

    async def recover_to_splash(self) -> None:
        """Return to the splash screen after the last card was lost."""
        array = self.array
        # Unwind to the base default screen (kept by `> 1`), then re-push splash onto it.
        while len(self.screen_stack) > 1:
            await self.pop_screen()
        await self.push_screen("splash")
        # The installed splash only resumes (on_mount won't re-run), so reset its state explicitly.
        self.get_screen("splash", SplashView).reset_for_reentry()
        # Close the dead pool only once scanner/focus are gone, so their teardown can't read a
        # half-closed interface.
        if array is not None:
            try:
                await array.close()
            except Exception:
                logger.debug("Closing the lost pool failed (already gone)", exc_info=True)
        self.array = None
        self.target_ap = None

    def action_preferences(self) -> None:
        self.push_screen(PreferencesModal(), self._on_preferences_closed)

    def _on_preferences_closed(self, _result) -> None:
        from wifit3.ui.screens.splash import SplashView

        if isinstance(self.screen, SplashView):
            self.screen.refresh_regulatory_subtitle()

    def action_about(self) -> None:
        self.push_screen(AboutModal())

    def action_diagnostics(self) -> None:
        self.push_screen(AdapterDiagnosticsModal())

    @work(thread=True, exclusive=True, group="updates")
    def check_updates(self, *, show_current: bool = False) -> None:
        try:
            update = check_for_update()
        except Exception as exc:
            if show_current:
                self.call_from_thread(
                    self.notify, str(exc), title="Update check failed", severity="error",
                )
            return
        if update.update_available:
            self.call_from_thread(
                self.push_screen,
                UpdateAvailableModal(update),
            )
        elif show_current:
            self.call_from_thread(
                self.notify,
                f"Version {update.current_version} is current",
                title="wifit3 update",
            )

    async def action_quit(self):
        self.persist_config()
        try:
            self.hidden_ssid_store.save()
        except HiddenSsidStoreError:
            logger.warning("Could not flush hidden SSID/probe history", exc_info=True)
        try:
            self.wifi_profile_store.save()
        except WifiProfileStoreError:
            logger.warning("Could not flush Wi-Fi profile history", exc_info=True)
        try:
            self.enterprise_session_store.save()
        except EnterpriseSessionStoreError:
            logger.warning("Could not flush Enterprise session history", exc_info=True)
        self.vault.manager.kill_all_running()
        self.stop_bluetooth_target_capture()
        focus = self.get_screen("focus", FocusViewV2)
        focus.stop_packet_capture(notify=False)
        client_focus = self.get_screen("client-focus", ClientFocusView)
        client_focus.stop_capture(notify=False)
        await client_focus.stop_honeypot()
        scanner = self.get_screen("scanner", ScannerView)
        await scanner.stop_open_probe_test()
        await focus.stop_eap_lab_honeypot()
        await self.bluetooth_manager.disconnect()
        await self.bluetooth_manager.stop()
        await self.get_screen("spectrum", RfSpectrumView).stop()
        await self.gps_manager.stop()
        if self.array:
            await self.array.close()
        self.end_scan_session()
        self.ap_history_store.close()
        self.bluetooth_history_store.close()
        self.location_store.close()
        self.hidden_ssid_store.close()
        self.enterprise_session_store.close()
        self.target_store.close()
        self.notification_store.close()
        self.exit()

    def action_targets_editor(self) -> None:
        """Open the targets & whitelist editor."""
        screen = self.screen
        if hasattr(screen, "action_targets_editor"):
            screen.action_targets_editor()
            return
        self.open_targets_editor()

    def action_toggle_vault(self) -> None:
        """Open the vault drawer."""
        if isinstance(
            self.screen, (
                BluetoothScannerView, BluetoothFocusView,
                BluetoothClassicFocusView,
            ),
        ):
            return
        if not isinstance(self.screen, VaultDrawer):
            self.vault_open = True
            
            def _on_dismiss(_=None):
                self.vault_open = False
                
            self.push_screen(VaultDrawer(), callback=_on_dismiss)

    def check_action(self, action: str, parameters: tuple) -> Optional[bool]:
        if action == "toggle_vault" and isinstance(
            self.screen, (
                BluetoothScannerView, BluetoothFocusView,
                BluetoothClassicFocusView,
            )
        ):
            return False
        return True

_FILE_LOGGING_CONFIGURED = False  # Avoid duplicate loggers


def _get_log_level(cli_log_level: Optional[str]) -> Optional[int]:
    """Level from ``WIFIT3_LOG`` or ``Config.log_level``, trace/debug/info/quiet."""
    env = os.environ.get("WIFIT3_LOG", cli_log_level)
    if env is None:
        env = Config.log_level
    env = env.strip().lower()
    if env == "trace":
        return log_trace.TRACE
    if env == "debug":
        return logging.DEBUG
    if env == "info":
        return logging.INFO
    return None  # any other value ("quiet") skips logging

def _configure_file_logging(cli_log_level: Optional[str]) -> None:
    """Files logged to ``wifit3.log`` in the CWD."""
    global _FILE_LOGGING_CONFIGURED
    if _FILE_LOGGING_CONFIGURED:
        return

    level = _get_log_level(cli_log_level)
    if level is None:
        return

    handler = logging.FileHandler("wifit3.log", mode="w", encoding="utf-8")
    handler.setFormatter(logging.Formatter(
        "%(asctime)s.%(msecs)03d %(levelname)-5s %(name)s: %(message)s",
        datefmt="%H:%M:%S"
    ))
    root = logging.getLogger()
    root.setLevel(level)
    root.addHandler(handler)
    _FILE_LOGGING_CONFIGURED = True
    logger.info(f"Logging enabled (level={logging.getLevelName(level)})")

