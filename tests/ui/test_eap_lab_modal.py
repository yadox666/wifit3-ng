"""Honeypot dialog labels stay inside the box; the full sentence is the tooltip."""
from textual.app import App
from textual.widgets import Checkbox, Label

from wifit3.ui.screens.eap_lab_modal import EapLabModal


async def test_honeypot_options_are_short_and_tooltip_keeps_the_rest():
    app = App()
    async with app.run_test(size=(100, 40)) as pilot:
        await app.push_screen(EapLabModal("EAP-TEST", 1, default_methods=(25,)))
        await pilot.pause()

        description = app.screen.query_one("#description", Label)
        assert "untrusted TLS" in str(description.render())
        assert "Vault" in str(description.tooltip)
        assert len(str(description.render())) < len(str(description.tooltip))

        for box in app.screen.query(Checkbox):
            label = str(box.label)
            tip = str(box.tooltip or "")
            assert len(label) <= 36, label
            assert tip
            assert len(tip) >= len(label)
        cert = app.screen.query_one("#lab-client-cert", Checkbox)
        assert "EAP-TLS" in str(cert.tooltip)
        assert "certificate picker" in str(cert.tooltip)

        dialog = app.screen.query_one("#dialog")
        assert dialog.region.width == 52
        longest = app.screen.query_one("#lab-distinct-ssid", Checkbox)
        assert longest.region.height == 1
        assert longest.region.right <= dialog.region.right - 1
        assert "Distinct SSID" in str(longest.label)
