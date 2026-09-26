import time

from rich.text import Text


def recording_indicator(label: str, active: bool, now: float | None = None) -> Text:
    if not active:
        return Text("")
    phase = int((time.monotonic() if now is None else now) * 2) % 2
    text = Text("● ", style="bold red" if phase == 0 else "bold #500000")
    text.append(label, style="bold red")
    return text
