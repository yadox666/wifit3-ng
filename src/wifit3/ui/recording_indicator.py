import time

from rich.text import Text


def recording_indicator(
    label: str,
    active: bool,
    now: float | None = None,
    detail: str | None = None,
) -> Text:
    if not active:
        return Text("")
    phase = int((time.monotonic() if now is None else now) * 2) % 2
    text = Text("● ", style="bold red" if phase == 0 else "bold #500000")
    text.append(label, style="bold red")
    if detail:
        text.append(f"\n{detail}", style="dim")
    return text


def pcap_progress(writer) -> str:
    count = writer.part_count
    noun = "file" if count == 1 else "files"
    megabytes = writer.total_bytes / (1024 * 1024)
    if megabytes < 10:
        size = f"{megabytes:.2f}"
    elif megabytes < 100:
        size = f"{megabytes:.1f}"
    else:
        size = f"{megabytes:.0f}"
    return f"{count} {noun}: {size} MB"
