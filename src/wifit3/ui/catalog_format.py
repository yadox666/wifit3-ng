"""Shared presentation for a product-catalog hit.

Scan rows, focus, offline history, and the device log all read the same fields.
A hit is a hypothesis about the advertisement. Protocol type is left alone.
"""
from __future__ import annotations

from typing import Any

from rich.markup import escape
from rich.text import Text


def catalog_class_cell(source) -> Text:
    """Offline table: product-catalog class only."""
    view = _view(source)
    cls = view["class"]
    if not cls:
        return Text("·", style="dim")
    style = "bold yellow" if view["attention"] else "cyan"
    return Text(cls, style=style)


def catalog_family_cell(source) -> Text:
    """Offline table: product-catalog family labels (and live chip when present)."""
    view = _view(source)
    text = Text(no_wrap=True)
    if not _present(view):
        return Text("·", style="dim")
    if view["attention"]:
        text.append("◆ ", style="bold yellow")
    shown = view["labels"][:2]
    if shown:
        label = " · ".join(shown)
        extra = len(view["labels"]) - len(shown)
        if extra:
            label = f"{label} +{extra}"
        text.append(label, style="bold yellow" if view["attention"] else "bold cyan")
    elif view["attention"]:
        text.append(_clip(view["attention"], 18), style="bold yellow")
    if view["live"] and view["live"] not in text.plain:
        if text.plain:
            text.append(" · ", style="dim")
        style = "bold yellow" if view["live_strong"] else "yellow"
        text.append(view["live"], style=style)
    if not text.plain:
        return Text("·", style="dim")
    return text


def catalog_chip(source) -> Text:
    """Short family chip for a table cell. Empty when the radio has no family."""
    view = _view(source)
    text = Text(no_wrap=True)
    if not _present(view):
        return text
    if view["attention"]:
        text.append("◆ ", style="bold yellow")
    shown = view["labels"][:2]
    if shown:
        label = " · ".join(shown)
        extra = len(view["labels"]) - len(shown)
        if extra:
            label = f"{label} +{extra}"
        text.append(label, style="bold yellow" if view["attention"] else "bold cyan")
    elif view["attention"]:
        text.append(_clip(view["attention"], 18), style="bold yellow")
    if view["live"] and view["live"] not in text.plain:
        if text.plain:
            text.append(" · ", style="dim")
        style = "bold yellow" if view["live_strong"] else "yellow"
        text.append(view["live"], style=style)
    return text


def catalog_router_markup(source, *, width: int = 28) -> str:
    """One-line chip under the access-point name. Empty hides the row."""
    view = _view(source)
    if not _present(view):
        return ""
    parts: list[str] = []
    if view["labels"]:
        name = " · ".join(view["labels"][:2])
        extra = len(view["labels"]) - min(2, len(view["labels"]))
        if extra:
            name = f"{name} +{extra}"
        parts.append(name)
    if view["live"]:
        parts.append(view["live"])
    plain = " · ".join(parts)
    if view["attention"]:
        plain = f"◆ {plain}".rstrip()
    room = max(8, width - 2)
    if len(plain) > room:
        plain = plain[: room - 1] + "…"
    if view["attention"] or view["live_strong"]:
        return f"[bold black on yellow] {escape(plain)} [/]"
    return f"[bold black on cyan] {escape(plain)} [/]"


def catalog_status_line(source) -> str:
    """One status-bar line: family, class, and the live chip."""
    view = _view(source)
    if not _present(view):
        return ""
    bits: list[str] = []
    if view["attention"]:
        bits.append("[bold yellow]◆[/]")
    if view["labels"]:
        style = "bold yellow" if view["attention"] else "bold cyan"
        bits.append(f"[{style}]{escape(' · '.join(view['labels'][:2]))}[/]")
    if view["class"]:
        bits.append(f"[dim]{escape(view['class'])}[/]")
    if view["live"]:
        style = "bold yellow" if view["live_strong"] else "yellow"
        bits.append(f"[{style}]{escape(view['live'])}[/]")
    return "  ".join(bits)


def catalog_detail_lines(source) -> list[str]:
    """Markup lines for a device log or focus detail. Empty when there is no hit."""
    view = _view(source)
    if not _present(view):
        return []
    lines = ["[bold cyan]Product catalog[/bold cyan]"]
    if view["labels"]:
        lines.append(f"  [bold]{escape(' · '.join(view['labels']))}[/bold]")
    if view["class"]:
        lines.append(f"  [dim]Class[/dim] {escape(view['class'])}")
    if view["live"]:
        style = "bold yellow" if view["live_strong"] else "yellow"
        lines.append(f"  [{style}]{escape(view['live'])}[/]")
    if view["sentence"]:
        lines.append(f"  [dim]{escape(view['sentence'])}[/dim]")
    if view["attention"]:
        lines.append(f"  [bold yellow]◆[/bold yellow] {escape(view['attention'])}")
    if view["notes"]:
        lines.append(f"  [dim]{escape(view['notes'])}[/dim]")
    return lines


def catalog_record_class(record: dict[str, Any]) -> str:
    """Product-catalog class on a saved AP/BT record, if any."""
    return _view(record)["class"]


def catalog_search_text(record: dict[str, Any]) -> str:
    """Words offline search should match for one saved radio."""
    view = _view(record)
    return " ".join(filter(None, (
        " ".join(view["labels"]),
        view["class"],
        view["live"],
        view["attention"],
        view["notes"],
        view["sentence"],
    )))


def catalog_expand_rows(record: dict[str, Any]) -> list[tuple[str, str]]:
    """Plain rows shown first when an offline record is expanded."""
    view = _view(record)
    if not _present(view):
        return []
    rows: list[tuple[str, str]] = []
    if view["labels"]:
        rows.append(("catalog", " · ".join(view["labels"])))
    if view["class"]:
        rows.append(("catalog class", view["class"]))
    if view["live"]:
        rows.append(("catalog live", view["live"]))
    if view["attention"]:
        rows.append(("catalog attention", view["attention"]))
    if view["sentence"]:
        rows.append(("catalog note", view["sentence"]))
    if view["notes"]:
        rows.append(("catalog notes", view["notes"]))
    return rows


def _present(view: dict[str, Any]) -> bool:
    return bool(view["labels"] or view["live"] or view["attention"])


def _view(source) -> dict[str, Any]:
    if source is None:
        return _blank()
    if isinstance(source, dict):
        catalog = source.get("catalog") if isinstance(source.get("catalog"), dict) else None
        capabilities = (
            source.get("capabilities")
            if isinstance(source.get("capabilities"), dict) else None
        )
        if catalog is not None or capabilities is not None:
            return _merge(_flat(catalog or {}), _flat(capabilities or {}))
        return _flat(source)
    return _flat({
        "catalog_labels": getattr(source, "catalog_labels", ()),
        "catalog_class": getattr(source, "catalog_class", ""),
        "catalog_live": getattr(source, "catalog_live", ""),
        "catalog_live_strong": getattr(source, "catalog_live_strong", False),
        "catalog_attention": getattr(source, "catalog_attention", ""),
        "catalog_notes": getattr(source, "catalog_notes", ""),
        "catalog_sentence": getattr(source, "catalog_sentence", ""),
    })


def _flat(data: dict[str, Any]) -> dict[str, Any]:
    return {
        "labels": _strings(data.get("catalog_labels", data.get("labels"))),
        "class": str(data.get("catalog_class") or data.get("class") or ""),
        "live": str(data.get("catalog_live") or data.get("live") or ""),
        "live_strong": bool(
            data.get("catalog_live_strong") or data.get("live_strong")
        ),
        "attention": str(data.get("catalog_attention") or data.get("attention") or ""),
        "notes": str(data.get("catalog_notes") or data.get("notes") or ""),
        "sentence": str(data.get("catalog_sentence") or data.get("sentence") or ""),
    }


def _merge(left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
    if left["live"]:
        live, strong = left["live"], left["live_strong"]
    else:
        live, strong = right["live"], right["live_strong"]
    return {
        "labels": left["labels"] or right["labels"],
        "class": left["class"] or right["class"],
        "live": live,
        "live_strong": strong,
        "attention": left["attention"] or right["attention"],
        "notes": left["notes"] or right["notes"],
        "sentence": left["sentence"] or right["sentence"],
    }


def _blank() -> dict[str, Any]:
    return {
        "labels": [],
        "class": "",
        "live": "",
        "live_strong": False,
        "attention": "",
        "notes": "",
        "sentence": "",
    }


def _strings(value) -> list[str]:
    if isinstance(value, str):
        return [value] if value else []
    if isinstance(value, (list, tuple)):
        return [str(item) for item in value if item]
    return []


def _clip(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[: limit - 1] + "…"
