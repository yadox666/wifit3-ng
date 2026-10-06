"""Binding maps for the footer when a filter Input has focus.

Textual removes screen shortcuts from ``active_bindings`` while an ``Input`` is
focused because printable keys are consumed for typing. Scanner screens still
want the full shortcut bar in the footer.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from textual.binding import ActiveBinding
from textual.dom import DOMNode
from textual.keys import key_to_character

if TYPE_CHECKING:
    from textual.screen import Screen


def binding_chain_for_focus(
    screen: Screen, focused: DOMNode | None
) -> list[tuple[DOMNode, object]]:
    """Mirror ``Screen._binding_chain`` for an explicit focus node."""
    if focused is not None and focused.loading:
        focused = None

    if focused is None:
        namespace_bindings = [
            (screen, screen._bindings.copy()),
            (screen.app, screen.app._bindings.copy()),
        ]
    else:
        namespace_bindings = [
            (node, node._bindings.copy()) for node in focused.ancestors_with_self
        ]

    filter_namespaces: list[DOMNode] = []
    for _namespace, bindings_map in namespace_bindings:
        for filter_namespace in filter_namespaces:
            check_consume_key = filter_namespace.check_consume_key
            for key in list(bindings_map.key_to_bindings):
                if check_consume_key(key, key_to_character(key)):
                    del bindings_map.key_to_bindings[key]
        filter_namespaces.append(_namespace)

    keymap = screen.app._keymap
    for namespace, bindings_map in namespace_bindings:
        if keymap:
            result = bindings_map.apply_keymap(keymap)
            if result.clashed_bindings:
                screen.app.handle_bindings_clash(result.clashed_bindings, namespace)

    return namespace_bindings


def _modal_binding_chain(
    binding_chain: list[tuple[DOMNode, object]],
) -> list[tuple[DOMNode, object]]:
    for index, (node, _bindings) in enumerate(binding_chain, 1):
        if node.is_modal:
            return binding_chain[:index]
    return binding_chain


def active_bindings_for_focus(
    screen: Screen, focused: DOMNode | None
) -> dict[str, ActiveBinding]:
    """Mirror ``Screen.active_bindings`` for an explicit focus node."""
    bindings_map: dict[str, ActiveBinding] = {}
    app = screen.app
    chain = _modal_binding_chain(binding_chain_for_focus(screen, focused))
    for namespace, bindings in chain:
        for key, binding in bindings:
            action_state = app._check_action_state(binding.action, namespace)
            if action_state is False:
                continue
            enabled = bool(action_state)
            existing = bindings_map.get(key)
            if existing is not None:
                if binding.priority and not existing.binding.priority:
                    bindings_map[key] = ActiveBinding(
                        namespace, binding, enabled, binding.tooltip
                    )
            else:
                bindings_map[key] = ActiveBinding(
                    namespace, binding, enabled, binding.tooltip
                )
    return bindings_map
