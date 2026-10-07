"""HTTPS helpers that keep certificate verification working in frozen builds."""
from __future__ import annotations

import ssl
from urllib.request import HTTPSHandler, OpenerDirector, Request, build_opener, urlopen

import certifi


def tls_context() -> ssl.SSLContext:
    """Build a verified TLS context from the CA bundle shipped with wifit3."""
    return ssl.create_default_context(cafile=certifi.where())


def secure_urlopen(request: Request, *, timeout: float):
    """Open one request with the bundled CA store."""
    return urlopen(request, timeout=timeout, context=tls_context())


def build_secure_opener(*handlers: object) -> OpenerDirector:
    """Build an urllib opener whose HTTPS redirects retain certificate verification."""
    return build_opener(*handlers, HTTPSHandler(context=tls_context()))
