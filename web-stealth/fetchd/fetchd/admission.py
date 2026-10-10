"""URL admission, mirrored from web-stealth/lib/policy.js.

The JS supervisor is authoritative; this is the second gate, because the
sidecar is the component that actually opens the socket and can also be run by
hand. Only literal addresses are checked here: with socks5h the proxy resolves
names, so a public name pointing at a private address is the proxy's decision.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

MAX_URL_LEN = 2048
_CREDENTIALS = re.compile(r"//[^/]*@")


class RejectedUrl(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _is_private(host: str) -> bool:
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    if address.version == 6:
        mapped = address.ipv4_mapped
        if mapped is None and address in ipaddress.ip_network("64:ff9b::/96"):
            # NAT64 well-known prefix: the IPv4 literal is embedded in the low 32 bits.
            mapped = ipaddress.IPv4Address(address.packed[12:])
        if mapped is not None:
            address = mapped
        elif address in ipaddress.ip_network("fc00::/7") or address in ipaddress.ip_network("fe80::/10"):
            return True
    return address.is_private or address.is_loopback or address.is_link_local or address.is_reserved or address.is_multicast


def admit(raw: str) -> str:
    """Return the URL, or raise RejectedUrl with a protocol error code."""
    if not isinstance(raw, str) or not raw:
        raise RejectedUrl("invalid-url", "url must be a non-empty string")
    if len(raw) > MAX_URL_LEN:
        raise RejectedUrl("invalid-url", f"url exceeds {MAX_URL_LEN} characters")
    if _CREDENTIALS.search(raw):
        raise RejectedUrl("invalid-url", "embedded credentials are not allowed")

    parts = urlsplit(raw)
    if parts.scheme not in ("http", "https"):
        raise RejectedUrl("invalid-url", f"scheme {parts.scheme!r} is not allowed")
    host = (parts.hostname or "").lower().rstrip(".")
    if not host:
        raise RejectedUrl("invalid-url", "url has no host")
    if host == "localhost" or host.endswith(".localhost"):
        raise RejectedUrl("blocked-url", f"{host} is a local name")
    if _is_private(host):
        raise RejectedUrl("blocked-url", f"{host} is a private or reserved address")
    return raw
