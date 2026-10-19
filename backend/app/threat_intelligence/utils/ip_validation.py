from dataclasses import dataclass
from ipaddress import ip_address, ip_network

DOCUMENTATION = tuple(
    map(
        ip_network,
        ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32", "3fff::/20"),
    )
)
# IPv4 embedding/transition mechanisms are deliberately not submitted externally.
TRANSITION = tuple(
    map(ip_network, ("64:ff9b::/96", "64:ff9b:1::/48", "2002::/16", "2001::/32", "::ffff:0:0/96"))
)


@dataclass(frozen=True)
class IPTarget:
    ip: str
    version: int
    external_allowed: bool
    documentation: bool
    reason: str | None


def validate_ip(value: str) -> IPTarget:
    if not isinstance(value, str) or "%" in value or "/" in value:
        raise ValueError("Supply one IPv4 or IPv6 address without a scope or network prefix")
    try:
        address = ip_address(value.strip())
    except ValueError:
        raise ValueError("Invalid IPv4 or IPv6 address") from None
    documentation = any(address in network for network in DOCUMENTATION)
    reason = None
    if documentation:
        reason = "Documentation address; external lookup skipped"
    elif any(address in network for network in TRANSITION):
        reason = "Transition or mapped address; external lookup skipped"
    elif address.is_loopback:
        reason = "Loopback address; external lookup skipped"
    elif address.is_link_local:
        reason = "Link-local address; external lookup skipped"
    elif address.is_multicast:
        reason = "Multicast address; external lookup skipped"
    elif address.is_reserved or address.is_unspecified or not address.is_global:
        reason = "Private or non-global address; external lookup skipped"
    return IPTarget(str(address), address.version, reason is None, documentation, reason)
