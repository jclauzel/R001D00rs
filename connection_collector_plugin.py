"""
Abstract base class for R001D00rs connection collector plugins.

Any plugin must subclass ``ConnectionCollectorPlugin`` and implement:
  - ``name``        (property) — human-readable display name
  - ``description`` (property) — short description shown in the UI tooltip
  - ``collect_raw_connections()`` — returns a ``list[dict]`` of raw connections

Each dict returned by ``collect_raw_connections`` must contain **at least**
the following string keys (values are all strings):

    process     — process name (e.g. "chrome.exe", "unknown")
    pid         — process ID as string (e.g. "1234", or "")
    protocol    — "TCP" or "UDP"
    local       — local IP address
    localport   — local port as string
    remote      — remote IP address (or "*" / "" if unknown)
    remoteport  — remote port as string (or "*" / "" if unknown)
    ip_type     — "IPv4" or "IPv6"
    hostname    — hostname of the machine that owns this connection

Optional numeric keys (int, default 0 when absent):

    bytes_sent  — total bytes sent on this connection (outbound)
    bytes_recv  — total bytes received on this connection (inbound)

When the collector can measure traffic volume (e.g. Scapy-based packet
capture), it should populate ``bytes_sent`` and ``bytes_recv``.  The main
application uses these values to render an optional traffic gauge on the
map next to each marker.
"""

from abc import ABC, abstractmethod


class ConnectionCollectorPlugin(ABC):
    """Base class for connection collector plugins."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable name shown in the Settings UI combo box."""
        ...

    @property
    def description(self) -> str:
        """Optional one-line description (used as tooltip)."""
        return ""

    @abstractmethod
    def collect_raw_connections(self) -> list:
        """Return a list of raw connection dicts.

        See module docstring for the required dict keys.
        """
        ...

    def stop(self):
        """Optional cleanup hook called when the user switches to a different
        collector or when the application exits.

        Override this if your plugin runs background threads or holds
        system resources (e.g. a live packet sniffer).  The default
        implementation does nothing.
        """
        pass
