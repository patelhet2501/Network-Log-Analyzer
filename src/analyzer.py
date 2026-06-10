"""Cisco syslog / OSPF log analyzer.

Parses Cisco-style syslog lines into structured :class:`LogEvent` records,
aggregates them to surface common operational anomalies (OSPF neighbor flaps,
interface up/down transitions, authentication failures, and per-device error
counts), and prints a human-readable summary from the command line.

Standard library only. The parsing is intentionally regex-driven and the
heuristics are kept small and explicit so each classification step is easy to
walk through.
"""

from __future__ import annotations

import argparse
import re
import sys
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from enum import Enum


class Kind(str, Enum):
    """Coarse classification for a parsed log line.

    Subclassing ``str`` means the members compare equal to their plain string
    values (``Kind.OSPF_NEIGHBOR == "ospf_neighbor"``), so callers can treat
    ``LogEvent.kind`` as a string without importing this enum.
    """

    OSPF_NEIGHBOR = "ospf_neighbor"
    INTERFACE = "interface"
    AUTH = "auth"
    OTHER = "other"


@dataclass
class LogEvent:
    timestamp: datetime | None
    device: str | None
    severity: str | None
    facility: str | None
    message: str
    raw: str
    kind: str  # e.g. "ospf_neighbor", "interface", "auth", "other"
    key: str | None  # e.g. neighbor ID, interface name, username


# ---------------------------------------------------------------------------
# Regular expressions
# ---------------------------------------------------------------------------
#
# A typical Cisco syslog line looks like:
#
#   Feb 10 10:23:45 R1 %OSPF-5-ADJCHG: Process 1, Nbr 10.0.0.2 on Gig0/1 ...
#   |-------------| || |----------|  |--------------------------------------|
#     timestamp     device  tag                     message
#
# We split this into three named groups up front, then look deeper into the
# message only to classify it.

# "Feb 10 10:23:45" — the classic syslog timestamp (no year).
_TS = r"(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"

# Device/host token: a bare hostname with no spaces.
_DEVICE = r"(?P<device>\S+)"

# Cisco mnemonic tag: %FACILITY-SEVERITY-MNEMONIC. Severity is a single digit
# (0-7). Facility can contain letters, digits and underscores (e.g. SEC_LOGIN).
_TAG = r"%(?P<facility>[A-Z0-9_]+)-(?P<severity>\d)-(?P<mnemonic>[A-Z0-9_]+)"

LINE_RE = re.compile(
    rf"^{_TS}\s+{_DEVICE}\s+{_TAG}:\s*(?P<message>.*)$"
)

# Fallback for lines that have a tag but no leading syslog timestamp/host,
# e.g. raw device console output: "%LINEPROTO-5-UPDOWN: ...".
TAG_ONLY_RE = re.compile(rf"^{_TAG}:\s*(?P<message>.*)$")

# An IPv4 address used to pull neighbor IDs / source IPs out of the message.
_IPV4 = r"\d{1,3}(?:\.\d{1,3}){3}"

# OSPF adjacency change: "... Nbr 10.0.0.2 ... from FULL to DOWN ..."
OSPF_NBR_RE = re.compile(rf"Nbr\s+(?P<nbr>{_IPV4})", re.IGNORECASE)

# Interface line: "Line protocol on Interface GigabitEthernet0/1, changed
# state to down" or "Interface GigabitEthernet0/1, changed state to up".
INTERFACE_RE = re.compile(
    r"Interface\s+(?P<intf>[A-Za-z][\w./-]*)",
)

# Auth failure helpers: "[user: admin]" and "[Source: 10.0.0.50]".
AUTH_USER_RE = re.compile(r"user:\s*(?P<user>[^\]\s]+)", re.IGNORECASE)
AUTH_SOURCE_RE = re.compile(rf"Source:\s*(?P<src>{_IPV4})", re.IGNORECASE)


def _parse_timestamp(ts: str) -> datetime | None:
    """Parse a syslog timestamp like ``Feb 10 10:23:45``.

    Syslog omits the year, so we assume the current year. ``strptime`` is
    whitespace-sensitive, so collapse the variable spacing first (the day can
    be space-padded, e.g. ``Feb  1``).
    """
    normalized = re.sub(r"\s+", " ", ts.strip())
    # Syslog omits the year. Splice in the current year up front (rather than
    # parsing yearless and patching afterwards) so strptime can handle Feb 29
    # and to avoid the yearless-parsing DeprecationWarning on Python 3.13+.
    year = datetime.now().year
    try:
        return datetime.strptime(f"{year} {normalized}", "%Y %b %d %H:%M:%S")
    except ValueError:
        return None


def _classify(facility: str | None, mnemonic: str | None, message: str) -> tuple[str, str | None]:
    """Decide the ``kind`` and ``key`` for a message.

    The facility/mnemonic from the Cisco tag is the primary signal; the message
    text is used as a fallback and to extract the key. Returns a
    ``(kind, key)`` pair.
    """
    facility = (facility or "").upper()
    mnemonic = (mnemonic or "").upper()

    # --- OSPF neighbor adjacency changes -------------------------------------
    # %OSPF-5-ADJCHG is the canonical one; key off the facility but also catch
    # any message that mentions a neighbor.
    if facility == "OSPF" or "ADJCHG" in mnemonic:
        m = OSPF_NBR_RE.search(message)
        if m:
            return Kind.OSPF_NEIGHBOR.value, m.group("nbr")

    # --- Interface up/down ---------------------------------------------------
    # %LINEPROTO-5-UPDOWN and %LINK-3-UPDOWN both describe interface state.
    if facility in {"LINEPROTO", "LINK"} or "UPDOWN" in mnemonic:
        m = INTERFACE_RE.search(message)
        if m:
            return Kind.INTERFACE.value, m.group("intf")

    # --- Authentication / login failures -------------------------------------
    # %SEC_LOGIN-4-LOGIN_FAILED, %SEC-6-IPACCESSLOGP, generic "login failed".
    looks_like_auth = (
        facility.startswith("SEC")
        or "LOGIN" in mnemonic
        or "AUTH" in mnemonic
        or re.search(r"login fail|authentication fail", message, re.IGNORECASE)
    )
    if looks_like_auth:
        user = AUTH_USER_RE.search(message)
        source = AUTH_SOURCE_RE.search(message)
        # Prefer the username as the key; fall back to the source IP.
        key = (user.group("user") if user else None) or (
            source.group("src") if source else None
        )
        return Kind.AUTH.value, key

    return Kind.OTHER.value, None


def parse_line(line: str) -> LogEvent | None:
    """Parse a single log line into a :class:`LogEvent`.

    Returns ``None`` for blank lines or lines that don't carry a recognizable
    Cisco tag, so callers can simply skip falsy results.
    """
    raw = line.rstrip("\n")
    if not raw.strip():
        return None

    match = LINE_RE.match(raw.strip())
    if match:
        timestamp = _parse_timestamp(match.group("ts"))
        device = match.group("device")
    else:
        # No timestamp/host prefix — try the bare-tag fallback.
        match = TAG_ONLY_RE.match(raw.strip())
        if not match:
            return None
        timestamp = None
        device = None

    facility = match.group("facility")
    mnemonic = match.group("mnemonic")
    severity = match.group("severity")
    message = match.group("message").strip()

    kind, key = _classify(facility, mnemonic, message)

    return LogEvent(
        timestamp=timestamp,
        device=device,
        severity=severity,
        facility=facility,
        message=message,
        raw=raw,
        kind=kind,
        key=key,
    )


def analyze_events(events: list[LogEvent]) -> dict:
    """Aggregate parsed events into anomaly summaries.

    Returns a dict with four entries:

    * ``neighbor_flaps``   - dict[neighbor IP -> count of adjacency changes]
    * ``interface_flaps``  - dict[interface -> count of up/down transitions]
    * ``auth_failures``    - list[LogEvent] for every auth failure seen
    * ``device_errors``    - dict[device -> count of warnings/errors]

    A "flap" here is simply any state-change event for that neighbor/interface;
    a high count is what makes it interesting. Counting both up and down
    transitions is deliberate — a link that bounces up and down repeatedly is
    exactly the instability we want to surface.
    """
    neighbor_flaps: Counter[str] = Counter()
    interface_flaps: Counter[str] = Counter()
    auth_failures: list[LogEvent] = []
    device_errors: Counter[str] = Counter()

    for event in events:
        if event.kind == Kind.OSPF_NEIGHBOR.value and event.key:
            neighbor_flaps[event.key] += 1
        elif event.kind == Kind.INTERFACE.value and event.key:
            interface_flaps[event.key] += 1
        elif event.kind == Kind.AUTH.value:
            auth_failures.append(event)

        # Cisco severity is 0 (emergency) .. 7 (debug); 0-4 are
        # warnings/errors or worse. Count those per device for an at-a-glance
        # "which box is noisiest" view.
        if event.device and event.severity is not None:
            try:
                level = int(event.severity)
            except ValueError:
                level = 7
            if level <= 4:
                device_errors[event.device] += 1

    return {
        "neighbor_flaps": dict(neighbor_flaps),
        "interface_flaps": dict(interface_flaps),
        "auth_failures": auth_failures,
        "device_errors": dict(device_errors),
    }


# ---------------------------------------------------------------------------
# CLI / reporting
# ---------------------------------------------------------------------------

def _format_ts(ts: datetime | None) -> str:
    return ts.strftime("%Y-%m-%d %H:%M:%S") if ts else "<no timestamp>"


def _print_summary(analysis: dict, flap_threshold: int) -> None:
    """Print a human-readable report from :func:`analyze_events` output."""
    neighbor_flaps: dict = analysis["neighbor_flaps"]
    interface_flaps: dict = analysis["interface_flaps"]
    auth_failures: list[LogEvent] = analysis["auth_failures"]
    device_errors: dict = analysis["device_errors"]

    print("=" * 60)
    print("Network log analysis summary")
    print("=" * 60)

    # --- OSPF neighbor flaps -------------------------------------------------
    print(f"\nTop OSPF neighbors by flap count (threshold = {flap_threshold})")
    if neighbor_flaps:
        for nbr, count in sorted(neighbor_flaps.items(), key=lambda kv: (-kv[1], kv[0])):
            flag = "  <-- above threshold" if count >= flap_threshold else ""
            print(f"  {nbr:<18} {count:>4} adjacency change(s){flag}")
    else:
        print("  (none)")

    # --- Interface flaps -----------------------------------------------------
    print("\nTop interfaces by up/down transitions")
    if interface_flaps:
        for intf, count in sorted(interface_flaps.items(), key=lambda kv: (-kv[1], kv[0])):
            flag = "  <-- above threshold" if count >= flap_threshold else ""
            print(f"  {intf:<24} {count:>4} transition(s){flag}")
    else:
        print("  (none)")

    # --- Auth failures -------------------------------------------------------
    print(f"\nAuthentication failures ({len(auth_failures)} total)")
    if auth_failures:
        for event in auth_failures:
            print(
                f"  {_format_ts(event.timestamp)}, "
                f"{event.device or '<unknown device>'}, "
                f"{event.message}"
            )
    else:
        print("  (none)")

    # --- Per-device errors ---------------------------------------------------
    print("\nPer-device warning/error counts (severity 0-4)")
    if device_errors:
        for device, count in sorted(device_errors.items(), key=lambda kv: (-kv[1], kv[0])):
            print(f"  {device:<18} {count:>4} event(s)")
    else:
        print("  (none)")

    print()


def _iter_lines(paths: list[str]):
    """Yield lines from each path, or from stdin when no paths are given."""
    if not paths:
        yield from sys.stdin
        return
    for path in paths:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as handle:
                yield from handle
        except OSError as exc:
            print(f"warning: could not read {path}: {exc}", file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Analyze Cisco syslog / OSPF logs for common anomalies.",
    )
    parser.add_argument(
        "paths",
        nargs="*",
        metavar="LOGFILE",
        help="One or more log files to analyze. Reads stdin if none are given.",
    )
    parser.add_argument(
        "-t",
        "--threshold",
        type=int,
        default=3,
        help="Flap-count threshold used to flag noisy neighbors/interfaces "
        "(default: 3).",
    )
    args = parser.parse_args(argv)

    events: list[LogEvent] = []
    for line in _iter_lines(args.paths):
        event = parse_line(line)
        if event is not None:
            events.append(event)

    analysis = analyze_events(events)
    _print_summary(analysis, flap_threshold=args.threshold)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
