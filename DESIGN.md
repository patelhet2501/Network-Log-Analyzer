# Design Notes

This document explains *why* the analyzer is built the way it is. For usage and
example output, see the [README](README.md).

## Goals

The tool is a **first-pass triage helper** for Cisco syslog / OSPF logs. When a
network or SOC analyst is staring at thousands of raw log lines, three patterns
are easy to miss and expensive to ignore:

- **Routing instability** — an OSPF neighbor whose adjacency keeps flapping.
- **Link instability** — an interface that repeatedly bounces up and down.
- **Authentication problems** — repeated login failures, often from one source.

The goal is not to be a full SIEM. It is a small, explainable script that
collapses noisy logs into a short summary pointing at the unstable neighbors,
flapping interfaces, suspicious logins, and noisiest devices — so a human knows
where to look first.

## High-level flow

The pipeline is four clear stages, each easy to test in isolation:

```
parse  ->  classify  ->  aggregate  ->  summarize
```

1. **Parse** (`parse_line`) — turn one raw line into a structured `LogEvent`
   (timestamp, device, facility, severity, message), or `None` if the line
   isn't a recognizable Cisco message.
2. **Classify** — while parsing, decide the event's `kind` and `key` (see
   below).
3. **Aggregate** (`analyze_events`) — fold a list of events into counts:
   neighbor flaps, interface flaps, auth failures, and per-device error counts.
4. **Summarize** (CLI in `main`) — print a human-readable report, flagging
   anything at or above the flap threshold (default 3, configurable with `-t`).

Keeping these stages separate means the parsing/classification logic can be
unit-tested on hardcoded strings with no files involved.

## Classification heuristics

Every parsed line is given a `kind` (`ospf_neighbor`, `interface`, `auth`, or
`other`) and an optional `key` that identifies *what* the event is about. The
heuristics lean on the Cisco message tag `%FACILITY-SEVERITY-MNEMONIC` first,
then fall back to the message text:

- **`ospf_neighbor`** — facility `OSPF` (or an `ADJCHG` mnemonic). The `key` is
  the neighbor IP pulled from `Nbr <ip>` in the message. This is what lets us
  count flaps *per neighbor*.
- **`interface`** — facility `LINEPROTO` or `LINK` (or an `UPDOWN` mnemonic).
  The `key` is the interface name (e.g. `GigabitEthernet0/1`). Both up and down
  transitions are counted, because a link that bounces up *and* down is exactly
  the instability we want to surface.
- **`auth`** — a `SEC*` facility, a `LOGIN`/`AUTH` mnemonic, or message text
  like "login failed". The `key` prefers the username (`[user: ...]`) and falls
  back to the source IP (`[Source: ...]`), so repeated attempts can be grouped.
- **`other`** — everything else; `key` is `None`.

Tag-first matching makes the rules predictable and easy to explain; the
message-text fallbacks make them resilient to small format variations.

### Why the severity 0–4 cutoff

Cisco severities run **0 (emergency) to 7 (debug)**. Levels **5–7**
(notice / informational / debug) are routine chatter — config saves, NTP
updates, debug traces — and counting them would drown out real problems. So the
per-device "warning/error" count only includes **severity 0–4** (warning or
worse). That cutoff is what makes `device_errors` a useful "which box is
noisiest with *actual* problems" signal rather than a raw line count.

## Tests and the sample log

Two artifacts keep the tool honest and easy to demo:

- **`tests/test_analyzer.py`** — regression safety. It calls `parse_line` on
  hardcoded strings and feeds the results to `analyze_events`, asserting exact
  values (`kind`, `key`, `severity`, and the precise counts in the result
  dict). The assertions are deliberately explicit so the tests also document the
  expected behavior. No real files are read or written. Run with:
  `python -m unittest discover -s tests`.

- **`samples/sample.log`** — a small, fully synthetic log used as a live demo
  and a sanity check. It deliberately contains a neighbor that crosses the flap
  threshold and one that stays below it, an interface that bounces, repeated
  auth failures from the same source, low-severity noise that should *not* count
  as errors, and a couple of genuine severity 0–4 messages. Running the CLI
  against it (see the README's Quick demo) shows the full report end to end.

Together they cover both ends of the workflow: the unit tests guard the parsing
and aggregation logic against regressions, while the sample log exercises the
whole parse → classify → aggregate → summarize path the way a user would.
