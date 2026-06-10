# Network Log Analyzer (Cisco / OSPF)

Network Log Analyzer is a Python tool that parses Cisco syslog and OSPF routing logs to highlight anomalies that could indicate misconfiguration, instability, or security issues.

## Problem

Cisco routers and switches constantly generate log messages:

- OSPF neighbor up/down events and adjacency flaps
- Interface link up/down transitions
- Authentication failures and privilege changes
- Various warnings and error conditions

When these logs are viewed as plain text, it is easy to miss patterns such as a neighbor that keeps dropping, an interface that bounces all day, or repeated login failures against the same device.

## Solution Overview

This script is designed as a first‑pass triage helper for network and SOC analysts. It:

- Accepts one or more log files containing Cisco syslog / OSPF messages
- Parses each line into a structured record (timestamp, device, severity, message)
- Applies simple, explainable heuristics to flag:
  - OSPF neighbors that flap more than a configurable threshold
  - Interfaces that repeatedly transition up/down
  - Authentication failures, unexpected privilege changes, or config write events
  - Devices that generate unusually high numbers of warnings/errors
- Produces a summary report that points the analyst to:
  - Unstable neighbors and interfaces
  - “Noisy” devices
  - Potentially suspicious authentication activity

This is not a full SIEM; it is a lightweight helper that makes raw logs easier to triage.

## Tech Stack

- Python 3
- Standard library only (`re`, `datetime`, `argparse`, `collections`)
- Designed to work with text log exports from Cisco IOS / IOS-XE devices

## Usage (design)

The planned CLI looks like:

```bash
python src/analyzer.py path/to/syslog.log [path/to/another.log ...]
```

Planned behaviour:

- Parse each line and classify it (OSPF neighbor event, interface event, auth event, other)
- Aggregate counts per neighbor, interface, device, and event type
- Print a human‑readable summary, for example:
  - Top N neighbors by flap count
  - Top N interfaces by up/down transitions
  - List of authentication failures (with timestamp and source)
  - Per‑device warning/error counts

## Status

This is an in‑progress portfolio project focused on:

- Robust parsing of common Cisco syslog / OSPF formats
- Simple but useful anomaly heuristics that a junior SOC/network analyst can explain
- Clean, CLI‑driven workflow that can be extended or integrated into larger tools