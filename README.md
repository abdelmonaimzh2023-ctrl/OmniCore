<div align="center">

<img src="assets/banner.svg" alt="OmniCore Banner" width="100%"/>

# OmniCore

**A modular, self-updating authorized penetration testing framework for Linux.**

[![License](https://img.shields.io/badge/License-FSL--1.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python&logoColor=white)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/Platform-Linux-333?logo=linux&logoColor=white)](#requirements)
[![Status](https://img.shields.io/badge/Status-Stable-brightgreen)](#)
[![PRs](https://img.shields.io/badge/PRs-Welcome-orange)](#contributing)
[![Maintenance](https://img.shields.io/badge/Maintained-Yes-green)](#)

**Reconnaissance · Web Assessment · Wireless · Health · Reporting**

[Quick Start](#quick-start) · [Features](#features) · [Modules](#modules) · [Installation](#installation) · [License](#license)

</div>

---

## Overview

**OmniCore** is a unified Linux framework that orchestrates the tools you
already trust — `nmap`, `nikto`, `sqlmap`, `aircrack-ng`, `hashcat`, and
more — behind a single, coherent terminal interface. It installs its own
toolkit, updates itself atomically from a cloud backend, and produces
professional multi-format reports.

Designed for **licensed pentesters**, **red teams**, and **security
researchers** running authorized engagements.

> ⚠️ **AUTHORIZED USE ONLY.** You must have **written permission** from
> the owner of any system you test. Unauthorized access is a criminal
> offense in most jurisdictions.

---

## Features

<table>
<tr>
<td width="50%" valign="top">

### 🎯 Core

- **Single-command bootstrap** — `python3 main.py` and you are in.
- **Atomic self-updates** — every module is SHA-256 verified before it lands.
- **Hardware-locked licensing** — 15-source fingerprint with fuzzy
  matching that survives OS reinstall, disk swap, and MAC randomization.
- **Auto tool install** — 300+ tools installed on demand via `apt`,
  `dnf`, `pacman`, `zypper`, `pipx`, or `git`.
- **Distro-aware** — detects your init system, network manager, and
  wireless stack automatically.

</td>
<td width="50%" valign="top">

### 🛡️ Defensive

- **Fail-closed integrity** — refuses to start with a missing file.
- **Authorization gates** — per-BSSID typed confirmation for every
  active wireless technique.
- **Tamper resistance** — session tokens bound to hardware + HMAC.
- **No telemetry** — nothing leaves your machine unless *you* publish.
- **Audit trail** — every sensitive action is timestamped and logged.

</td>
</tr>
</table>

---

## Requirements

| Component | Minimum |
|---|---|
| **OS**           | Linux (Debian, Ubuntu, Kali, Fedora, Arch, openSUSE, antiX, …) |
| **Python**       | 3.10+ |
| **Privileges**   | `sudo` for install; root for wireless/raw-socket features |
| **Disk**         | ~500 MB (toolkit) + ~100 MB (reports) |
| **Network**      | Internet for module updates (offline mode available) |

---

## Installation

### Quick install (recommended)

```bash
git clone https://github.com/MONAIM-FP/OmniCore.git
cd OmniCore
chmod +x install.sh
./install.sh
python3 main.py

Manual install
bash

git clone https://github.com/MONAIM-FP/OmniCore.git
cd OmniCore

# Install Python dependency (only one: requests)
python3 -m pip install --user requests

# Mark entry points executable
chmod +x main.py hwid_guard.py updater.py hardware_id.py integrity.py

# Run
python3 main.py

First run

On first launch OmniCore will:

    Verify your hardware and generate a device fingerprint.

    Ask for a license key (see License keys below).

    Download the module set from the cloud backend.

    Install any missing tools automatically.

    Present the main menu.

Quick Start
text

$ python3 main.py
License key: XXXX-XXXX-XXXX-XXXX

── PHASE 1 :: HWID & LICENSE ENFORCEMENT ────────────────
[+] License verified :: HWID a7c9d812... :: session ACTIVE

── PHASE 2 :: AUTO-UPDATE PIPELINE ──────────────────────
[+] 10 modules updated
[i] Sync finished in 1.24s

── PHASE 3 :: DYNAMIC MODULE INJECTION ──────────────────
[+] Loaded module 'core_engine' ...

You will then see the main menu:
text

╭───────────────── OMNICORE — MAIN MENU ─────────────────╮
│                                                         │
│   [1]  Install / Update Pentest Toolkit                 │
│   [2]  System Health Scan                               │
│   [3]  Reconnaissance                                   │
│   [4]  Web Assessment                                   │
│   [5]  Wireless Analysis                                │
│   [6]  Report Generator                                 │
│   [7]  Support                                          │
│   [8]  Settings                                         │
│   [0]  Exit                                             │
╰─────────────────────────────────────────────────────────╯

Modules
#	Module	Description	Tools
1	Installer	Installs 300+ curated security tools	apt dnf pacman zypper pipx git
2	Health Scan	Defensive audit of the local host	ss lsof journalctl find
3	Reconnaissance	Network information gathering	nmap whois dig traceroute subfinder
4	Web Assessment	Web application security testing	nikto gobuster sqlmap ffuf wpscan
5	Wireless	Wi-Fi / Bluetooth audit	aircrack-ng reaver hashcat kismet
6	Reporting	Multi-format evidence reports	HTML · PDF · Markdown · JSON · TXT
Architecture
text

┌───────────────────────────────────────────────────────────┐
│   main.py              ← entry point + 4-phase pipeline   │
│     ↓                                                     │
│   Phase 1  hwid_guard  ← hardware fingerprint + license   │
│   Phase 2  updater     ← atomic SHA-256 module sync       │
│   Phase 3  core_engine ← dynamic import + menu            │
│   Phase 4  shutdown    ← graceful exit + state cleanup    │
└───────────────────────────────────────────────────────────┘
                          │
                          ▼
              ┌─────────────────────────┐
              │   ~/.local/share/       │
              │   OmniCore/modules/     │
              │                         │
              │   recon.py              │
              │   web_scan.py           │
              │   wireless.py           │
              │   health_scan.py        │
              │   report.py             │
              └─────────────────────────┘

Hardware Fingerprint

OmniCore identifies your machine using 15 independent hardware
sources combined into a tiered fingerprint:

    DMI serials — motherboard, product, chassis (root)

    Storage — physical disk serial

    Firmware — BIOS vendor / version / date

    CPU — vendor + model + core count

    Network — first physical MAC (non-virtual)

Three matching tiers are used server-side:
Tier	Meaning
STRICT	Every source matches exactly.
SOFT	The combined hash matches.
FUZZY	≥ 3 of ≥ 4 components match (hardware changes).

This means your license survives OS reinstalls, disk swaps,
RAM upgrades, and MAC randomization — while still blocking
unauthorized machines.
Security

    No telemetry. OmniCore never sends your data anywhere except the
    configured license/update backend.

    Atomic writes. Every file is written via tempfile + os.replace.

    Fail-closed. Missing bootstrap files abort startup. No files are
    ever modified or deleted as a side effect.

    Signature verified. Every downloaded module is SHA-256 checked
    before it becomes importable.

    Session-bound. Dynamic modules refuse to run outside the pipeline
    and require an HMAC-signed session token.

Reporting

Reports are generated in five synchronized formats:
Format	Purpose
HTML	Branded, print-ready A4 document
PDF	Same content, ideal for clients
MD	Editable, version-control friendly
JSON	Machine readable, CI/CD friendly
TXT	Plain-text evidence archive

Every report includes:

    Cover page with session ID + HWID fingerprint

    Table of contents

    Executive summary with severity breakdown

    Per-target detail with key findings

    Full untruncated raw evidence in appendix

    SHA-256 integrity hash of every included scan file

License Keys

OmniCore requires a valid license key bound to your hardware fingerprint.

To obtain a key:

    ✉️ Telegram: @monaimFp

    🐛 GitHub Issues: open an issue

Please include your device's HWID (shown at first run).
Legal

    ⚠️ AUTHORIZED USE ONLY.

    OmniCore is provided exclusively for authorized security testing,
    academic research, and defensive operations. You must have prior
    written permission from the owner of any system you assess.

    Unauthorized use — including but not limited to accessing systems
    without permission, intercepting communications, or disrupting
    services — is a criminal offense in most jurisdictions.

    The author assumes no responsibility for misuse. By using this
    software you accept full legal responsibility for your actions.

License

Distributed under the Functional Source License (FSL-1.0).
See LICENSE for full text.

    ✅ Free for personal, academic, and internal security testing.

    ❌ Commercial resale of the framework is prohibited.

    ✅ Two years after each release, the code becomes Apache 2.0.

Contributing

Contributions are welcome via pull request.
Please do not open public issues about license enforcement
mechanics — contact the author directly.
Contact
Channel	Link
Telegram	@monaimFp
GitHub	MONAIM-FP/OmniCore
<div align="center">

OmniCore — build once, trust the fingerprint, ship everywhere.

Made with ⚡ by @monaimFp
