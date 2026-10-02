cat > ~/OmniCore/README.md << 'READMEEOF'
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
