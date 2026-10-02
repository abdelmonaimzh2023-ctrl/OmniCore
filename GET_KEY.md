<div align="center">

# 🔑 Get Your OmniCore License Key

**OmniCore requires a personal activation key bound to your hardware.**

Each key is unique, tied to your device fingerprint, and issued
personally by the author.

</div>

---

## How to Request a Key

### Step 1 — Run OmniCore once

```bash
git clone https://github.com/MONAIM-FP/OmniCore.git
cd OmniCore
./install.sh
python3 main.py

On the first launch, OmniCore will display your Hardware ID (HWID):
text

┌─[ SYSTEM STATUS ]────────────────────────────────────┐
│ Python      : 3.13.5 (CPython)                       │
│ OS          : Debian GNU/Linux 13 (trixie)           │
│ Environment : x11 · icewm                            │
│ HWID        : a7c9d812... (64-char fingerprint)      │
│ Session     : PENDING VERIFICATION                   │
└──────────────────────────────────────────────────────┘

Copy the full HWID — you will need to send it.
Step 2 — Contact the author on Telegram

Open Telegram and message:
<div align="center">
💬 @monaimFp
</div>

Send this exact message:
text

Hello, I would like an OmniCore license key.

HWID: <paste-your-full-64-char-hwid-here>

Purpose: <personal / academic / professional pentesting>

Step 3 — Receive your key

The author will reply with a unique key in this format:
text

VIP-MONAIM-DEV-XXXXXXXX

Step 4 — Activate OmniCore

Run OmniCore again:
bash

python3 main.py

When prompted:
text

License key: VIP-MONAIM-DEV-XXXXXXXX

You are done. The key is now bound to your hardware.
Frequently Asked Questions
<details> <summary><b>Is OmniCore free?</b></summary>

Yes — for personal, academic, and internal security testing use.
Commercial resale of the framework itself requires a separate license.
</details><details> <summary><b>How long does a key take to be issued?</b></summary>

Usually within 24 hours. If you do not hear back within 48 hours,
send a follow-up message.
</details><details> <summary><b>Can I use the same key on multiple machines?</b></summary>

No. Each key is bound to one hardware fingerprint at first use.
If you need additional machines, request additional keys.
</details><details> <summary><b>What if I change my hardware (RAM, disk, BIOS)?</b></summary>

The OmniCore fingerprint uses 15 independent hardware sources with
tiered matching (STRICT / SOFT / FUZZY). Minor hardware changes are
tolerated automatically. For a full hardware replacement, contact the
author with your new HWID.
</details><details> <summary><b>What if I reinstall my operating system?</b></summary>

Your hardware fingerprint is derived from firmware-level identifiers
(motherboard serial, BIOS, chassis), not from the OS. Reinstalling
Linux does not invalidate your key.
</details><details> <summary><b>Can I share my key with a friend?</b></summary>

No. The key is cryptographically bound to your machine. Sharing it
will not work on another device and may result in the key being
permanently banned.
</details><details> <summary><b>My key stopped working — what do I do?</b></summary>

Contact the author on Telegram with:

    Your key (first 8 characters only)

    Your current HWID

    A description of the problem

Do not post your full key publicly on GitHub or any forum.
</details>
Contact
Channel	Handle
Telegram (primary)	@monaimFp
GitHub Issues	MONAIM-FP/OmniCore/issues

    ⚠️ Security note: The author will never ask you for:

        Your full license key

        Your GitHub password

        Any payment outside the official channels

    If someone contacts you claiming to be the author and asking for
    these, they are impersonating.

<div align="center">

OmniCore — authorized pentest framework

Made with ⚡ by @monaimFp
</div>
