# Flipper Access Audit

A Flipper Zero app for **defensive auditing of NFC access-control credentials**.

Tap a card, get an instant risk score. Save a session report to SD.

> **Authorized use only.** This tool is intended for security professionals, system owners, and researchers assessing systems they own or are permitted to test.

---

## Features

- **Automatic card classification** — MIFARE Classic 1K/4K/Mini, DESFire, Plus, Ultralight, NTAG203/213/215/216, NTAG I2C, ISO14443-A/B, ISO15693, FeliCa, SLIX, ST25TB
- **Instant risk score** — 0–100 score with HIGH RISK / MODERATE / LOW RISK / SECURE label
- **Multi-scan sessions** — scan up to 20 cards per session; a counter tracks how many you've scanned
- **SD card reports** — saves a timestamped `.txt` report to `/ext/apps_data/access_audit/` on exit
- **On-device report viewer** — browse and scroll through saved reports without leaving the app

---

## Installation

### From release (recommended)

1. Download `access_audit.fap` from the [latest release](https://github.com/matthewkayne/flipper-access-audit/releases/latest)
2. Copy it to `apps/Tools/` on your Flipper's SD card via qFlipper or USB
3. Launch from **Apps → Tools → Access Audit**

### Build from source

Requires [uFBT](https://github.com/flipperdevices/flipperzero-ufbt).

```sh
ufbt
# FAP is written to dist/access_audit.fap
```

---

## Usage

| Screen | Controls |
|---|---|
| Scan | Tap a card to scan · **Up** to view reports · **Back** to exit |
| Result | **OK** to rescan · **Back** to save session and exit |
| Reports list | **Up/Down** to scroll · **OK** to open · **Back** to return |
| Report viewer | **Up/Down** to scroll lines · **Back** to list |

### Score interpretation

| Label | Score | Meaning |
|---|---|---|
| HIGH RISK | 35–100 | Legacy family (MIFARE Classic, EM4100) or static-replay pattern |
| MODERATE | 20–34 | Some risk indicators present |
| LOW RISK | 10–19 | Minor concerns, e.g. incomplete metadata |
| SECURE | 0–9 | Modern crypto family, no major findings |

---

## How it works

The app uses the Flipper NFC scanner to detect the card family, then starts the appropriate poller to extract the UID and card-specific metadata without any authentication. Results are scored against a set of named rules (see [docs/rules.md](docs/rules.md)).

No card data is modified. No authentication is attempted against protected sectors.

---

## Development

- Platform: Flipper Zero (official firmware, Momentum)
- Language: C (uFBT / Flipper SDK)
- CI: GitHub Actions — builds against official release, official dev, Momentum release, and Momentum dev SDKs on every push

```
core/
  observation.h          — data model
  observation_provider.c — NFC scan pipeline (scanner + poller state machine)
  rules.c                — named audit rules
  scoring.c              — score calculator + card-type strings
  session.c              — multi-scan session buffer
  report.c               — SD card save + report listing/loading
access_audit.c           — app loop, screens, input handling
```

---

## Roadmap

- [x] NFC card scan and classification
- [x] Risk scoring with named rules
- [x] Result screen with prominent risk label
- [x] Multi-scan session buffer
- [x] SD card report saving
- [x] Card sub-type detection (Classic 1K/4K/Mini, NTAG213/215/216)
- [x] On-device report viewer
- [ ] RFID 125 kHz support (EM4100, HID Proxcard)
- [ ] Named scan sessions (user-entered label)
- [ ] Session summary stats (high/medium/low counts per report)
- [ ] Flipper App Catalog submission
- [ ] Additional card-type depth (ISO15693 sub-types, DESFire EV level)

---

## License

[MIT](LICENSE)
