# Changelog

All notable changes to this project are documented here.

## [0.4.0] — Named sessions

- Optional session naming on save via on-screen QWERTY keyboard
- Session name written to report header when provided
- Back button on keyboard acts as backspace; saving with an empty name skips the name

## [0.3.0] — RFID support and report improvements

- RFID 125 kHz support: EM4100, HID H10301, HID Generic, Indala, and more
- Left/Right on scan screen toggles between NFC and RFID mode (lazy hardware allocation prevents conflict)
- Radio type (NFC 13.56MHz / RFID 125kHz) written to each card entry in reports
- Session summary stats (High/Medium/Low/Secure counts, most common card type) added to report header

## [0.2.0] — On-device report viewer and card sub-types

- On-device report viewer: browse and scroll saved reports without leaving the app
- Card sub-type detection: MIFARE Classic 1K/4K/Mini (via SAK byte), NTAG213/215/216/I2C (via MfUltralight poller)
- Multi-scan session buffer: scan up to 20 cards per session, session counter on result screen

## [0.1.0] — Initial release

- NFC card scan and classification (MIFARE Classic, DESFire, Plus, Ultralight, NTAG, ISO14443-A/B, ISO15693, FeliCa, SLIX, ST25TB)
- Instant risk score 0–100 with HIGH RISK / MODERATE / LOW RISK / SECURE label
- Six named audit rules: legacy_family, identifier_only, uid_no_memory, modern_crypto, incomplete_evidence, no_uid
- SD card report saving to `/ext/apps_data/access_audit/`
