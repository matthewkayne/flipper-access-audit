## v0.5

- DESFire EV1/EV2/EV3/Light detection via GetVersion command
- MIFARE Plus SL1/SL2/SL3 security level detection
- Scoring fix: DESFire EV2/EV3 and Plus SL2/SL3 now correctly score SECURE
- Scoring fix: MIFARE Plus SL1 now scores HIGH RISK (Classic-compatibility mode)
- Per-card Advice line in reports with plain-English recommendation
- Confidence percentage shown alongside risk score in reports
- Session-level ACTION REQUIRED / REVIEW RECOMMENDED advisory in reports

## v0.4

- Optional session naming on save via on-screen QWERTY keyboard
- Session name written to report header when provided
- App icon added (10×10px)

## v0.3

- RFID 125 kHz support: EM4100, HID H10301, HID Generic, Indala, and more
- Left/Right on scan screen toggles between NFC and RFID modes
- Radio type (NFC/RFID) written to each card entry in reports
- Session summary stats (High/Medium/Low/Secure counts, most common type) in report header

## v0.2

- On-device report viewer: browse and scroll saved reports without leaving the app
- MIFARE Classic 1K/4K/Mini detection via SAK byte
- NTAG203/213/215/216/I2C detection via MfUltralight poller
- Multi-scan session buffer: up to 20 cards per session with live counter

## v0.1

- NFC card scan and classification
- Instant risk score 0–100 with HIGH RISK / MODERATE / LOW RISK / SECURE label
- Six named audit rules: legacy_family, identifier_only, uid_no_memory, modern_crypto, incomplete_evidence, no_uid
- SD card report saving to /ext/apps_data/access_audit/
