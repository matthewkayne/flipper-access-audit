# Changelog

All notable changes to this project are documented here.

## [1.2.0] — Code cleanup, delete report, full docs

### Added
- **Delete report from viewer** — hold Back in the report viewer to open a delete confirmation screen; OK deletes and returns to the report list, Back cancels
- **docs/scoring.md** — full scoring formula with severity thresholds, confidence penalties, and worked examples for every common card type
- **docs/card-types.md** — reference table for every `CardType` enum value: risk rating, common deployment, and recommended remediation
- **docs/contributing.md** — step-by-step guide for adding a new card type or rule, including provider patterns and code style notes

### Changed
- `rule_identifier_only_pattern` — removed the `repeated_reads_identical` field that was never set by any provider; rule now fires on `uid_present && !user_memory_present && metadata_complete`, which correctly identifies all static-replay credential patterns
- `AccessObservation` struct — removed the dead `repeated_reads_identical` field

### Fixed
- docs/rules.md — updated `identifier_only_pattern` signal conditions to match the implementation; added HID iCLASS Legacy family to `legacy_family` match list; corrected rule interaction examples table (scores now reflect `identifier_only_pattern` firing correctly)

## [1.1.0] — HID iCLASS support and bug fixes

### Added
- **HID iCLASS scanning** — proprietary ACTALL → IDENTIFY → SELECT → READ block 1 exchange over ISO15693 RF; detects and scores iCLASS DES/3DES legacy cards (HIGH RISK) with advice to upgrade to iCLASS SE/Seos
- **iCLASS memory variant classification** — reads configuration block to distinguish 2k, 16k, and 32k variants where block 1 is accessible; falls back to generic "HID iCLASS (Legacy)" gracefully when block is protected
- **Three-way scan mode** — Left/Right on scan screen now cycles NFC → RFID → iCLASS → NFC

### Fixed
- Left arrow now cycles scan mode in reverse; previously both arrows cycled in the same direction
- Consecutive iCLASS rescans now work correctly — a stale-poller slot prevents the poller appearing still-running after it completes
- Report directory (`/ext/apps_data/access_audit`) now created recursively on first save; previously silent failures on SD cards where the parent directory did not yet exist
- Report list now reads all reports before sorting, so the newest reports always appear first; previously capped at 20 before sort, which hid newer files when more than 20 existed
- Post-save confirmation screen now returns to scan mode instead of exiting the app
- Save result correctly captured when saving without a session name via the Back button

## [1.0.0] — First stable release

- Full NFC 13.56 MHz and RFID 125 kHz support with hardware-safe toggling
- Deep card classification: DESFire EV1/EV2/EV3/Light, MIFARE Classic 1K/4K/Mini, Plus SL1/SL2/SL3, NTAG203/213/215/216/I2C, EM4100, HID H10301/Generic, Indala, and more
- Six named audit rules with additive scoring (0–100) and four severity labels
- MIFARE Plus SL1 correctly scored HIGH RISK; DESFire EV2/EV3 correctly scored SECURE
- Named scan sessions via on-screen QWERTY keyboard
- Multi-scan session buffer (up to 20 cards) with live counter
- SD card reports with per-card advice, confidence score, memory capacity, manufacturer, UID byte count, unique card count, mixed-tech flag, and session-level advisory
- On-device report viewer with scrolling
- App icon (10×10px)

## [0.5.0] — Deep card classification and report improvements

- DESFire EV1/EV2/EV3/Light detection via GetVersion command (poller callback)
- MIFARE Plus SL1/SL2/SL3 detection via SDK security level response
- Scoring fix: DESFire EV2/EV3 and Plus SL2/SL3 now correctly score SECURE
- Scoring fix: MIFARE Plus SL1 now scores HIGH RISK (Classic-compatibility mode)
- Per-card `Advice:` line in reports with plain-English recommendation per card type
- Confidence percentage shown alongside risk score in reports
- Session-level `ACTION REQUIRED` / `REVIEW RECOMMENDED` advisory at end of report
- README and docs updated to reflect full card classification depth and scoring behaviour

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
