# Audit Rules

Each rule maps to a named finding in saved reports. Rules are additive — multiple rules can fire on the same observation. The final score is clamped to 0–100.

---

## High-risk rules

### `legacy_family`

Triggers for credential families that lack effective cryptographic protection.

Matches:
- All 125 kHz RFID protocols (EM4100-like, HID Prox, HID Generic, Indala, generic 125 kHz) — no crypto at all
- MIFARE Classic (1K, 4K, Mini) — Crypto1 cipher is practically broken
- MIFARE Plus SL1 — Classic-compatibility mode; AES is not active

**Score contribution:** +35 · **Max severity:** HIGH

---

### `identifier_only_pattern`

Triggers when a stable UID is present with no evidence of protected user memory and repeated reads are identical. The card behaves as a static replay token — the UID alone is the credential.

Signals:
- `uid_present` = true
- `user_memory_present` = false
- `repeated_reads_identical` = true

**Score contribution:** +35 · **Max severity:** HIGH

---

## Medium-risk rules

### `uid_no_memory`

Weaker form of `identifier_only_pattern`. A UID is present but no evidence of authenticated/protected memory has been observed. Does not fire when `identifier_only_pattern` already applies, or when the card has confirmed protected application memory (DESFire with apps, Plus SL2/SL3).

**Score contribution:** +20 · **Max severity:** MEDIUM

---

## Low-risk / confidence rules

### `incomplete_evidence`

Classification metadata is incomplete. The result should be treated with caution.

**Score contribution:** +10 · **Confidence penalty:** −20

---

### `no_uid`

UID could not be extracted. The observation cannot be fully assessed.

**Score contribution:** +10 · **Confidence penalty:** −15

---

## Mitigating rules

### `modern_crypto`

Card family uses modern cryptography. Reduces the effective risk score and lowers the severity label.

Matches:
- MIFARE DESFire (all variants: EV1, EV2, EV3, Light) — DES/3DES or AES
- MIFARE Plus SL2 — AES crypto active (Classic-format frames)
- MIFARE Plus SL3 — AES crypto + ISO14443-4 protocol
- FeliCa — proprietary crypto

**Score contribution:** −20 · **Severity effect:** HIGH → MEDIUM (when no legacy rule also fired); MEDIUM → SECURE when score reaches zero

---

## Scoring thresholds

| Label | Score range | Typical cause |
|---|---|---|
| HIGH RISK | 35–100 | `legacy_family` or `identifier_only_pattern` fired |
| MODERATE | 20–34 | `uid_no_memory` fired without modern crypto mitigation |
| LOW RISK | 10–19 | `incomplete_evidence` or `no_uid` only |
| SECURE | 0–9 | Modern crypto family with no other risk factors |

---

## Rule interaction examples

| Card | Rules fired | Score | Label |
|---|---|---|---|
| EM4100 | legacy_family, uid_no_memory | 55 | HIGH RISK |
| MIFARE Classic 1K | legacy_family, uid_no_memory | 55 | HIGH RISK |
| MIFARE Plus SL1 | legacy_family, uid_no_memory | 55 | HIGH RISK |
| MIFARE Plus SL2 | uid_no_memory, modern_crypto | 0 | SECURE |
| MIFARE Plus SL3 | modern_crypto | 0 | SECURE |
| DESFire EV1/EV2/EV3 | modern_crypto | 0 | SECURE |
| NTAG213 | uid_no_memory | 20 | MODERATE |
| Unknown card | incomplete_evidence, no_uid | 20 | MODERATE |
