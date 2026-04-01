# Audit Rules

Each rule maps to a named finding in saved reports. Rules are additive — multiple rules can fire on the same observation.

---

## High-risk rules

### `legacy_family`

Triggers for credential families considered lower-assurance in a modern deployment.

Matches: EM4100-like · HID Prox-like · MIFARE Classic (any variant: 1K, 4K, Mini)

**Score contribution:** +35

---

### `identifier_only_pattern`

Triggers when a stable UID is present with no evidence of protected user memory and repeated reads are identical. The card is used as a static replay token — the UID alone is the credential.

Signals:
- UID present
- No user memory present
- Repeated reads identical

**Score contribution:** +35

---

## Medium-risk rules

### `uid_no_memory`

Weaker form of `identifier_only_pattern`. UID is present but no user memory has been observed. Does not fire when `identifier_only_pattern` already applies.

**Score contribution:** +20

---

## Low-risk / confidence rules

### `incomplete_evidence`

Classification metadata is incomplete. Treat the result with caution.

**Score contribution:** +10, −20 confidence

---

### `no_uid`

UID could not be extracted. The observation cannot be fully assessed.

**Score contribution:** +10, −15 confidence

---

## Mitigating rules

### `modern_crypto`

Card family uses modern cryptography (MIFARE DESFire, MIFARE Plus, FeliCa). Reduces the effective risk score.

Matches: MIFARE DESFire · MIFARE Plus · FeliCa

**Score contribution:** −20 (and clamps max severity to MODERATE if no legacy rule also fired)
