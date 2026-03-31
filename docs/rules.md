# Audit Rules v1

## legacy_family

Triggers for older credential families that should be treated as lower-assurance in a modern deployment.

Current matches:

- EM4100-like
- MIFARE Classic

## identifier_only_pattern

Triggers when a stable identifier is present and there is no evidence of meaningful protected user memory in the current observation.

Signals:

- UID present
- No user memory present
- Repeated reads are identical

## incomplete_evidence

Triggers when classification metadata is incomplete, so the result should be treated with caution.
