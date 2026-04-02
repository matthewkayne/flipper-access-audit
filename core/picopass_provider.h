#pragma once

#include <stdbool.h>
#include "observation.h"

/**
 * Minimal iCLASS / PicoPass provider.
 *
 * HID iCLASS does not respond to standard ISO15693 inventory commands, so it
 * is invisible to NfcScanner. This provider bypasses the scanner and uses the
 * raw NFC API (NfcTechIso15693 + nfc_poller_trx) to send the picopass-specific
 * ACTALL and IDENTIFY commands, which are the only commands needed to obtain
 * the CSN (card serial number, equivalent to a UID).
 *
 * Protocol reference: bettse/picopass (rfal_picopass.h, picopass_poller_i.c)
 */

typedef struct PicopassProvider PicopassProvider;

PicopassProvider* picopass_provider_alloc(void);
void              picopass_provider_free(PicopassProvider* provider);

void picopass_provider_start(PicopassProvider* provider);
void picopass_provider_stop(PicopassProvider* provider);

/** Returns true and fills *out once a card has been identified. */
bool picopass_provider_poll(PicopassProvider* provider, AccessObservation* out);
