#include "picopass_provider.h"

#include <furi.h>
#include <nfc/nfc.h>
#include <toolbox/bit_buffer.h>
#include <nfc/helpers/iso13239_crc.h>
#include <string.h>
#include <stdlib.h>

/* -------------------------------------------------------------------------
 * PicoPass command bytes (from rfal_picopass.h in bettse/picopass)
 * -------------------------------------------------------------------------
 */
#define PICOPASS_CMD_ACTALL    0x0A  /* No args → SOF only (IncompleteFrame is OK) */
#define PICOPASS_CMD_IDENTIFY  0x0C  /* No args → CSN(8) + CRC16(2) */
#define PICOPASS_CSN_LEN       8
#define PICOPASS_POLLER_FWT_FC 100000 /* Frame wait time in FC units */
#define PICOPASS_BUF_SIZE      32

struct PicopassProvider {
    Nfc*       nfc;
    BitBuffer* tx_buf;
    BitBuffer* rx_buf;
    FuriMutex* mutex;
    bool       done;
    AccessObservation pending;
};

/* -------------------------------------------------------------------------
 * Raw NFC callback — runs on the NFC worker thread
 * -------------------------------------------------------------------------
 */
static NfcCommand picopass_nfc_callback(NfcEvent event, void* context) {
    PicopassProvider* p = context;

    if(event.type != NfcEventTypePollerReady) {
        return NfcCommandContinue;
    }

    /* ── Step 1: ACTALL ── */
    bit_buffer_reset(p->tx_buf);
    bit_buffer_append_byte(p->tx_buf, PICOPASS_CMD_ACTALL);

    NfcError err = nfc_poller_trx(p->nfc, p->tx_buf, p->rx_buf, PICOPASS_POLLER_FWT_FC);
    /* ACTALL response is a bare SOF — IncompleteFrame is the expected result */
    if(err != NfcErrorNone && err != NfcErrorIncompleteFrame) {
        furi_delay_ms(50);
        return NfcCommandContinue;
    }

    /* ── Step 2: IDENTIFY ── */
    bit_buffer_reset(p->tx_buf);
    bit_buffer_append_byte(p->tx_buf, PICOPASS_CMD_IDENTIFY);

    err = nfc_poller_trx(p->nfc, p->tx_buf, p->rx_buf, PICOPASS_POLLER_FWT_FC);
    if(err != NfcErrorNone) {
        furi_delay_ms(50);
        return NfcCommandContinue;
    }

    /* Expect CSN(8) + CRC(2) = 10 bytes; verify and strip CRC */
    if(bit_buffer_get_size_bytes(p->rx_buf) != PICOPASS_CSN_LEN + 2) {
        return NfcCommandContinue;
    }
    if(!iso13239_crc_check(Iso13239CrcTypePicopass, p->rx_buf)) {
        return NfcCommandContinue;
    }
    iso13239_crc_trim(p->rx_buf);

    /* ── Build observation ── */
    furi_mutex_acquire(p->mutex, FuriWaitForever);

    p->pending = (AccessObservation){0};
    p->pending.tech = TechTypeNfc13Mhz;
    p->pending.card_type = CardTypeHidIclass;
    p->pending.metadata_complete = true;
    p->pending.uid_present = true;
    p->pending.uid_len = PICOPASS_CSN_LEN;
    bit_buffer_write_bytes(p->rx_buf, p->pending.uid, PICOPASS_CSN_LEN);
    p->done = true;

    furi_mutex_release(p->mutex);

    return NfcCommandStop;
}

/* -------------------------------------------------------------------------
 * Public API
 * -------------------------------------------------------------------------
 */

PicopassProvider* picopass_provider_alloc(void) {
    PicopassProvider* p = malloc(sizeof(PicopassProvider));
    if(!p) return NULL;

    p->nfc    = nfc_alloc();
    p->tx_buf = bit_buffer_alloc(PICOPASS_BUF_SIZE);
    p->rx_buf = bit_buffer_alloc(PICOPASS_BUF_SIZE);
    p->mutex  = furi_mutex_alloc(FuriMutexTypeNormal);
    p->done   = false;
    p->pending = (AccessObservation){0};

    if(!p->nfc || !p->tx_buf || !p->rx_buf || !p->mutex) {
        if(p->nfc)    nfc_free(p->nfc);
        if(p->tx_buf) bit_buffer_free(p->tx_buf);
        if(p->rx_buf) bit_buffer_free(p->rx_buf);
        if(p->mutex)  furi_mutex_free(p->mutex);
        free(p);
        return NULL;
    }

    /* Configure for ISO15693 polling — same parameters as picopass app */
    nfc_config(p->nfc, NfcModePoller, NfcTechIso15693);
    nfc_set_guard_time_us(p->nfc, 10000);
    nfc_set_fdt_poll_fc(p->nfc, 5000);
    nfc_set_fdt_poll_poll_us(p->nfc, 1000);

    return p;
}

void picopass_provider_free(PicopassProvider* provider) {
    if(!provider) return;
    picopass_provider_stop(provider);
    nfc_free(provider->nfc);
    bit_buffer_free(provider->tx_buf);
    bit_buffer_free(provider->rx_buf);
    furi_mutex_free(provider->mutex);
    free(provider);
}

void picopass_provider_start(PicopassProvider* provider) {
    if(!provider) return;
    furi_mutex_acquire(provider->mutex, FuriWaitForever);
    provider->done = false;
    furi_mutex_release(provider->mutex);
    nfc_start(provider->nfc, picopass_nfc_callback, provider);
}

void picopass_provider_stop(PicopassProvider* provider) {
    if(!provider) return;
    nfc_stop(provider->nfc);
}

bool picopass_provider_poll(PicopassProvider* provider, AccessObservation* out) {
    if(!provider || !out) return false;

    furi_mutex_acquire(provider->mutex, FuriWaitForever);
    bool ready = provider->done;
    AccessObservation result = provider->pending;
    if(ready) provider->done = false;
    furi_mutex_release(provider->mutex);

    if(ready) {
        *out = result;
        return true;
    }
    return false;
}
