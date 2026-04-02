#include "iclass_provider.h"

#include <furi.h>
#include <nfc/nfc.h>
#include <toolbox/bit_buffer.h>
#include <nfc/helpers/iso13239_crc.h>
#include <string.h>
#include <stdlib.h>

/* -------------------------------------------------------------------------
 * iCLASS command bytes (HID iCLASS proprietary protocol over ISO15693)
 * -------------------------------------------------------------------------
 */
#define ICLASS_CMD_ACTALL    0x0A  /* No args → SOF only (IncompleteFrame is OK) */
#define ICLASS_CMD_IDENTIFY  0x0C  /* No args → CSN(8) + CRC16(2) */
#define ICLASS_CSN_LEN       8
#define ICLASS_POLLER_FWT_FC 100000 /* Frame wait time in FC units */
#define ICLASS_BUF_SIZE      32

struct IclassProvider {
    Nfc*       nfc;    /* borrowed — not owned */
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
static NfcCommand iclass_nfc_callback(NfcEvent event, void* context) {
    IclassProvider* p = context;

    if(event.type != NfcEventTypePollerReady) {
        return NfcCommandContinue;
    }

    /* ── Step 1: ACTALL ── */
    bit_buffer_reset(p->tx_buf);
    bit_buffer_append_byte(p->tx_buf, ICLASS_CMD_ACTALL);

    NfcError err = nfc_poller_trx(p->nfc, p->tx_buf, p->rx_buf, ICLASS_POLLER_FWT_FC);
    /* ACTALL response is a bare SOF — IncompleteFrame is the expected result.
     * Any other error means no card; NfcCommandReset cycles the RF field,
     * introducing a natural inter-poll delay and preventing a tight spin. */
    if(err != NfcErrorNone && err != NfcErrorIncompleteFrame) {
        return NfcCommandReset;
    }

    /* ── Step 2: IDENTIFY ── */
    bit_buffer_reset(p->tx_buf);
    bit_buffer_append_byte(p->tx_buf, ICLASS_CMD_IDENTIFY);

    err = nfc_poller_trx(p->nfc, p->tx_buf, p->rx_buf, ICLASS_POLLER_FWT_FC);
    if(err != NfcErrorNone) {
        return NfcCommandReset;
    }

    /* Expect CSN(8) + CRC(2) = 10 bytes; verify and strip CRC */
    if(bit_buffer_get_size_bytes(p->rx_buf) != ICLASS_CSN_LEN + 2) {
        return NfcCommandReset;
    }
    if(!iso13239_crc_check(Iso13239CrcTypePicopass, p->rx_buf)) {
        return NfcCommandReset;
    }
    iso13239_crc_trim(p->rx_buf);

    /* ── Build observation ── */
    furi_mutex_acquire(p->mutex, FuriWaitForever);

    p->pending = (AccessObservation){0};
    p->pending.tech = TechTypeNfc13Mhz;
    p->pending.card_type = CardTypeHidIclass;
    p->pending.metadata_complete = true;
    p->pending.uid_present = true;
    p->pending.uid_len = ICLASS_CSN_LEN;
    bit_buffer_write_bytes(p->rx_buf, p->pending.uid, ICLASS_CSN_LEN);
    p->done = true;

    furi_mutex_release(p->mutex);

    return NfcCommandStop;
}

/* -------------------------------------------------------------------------
 * Public API
 * -------------------------------------------------------------------------
 */

IclassProvider* iclass_provider_alloc(Nfc* nfc) {
    if(!nfc) return NULL;

    IclassProvider* p = malloc(sizeof(IclassProvider));
    if(!p) return NULL;

    p->nfc    = nfc;  /* borrowed — not owned */
    p->tx_buf = bit_buffer_alloc(ICLASS_BUF_SIZE);
    p->rx_buf = bit_buffer_alloc(ICLASS_BUF_SIZE);
    p->mutex  = furi_mutex_alloc(FuriMutexTypeNormal);
    p->done   = false;
    p->pending = (AccessObservation){0};

    if(!p->tx_buf || !p->rx_buf || !p->mutex) {
        if(p->tx_buf) bit_buffer_free(p->tx_buf);
        if(p->rx_buf) bit_buffer_free(p->rx_buf);
        if(p->mutex)  furi_mutex_free(p->mutex);
        free(p);
        return NULL;
    }

    return p;
}

void iclass_provider_free(IclassProvider* provider) {
    if(!provider) return;
    iclass_provider_stop(provider);
    /* nfc is borrowed — do not free it */
    bit_buffer_free(provider->tx_buf);
    bit_buffer_free(provider->rx_buf);
    furi_mutex_free(provider->mutex);
    free(provider);
}

void iclass_provider_start(IclassProvider* provider) {
    if(!provider) return;

    furi_mutex_acquire(provider->mutex, FuriWaitForever);
    provider->done = false;
    furi_mutex_release(provider->mutex);

    /* Ensure the NFC hardware is fully stopped before reconfiguring.
     * The Nfc* may be in an intermediate state after NfcScanner last used it. */
    nfc_stop(provider->nfc);

    /* Configure for ISO15693 polling with HID iCLASS timing parameters */
    nfc_config(provider->nfc, NfcModePoller, NfcTechIso15693);
    nfc_set_guard_time_us(provider->nfc, 10000);
    nfc_set_fdt_poll_fc(provider->nfc, 5000);
    nfc_set_fdt_poll_poll_us(provider->nfc, 1000);

    nfc_start(provider->nfc, iclass_nfc_callback, provider);
}

void iclass_provider_stop(IclassProvider* provider) {
    if(!provider) return;
    nfc_stop(provider->nfc);
}

bool iclass_provider_poll(IclassProvider* provider, AccessObservation* out) {
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
