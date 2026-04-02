#include "iclass_provider.h"

#include <furi.h>
#include <nfc/nfc.h>
#include <nfc/nfc_poller.h>
#include <nfc/protocols/iso15693_3/iso15693_3_poller.h>
#include <toolbox/bit_buffer.h>
#include <nfc/helpers/iso13239_crc.h>
#include <string.h>
#include <stdlib.h>

/* -------------------------------------------------------------------------
 * iCLASS command bytes (HID iCLASS proprietary protocol over ISO15693 RF)
 * -------------------------------------------------------------------------
 */
#define ICLASS_CMD_ACTALL    0x0A  /* SOF-only response (IncompleteFrame expected) */
#define ICLASS_CMD_IDENTIFY  0x0C  /* Response: CSN(8) + iCLASS CRC16(2) */
#define ICLASS_CSN_LEN       8
#define ICLASS_POLLER_FWT_FC 100000 /* Frame wait time in FC units (~7.4 ms) */
#define ICLASS_BUF_SIZE      32

struct IclassProvider {
    Nfc*       nfc;     /* borrowed — not owned */
    NfcPoller* poller;  /* owned ISO15693_3 poller, NULL when stopped */
    BitBuffer* tx_buf;
    BitBuffer* rx_buf;
    FuriMutex* mutex;
    bool       done;
    AccessObservation pending;
};

/* -------------------------------------------------------------------------
 * ISO15693_3 poller callback — runs on the NFC worker thread
 *
 * The ISO15693_3 poller fires Iso15693_3PollerEventTypeError whenever the
 * standard inventory command gets no response.  HID iCLASS DP never responds
 * to inventory, so we always arrive here.  With the ISO15693 RF channel
 * already established, we inject the proprietary ACTALL + IDENTIFY exchange
 * using the low-level nfc_poller_trx() (raw bytes, no CRC manipulation).
 * -------------------------------------------------------------------------
 */
static NfcCommand iclass_poller_cb(NfcGenericEvent event, void* context) {
    IclassProvider* p = context;
    Iso15693_3PollerEvent* iso_event = (Iso15693_3PollerEvent*)event.event_data;

    if(iso_event->type == Iso15693_3PollerEventTypeReady) {
        /* A standard ISO15693 card responded to inventory — not an iCLASS DP.
         * Reset and keep scanning. */
        return NfcCommandReset;
    }

    /* Iso15693_3PollerEventTypeError: inventory got no response.
     * The RF field is still on.  Try iCLASS ACTALL then IDENTIFY.
     * NfcCommandReset on any failure causes the poller to restart with its
     * own built-in inter-poll delay, preventing a tight spin. */

    /* ── Step 1: ACTALL ── */
    bit_buffer_reset(p->tx_buf);
    bit_buffer_append_byte(p->tx_buf, ICLASS_CMD_ACTALL);

    NfcError err = nfc_poller_trx(p->nfc, p->tx_buf, p->rx_buf, ICLASS_POLLER_FWT_FC);
    /* ACTALL response is a bare SOF — IncompleteFrame is success here */
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

    /* Expect CSN(8) + CRC(2) = 10 bytes; verify iCLASS CRC and strip it */
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

    p->nfc    = nfc;   /* borrowed — not owned */
    p->poller = NULL;
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
    bool already_running = (provider->poller != NULL);
    provider->done = false;
    furi_mutex_release(provider->mutex);

    if(already_running) return;

    /* Start an ISO15693_3 poller directly (no NfcScanner needed).
     * The poller manages the Nfc* lifecycle — no nfc_config/nfc_start needed. */
    NfcPoller* poller = nfc_poller_alloc(provider->nfc, NfcProtocolIso15693_3);

    furi_mutex_acquire(provider->mutex, FuriWaitForever);
    provider->poller = poller;
    furi_mutex_release(provider->mutex);

    if(poller) {
        nfc_poller_start(poller, iclass_poller_cb, provider);
    }
}

void iclass_provider_stop(IclassProvider* provider) {
    if(!provider) return;

    furi_mutex_acquire(provider->mutex, FuriWaitForever);
    NfcPoller* poller = provider->poller;
    provider->poller = NULL;
    furi_mutex_release(provider->mutex);

    if(poller) {
        nfc_poller_stop(poller);
        nfc_poller_free(poller);
    }
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
