#include <furi.h>
#include <nfc/nfc.h>
#include <nfc/nfc_poller.h>
#include <nfc/nfc_scanner.h>
#include <nfc/protocols/nfc_protocol.h>
#include <nfc/protocols/iso14443_3a/iso14443_3a.h>
#include <nfc/protocols/iso14443_3a/iso14443_3a_poller.h>

#include "observation_provider.h"

/* -------------------------------------------------------------------------
 * Internal state machine
 * -------------------------------------------------------------------------
 *
 * Idle ──start()──> Scanning ──(scanner cb)──> ReadPending
 *                                                   │
 *                                            poll() stops scanner,
 *                                            starts ISO14443-3a poller
 *                                                   │
 *                                               Reading
 *                                              /       \
 *                                    (poller cb)       (poller cb)
 *                                       Ready          Error/Fail
 *                                          │                │
 *                                        Done          ReadFailed
 *                                          │                │
 *                                    poll() returns    poll() restarts
 *                                    true, goes Idle    scanner
 *
 * All reads/writes of shared fields happen under mutex.
 * All NFC API calls (start/stop/free) happen OUTSIDE the mutex to avoid
 * deadlocks with the NFC worker thread that runs the callbacks.
 * -------------------------------------------------------------------------
 */

typedef enum {
    ProviderStateIdle,
    ProviderStateScanning,
    ProviderStateReadPending,
    ProviderStateReading,
    ProviderStateDone,
    ProviderStateReadFailed,
} ProviderState;

struct ObservationProvider {
    Nfc* nfc;
    NfcScanner* scanner;
    NfcPoller* poller;
    FuriMutex* mutex;
    ProviderState state;
    /* Set by scanner callback, read by poll() */
    CardType detected_card_type;
    /* Always NfcProtocolIso14443_3a for 3a-family cards */
    NfcProtocol uid_protocol;
    /* Populated by poller callback */
    AccessObservation pending;
};

/* -------------------------------------------------------------------------
 * Protocol helpers
 * -------------------------------------------------------------------------
 */

/** Map a detected protocol to its CardType. Higher-priority protocols are
 *  checked first so the richest classification wins. */
static CardType protocol_to_card_type(NfcProtocol protocol) {
    switch(protocol) {
    case NfcProtocolMfDesfire:
        return CardTypeMifareDesfire;
    case NfcProtocolMfPlus:
        return CardTypeMifarePlus;
    case NfcProtocolMfClassic:
        return CardTypeMifareClassic;
    case NfcProtocolMfUltralight:
        return CardTypeMifareUltralight;
    case NfcProtocolIso14443_4a:
    case NfcProtocolIso14443_3a:
        return CardTypeIso14443A;
    case NfcProtocolIso14443_4b:
    case NfcProtocolIso14443_3b:
        return CardTypeIso14443B;
    case NfcProtocolIso15693_3:
        return CardTypeIso15693;
    case NfcProtocolFelica:
        return CardTypeFelica;
    case NfcProtocolSlix:
        return CardTypeSlix;
    case NfcProtocolSt25tb:
        return CardTypeSt25tb;
    default:
        return CardTypeUnknown;
    }
}

/** Priority-ordered list used for card-type classification. */
static const NfcProtocol CARD_TYPE_PRIORITY[] = {
    NfcProtocolMfDesfire,
    NfcProtocolMfPlus,
    NfcProtocolMfClassic,
    NfcProtocolMfUltralight,
    NfcProtocolIso14443_4a,
    NfcProtocolIso14443_4b,
    NfcProtocolIso14443_3a,
    NfcProtocolIso14443_3b,
    NfcProtocolIso15693_3,
    NfcProtocolFelica,
    NfcProtocolSlix,
    NfcProtocolSt25tb,
};
static const size_t CARD_TYPE_PRIORITY_COUNT =
    sizeof(CARD_TYPE_PRIORITY) / sizeof(CARD_TYPE_PRIORITY[0]);

/** Pick the richest card type from the list the scanner reported. */
static CardType best_card_type(const NfcProtocol* protos, size_t count) {
    for(size_t p = 0; p < CARD_TYPE_PRIORITY_COUNT; p++) {
        for(size_t i = 0; i < count; i++) {
            if(protos[i] == CARD_TYPE_PRIORITY[p]) {
                return protocol_to_card_type(CARD_TYPE_PRIORITY[p]);
            }
        }
    }
    return CardTypeUnknown;
}

/**
 * Determine the transport-layer protocol to use for UID reading.
 *
 * All MIFARE variants (Classic, Ultralight, DESFire, Plus) and ISO14443-4a
 * are built on ISO14443-3a, so we always start an ISO14443-3a poller for them.
 * That gives us the UID from the anti-collision step without needing auth.
 *
 * Uses nfc_protocol_has_parent() from the SDK to handle the hierarchy
 * automatically rather than maintaining a hard-coded list.
 */
static NfcProtocol uid_transport(const NfcProtocol* protos, size_t count) {
    for(size_t i = 0; i < count; i++) {
        if(protos[i] == NfcProtocolIso14443_3a ||
           nfc_protocol_has_parent(protos[i], NfcProtocolIso14443_3a)) {
            return NfcProtocolIso14443_3a;
        }
    }
    for(size_t i = 0; i < count; i++) {
        if(protos[i] == NfcProtocolIso14443_3b ||
           nfc_protocol_has_parent(protos[i], NfcProtocolIso14443_3b)) {
            return NfcProtocolIso14443_3b;
        }
    }
    /* Fallback: use first detected protocol */
    return (count > 0) ? protos[0] : NfcProtocolInvalid;
}

/* -------------------------------------------------------------------------
 * Validation (same rules as before)
 * -------------------------------------------------------------------------
 */

static bool observation_is_valid(const AccessObservation* obs) {
    if(!obs) return false;
    if(obs->tech != TechTypeNfc13Mhz) return false;
    if(obs->card_type == CardTypeUnknown) return false;
    if(!obs->uid_present) return false;
    if(obs->uid_len == 0) return false;
    return true;
}

/* -------------------------------------------------------------------------
 * Scanner callback  (runs on NFC worker thread)
 * -------------------------------------------------------------------------
 */

static void scanner_callback(NfcScannerEvent event, void* context) {
    ObservationProvider* p = context;

    if(event.type != NfcScannerEventTypeDetected) return;
    if(event.data.protocol_num == 0) return;

    furi_mutex_acquire(p->mutex, FuriWaitForever);

    if(p->state == ProviderStateScanning) {
        p->detected_card_type =
            best_card_type(event.data.protocols, event.data.protocol_num);
        p->uid_protocol = uid_transport(event.data.protocols, event.data.protocol_num);
        p->state = ProviderStateReadPending;
    }

    furi_mutex_release(p->mutex);
}

/* -------------------------------------------------------------------------
 * ISO14443-3a poller callback  (runs on NFC worker thread)
 *
 * Iso14443_3aPollerEventTypeReady fires after the card has been activated
 * (anti-collision complete, UID in poller data).  We read the UID here
 * while the card is definitely present, then stop.
 * -------------------------------------------------------------------------
 */

static NfcCommand iso14443_3a_poller_cb(NfcGenericEvent event, void* context) {
    ObservationProvider* p = context;
    Iso14443_3aPollerEvent* iso_event = (Iso14443_3aPollerEvent*)event.event_data;

    furi_mutex_acquire(p->mutex, FuriWaitForever);

    if(iso_event->type == Iso14443_3aPollerEventTypeReady) {
        /* nfc_poller_get_data() on the outer NfcPoller returns Iso14443_3aData* */
        const Iso14443_3aData* data = (const Iso14443_3aData*)nfc_poller_get_data(p->poller);

        if(data) {
            size_t uid_len = 0;
            const uint8_t* uid = iso14443_3a_get_uid(data, &uid_len);

            p->pending = (AccessObservation){0};
            p->pending.tech = TechTypeNfc13Mhz;
            p->pending.card_type = p->detected_card_type;
            p->pending.metadata_complete = true;

            if(uid && uid_len > 0) {
                p->pending.uid_present = true;
                p->pending.uid_len =
                    uid_len <= sizeof(p->pending.uid) ? uid_len : sizeof(p->pending.uid);
                for(size_t i = 0; i < p->pending.uid_len; i++) {
                    p->pending.uid[i] = uid[i];
                }
            }

            p->state = ProviderStateDone;
        } else {
            p->state = ProviderStateReadFailed;
        }
    } else {
        /* Iso14443_3aPollerEventTypeError */
        p->state = ProviderStateReadFailed;
    }

    furi_mutex_release(p->mutex);
    return NfcCommandStop;
}

/* -------------------------------------------------------------------------
 * Internal helpers (main thread only — no races with each other)
 * -------------------------------------------------------------------------
 */

/** Allocate and start a fresh NfcScanner. Updates mutex-protected fields. */
static void provider_start_scanner(ObservationProvider* p) {
    NfcScanner* sc = nfc_scanner_alloc(p->nfc);

    furi_mutex_acquire(p->mutex, FuriWaitForever);
    p->scanner = sc;
    p->state = ProviderStateScanning;
    furi_mutex_release(p->mutex);

    if(sc) {
        nfc_scanner_start(sc, scanner_callback, p);
    }
}

/** Choose the right poller callback for the given protocol. */
static NfcGenericCallback callback_for_protocol(NfcProtocol protocol) {
    switch(protocol) {
    case NfcProtocolIso14443_3a:
        return iso14443_3a_poller_cb;
    default:
        /* Other transport protocols not yet supported; caller will handle NULL */
        return NULL;
    }
}

/* -------------------------------------------------------------------------
 * Public API
 * -------------------------------------------------------------------------
 */

ObservationProvider* observation_provider_alloc(void) {
    ObservationProvider* p = malloc(sizeof(ObservationProvider));
    if(!p) return NULL;

    p->nfc = nfc_alloc();
    p->mutex = furi_mutex_alloc(FuriMutexTypeNormal);
    p->scanner = NULL;
    p->poller = NULL;
    p->state = ProviderStateIdle;
    p->detected_card_type = CardTypeUnknown;
    p->uid_protocol = NfcProtocolInvalid;
    p->pending = (AccessObservation){0};

    if(!p->nfc || !p->mutex) {
        if(p->nfc) nfc_free(p->nfc);
        if(p->mutex) furi_mutex_free(p->mutex);
        free(p);
        return NULL;
    }

    return p;
}

void observation_provider_free(ObservationProvider* provider) {
    if(!provider) return;
    observation_provider_stop(provider);
    nfc_free(provider->nfc);
    furi_mutex_free(provider->mutex);
    free(provider);
}

void observation_provider_start(ObservationProvider* provider) {
    if(!provider) return;

    furi_mutex_acquire(provider->mutex, FuriWaitForever);
    bool idle = (provider->state == ProviderStateIdle);
    furi_mutex_release(provider->mutex);

    if(idle) {
        provider_start_scanner(provider);
    }
}

void observation_provider_stop(ObservationProvider* provider) {
    if(!provider) return;

    /* Atomically take ownership of any live scanner/poller and go idle. */
    furi_mutex_acquire(provider->mutex, FuriWaitForever);
    NfcScanner* sc = provider->scanner;
    NfcPoller* pl = provider->poller;
    provider->scanner = NULL;
    provider->poller = NULL;
    provider->state = ProviderStateIdle;
    furi_mutex_release(provider->mutex);

    /* Stop/free outside the mutex so callbacks can complete without deadlock. */
    if(sc) {
        nfc_scanner_stop(sc);
        nfc_scanner_free(sc);
    }
    if(pl) {
        nfc_poller_stop(pl);
        nfc_poller_free(pl);
    }
}

bool observation_provider_poll(ObservationProvider* provider, AccessObservation* out) {
    if(!provider || !out) return false;

    furi_mutex_acquire(provider->mutex, FuriWaitForever);
    ProviderState state = provider->state;
    furi_mutex_release(provider->mutex);

    /* ── ReadPending: scanner found a card, transition to poller ── */
    if(state == ProviderStateReadPending) {
        /* Atomically take the scanner and protocol info, mark as Reading. */
        furi_mutex_acquire(provider->mutex, FuriWaitForever);
        if(provider->state != ProviderStateReadPending) {
            /* Raced with stop() — nothing to do. */
            furi_mutex_release(provider->mutex);
            return false;
        }
        NfcScanner* sc = provider->scanner;
        provider->scanner = NULL;
        NfcProtocol proto = provider->uid_protocol;
        provider->state = ProviderStateReading;
        furi_mutex_release(provider->mutex);

        /* Stop scanner outside the mutex. */
        if(sc) {
            nfc_scanner_stop(sc);
            nfc_scanner_free(sc);
        }

        NfcGenericCallback cb = callback_for_protocol(proto);
        if(cb) {
            NfcPoller* pl = nfc_poller_alloc(provider->nfc, proto);

            furi_mutex_acquire(provider->mutex, FuriWaitForever);
            provider->poller = pl;
            furi_mutex_release(provider->mutex);

            if(pl) {
                nfc_poller_start(pl, cb, provider);
            } else {
                /* Poller allocation failed — restart scanner. */
                provider_start_scanner(provider);
            }
        } else {
            /* Unsupported transport protocol — restart scanner. */
            provider_start_scanner(provider);
        }
        return false;
    }

    /* ── Done: poller read succeeded ── */
    if(state == ProviderStateDone) {
        furi_mutex_acquire(provider->mutex, FuriWaitForever);
        if(provider->state != ProviderStateDone) {
            furi_mutex_release(provider->mutex);
            return false;
        }
        NfcPoller* pl = provider->poller;
        provider->poller = NULL;
        AccessObservation result = provider->pending;
        provider->state = ProviderStateIdle;
        furi_mutex_release(provider->mutex);

        /* Stop/free poller outside mutex. */
        if(pl) {
            nfc_poller_stop(pl);
            nfc_poller_free(pl);
        }

        if(observation_is_valid(&result)) {
            *out = result;
            return true;
        }

        /* Result was invalid — restart scanning automatically. */
        provider_start_scanner(provider);
        return false;
    }

    /* ── ReadFailed: poller hit an error, restart scanner ── */
    if(state == ProviderStateReadFailed) {
        furi_mutex_acquire(provider->mutex, FuriWaitForever);
        if(provider->state != ProviderStateReadFailed) {
            furi_mutex_release(provider->mutex);
            return false;
        }
        NfcPoller* pl = provider->poller;
        provider->poller = NULL;
        provider->state = ProviderStateScanning;
        furi_mutex_release(provider->mutex);

        if(pl) {
            nfc_poller_stop(pl);
            nfc_poller_free(pl);
        }

        provider_start_scanner(provider);
        return false;
    }

    return false;
}

