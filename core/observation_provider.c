#include "observation_provider.h"
#include "sample_data.h"

#include <nfc/nfc.h>
#include <nfc/nfc_poller.h>

static CardType protocol_to_card_type(NfcProtocol protocol) {
    switch(protocol) {
    case NfcProtocolMfClassic:
        return CardTypeMifareClassic;
    case NfcProtocolMfUltralight:
        return CardTypeMifareUltralight;
    case NfcProtocolIso14443_3a:
    case NfcProtocolIso14443_4a:
        return CardTypeNtagLike;
    default:
        return CardTypeUnknown;
    }
}

bool observation_provider_get_demo(AccessObservation* out) {
    if(!out) return false;

    *out = sample_observation_mifare_classic();
    return true;
}

bool observation_provider_get_from_nfc(AccessObservation* out) {
    if(!out) return false;

    *out = sample_observation_unknown();

    Nfc* nfc = nfc_alloc();
    if(!nfc) {
        return false;
    }

    const NfcProtocol protocols_to_try[] = {
        NfcProtocolMfClassic,
        NfcProtocolMfUltralight,
        NfcProtocolMfDesfire,
        NfcProtocolMfPlus,
        NfcProtocolIso14443_4a,
        NfcProtocolIso14443_3a,
        NfcProtocolIso14443_3b,
        NfcProtocolIso15693_3,
        NfcProtocolFelica,
        NfcProtocolSlix,
        NfcProtocolSt25tb,
    };

    const size_t protocol_count = sizeof(protocols_to_try) / sizeof(protocols_to_try[0]);

    bool found = false;

    for(size_t i = 0; i < protocol_count; i++) {
        NfcProtocol protocol = protocols_to_try[i];

        NfcPoller* poller = nfc_poller_alloc(nfc, protocol);
        if(!poller) {
            continue;
        }

        if(nfc_poller_detect(poller)) {
            out->tech = TechTypeNfc13Mhz;
            out->card_type = protocol_to_card_type(protocol);
            out->uid_present = false;
            out->uid_len = 0;
            out->user_memory_present = false;
            out->repeated_reads_identical = false;
            out->metadata_complete = true;

            found = true;
            nfc_poller_free(poller);
            break;
        }

        nfc_poller_free(poller);
    }

    nfc_free(nfc);
    return found;
}