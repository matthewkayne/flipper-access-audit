#include "observation_provider.h"
#include "sample_data.h"

#include <nfc/nfc.h>
#include <nfc/nfc_poller.h>
#include <nfc/nfc_device.h>

static CardType protocol_to_card_type(NfcProtocol protocol) {
    switch(protocol) {
    case NfcProtocolMfClassic:
        return CardTypeMifareClassic;
    case NfcProtocolMfUltralight:
        return CardTypeMifareUltralight;
    case NfcProtocolMfDesfire:
        return CardTypeMifareDesfire;
    case NfcProtocolMfPlus:
        return CardTypeMifarePlus;
    case NfcProtocolIso14443_3a:
    case NfcProtocolIso14443_4a:
        return CardTypeIso14443A;
    case NfcProtocolIso14443_3b:
    case NfcProtocolIso14443_4b:
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

static void observation_fill_uid_from_device(AccessObservation* out, NfcDevice* device) {
    size_t uid_len = 0;
    const uint8_t* uid = nfc_device_get_uid(device, &uid_len);

    out->uid_present = false;
    out->uid_len = 0;

    if(!uid || uid_len == 0) {
        return;
    }

    size_t copy_len = uid_len;
    if(copy_len > sizeof(out->uid)) {
        copy_len = sizeof(out->uid);
    }

    for(size_t i = 0; i < copy_len; i++) {
        out->uid[i] = uid[i];
    }

    out->uid_present = true;
    out->uid_len = copy_len;
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
        const NfcProtocol protocol = protocols_to_try[i];

        NfcPoller* poller = nfc_poller_alloc(nfc, protocol);
        if(!poller) {
            continue;
        }

        if(nfc_poller_detect(poller)) {
            out->tech = TechTypeNfc13Mhz;
            out->card_type = protocol_to_card_type(protocol);
            out->user_memory_present = false;
            out->repeated_reads_identical = false;
            out->metadata_complete = true;

            const NfcDeviceData* protocol_data = nfc_poller_get_data(poller);
            if(protocol_data) {
                NfcDevice* device = nfc_device_alloc();
                if(device) {
                    nfc_device_set_data(device, protocol, protocol_data);
                    observation_fill_uid_from_device(out, device);
                    nfc_device_free(device);
                }
            }

            found = true;
            nfc_poller_free(poller);
            break;
        }

        nfc_poller_free(poller);
    }

    nfc_free(nfc);
    return found;
}