#include "sample_data.h"

AccessObservation sample_observation_mifare_classic(void) {
    return (AccessObservation){
        .tech = TechTypeNfc13Mhz,
        .card_type = CardTypeMifareClassic,
        .uid_present = true,
        .user_memory_present = false,
        .repeated_reads_identical = true,
        .metadata_complete = true,
        .uid_len = 4,
        .uid = {0xDE, 0xAD, 0xBE, 0xEF},
    };
}

AccessObservation sample_observation_em4100(void) {
    return (AccessObservation){
        .tech = TechTypeRfid125,
        .card_type = CardTypeEm4100Like,
        .uid_present = true,
        .user_memory_present = false,
        .repeated_reads_identical = true,
        .metadata_complete = true,
        .uid_len = 5,
        .uid = {0x11, 0x22, 0x33, 0x44, 0x55},
    };
}

AccessObservation sample_observation_unknown(void) {
    return (AccessObservation){
        .tech = TechTypeUnknown,
        .card_type = CardTypeUnknown,
        .uid_present = false,
        .user_memory_present = false,
        .repeated_reads_identical = false,
        .metadata_complete = false,
        .uid_len = 0,
    };
}