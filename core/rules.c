#include "rules.h"

bool rule_legacy_family(const AccessObservation* obs) {
    if(!obs) return false;

    return (obs->card_type == CardTypeEm4100Like) ||
           (obs->card_type == CardTypeMifareClassic);
}

bool rule_identifier_only_pattern(const AccessObservation* obs) {
    if(!obs) return false;

    return obs->uid_present &&
           !obs->user_memory_present &&
           obs->repeated_reads_identical;
}

bool rule_incomplete_evidence(const AccessObservation* obs) {
    if(!obs) return true;
    return !obs->metadata_complete;
}