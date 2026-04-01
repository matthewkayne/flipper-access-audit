#include "rules.h"

bool rule_legacy_family(const AccessObservation* obs) {
    if(!obs) return false;
    return (obs->card_type == CardTypeEm4100Like) ||
           (obs->card_type == CardTypeHidProxLike) ||
           (obs->card_type == CardTypeMifareClassic) ||
           (obs->card_type == CardTypeMifareClassic1K) ||
           (obs->card_type == CardTypeMifareClassic4K) ||
           (obs->card_type == CardTypeMifareClassicMini);
}

bool rule_identifier_only_pattern(const AccessObservation* obs) {
    if(!obs) return false;
    return obs->uid_present && !obs->user_memory_present && obs->repeated_reads_identical;
}

bool rule_uid_no_memory(const AccessObservation* obs) {
    if(!obs) return false;
    /* Only fire when identifier_only_pattern does not already apply */
    if(rule_identifier_only_pattern(obs)) return false;
    return obs->uid_present && !obs->user_memory_present;
}

bool rule_incomplete_evidence(const AccessObservation* obs) {
    if(!obs) return true;
    return !obs->metadata_complete;
}

bool rule_no_uid(const AccessObservation* obs) {
    if(!obs) return true;
    return !obs->uid_present || obs->uid_len == 0;
}

bool rule_modern_crypto(const AccessObservation* obs) {
    if(!obs) return false;
    return (obs->card_type == CardTypeMifareDesfire) ||
           (obs->card_type == CardTypeMifarePlus) ||
           (obs->card_type == CardTypeFelica);
}
