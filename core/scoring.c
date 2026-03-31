#include "scoring.h"
#include "rules.h"

static uint8_t severity_points(Severity severity) {
    switch(severity) {
    case SeverityInfo:
        return 5;
    case SeverityLow:
        return 10;
    case SeverityMedium:
        return 20;
    case SeverityHigh:
        return 35;
    default:
        return 0;
    }
}

AuditScore score_observation(const AccessObservation* obs) {
    AuditScore result = {
        .score = 0,
        .confidence = 90,
        .max_severity = SeverityInfo,
    };

    if(!obs) {
        result.score = 0;
        result.confidence = 0;
        return result;
    }

    if(rule_legacy_family(obs)) {
        result.score += severity_points(SeverityHigh);
        result.max_severity = SeverityHigh;
    }

    if(rule_identifier_only_pattern(obs)) {
        result.score += severity_points(SeverityHigh);
        result.max_severity = SeverityHigh;
    }

    if(rule_incomplete_evidence(obs)) {
        result.score += severity_points(SeverityLow);
        if(result.confidence >= 20) result.confidence -= 20;
        if(result.max_severity < SeverityLow) result.max_severity = SeverityLow;
    }

    if(result.score > 100) result.score = 100;
    return result;
}

const char* severity_to_string(Severity severity) {
    switch(severity) {
    case SeverityInfo:
        return "Info";
    case SeverityLow:
        return "Low";
    case SeverityMedium:
        return "Medium";
    case SeverityHigh:
        return "High";
    default:
        return "Unknown";
    }
}

const char* card_type_to_string(CardType type) {
    switch(type) {
    case CardTypeEm4100Like:
        return "EM4100-like";
    case CardTypeHidProxLike:
        return "HID Prox-like";
    case CardTypeMifareClassic:
        return "MIFARE Classic";
    case CardTypeMifareUltralight:
        return "MIFARE Ultralight";
    case CardTypeNtagLike:
        return "NTAG-like";
    case CardTypeMifareDesfire:
        return "MIFARE DESFire";
    case CardTypeMifarePlus:
        return "MIFARE Plus";
    case CardTypeIso14443A:
        return "ISO14443-A";
    case CardTypeIso14443B:
        return "ISO14443-B";
    case CardTypeIso15693:
        return "ISO15693";
    case CardTypeFelica:
        return "FeliCa";
    case CardTypeSlix:
        return "SLIX";
    case CardTypeSt25tb:
        return "ST25TB";
    default:
        return "Unknown";
    }
}