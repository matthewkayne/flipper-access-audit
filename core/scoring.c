#include "scoring.h"
#include "observation.h"
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
        .confidence = 80,
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