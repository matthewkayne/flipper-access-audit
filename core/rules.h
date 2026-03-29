#pragma once

#include <stdbool.h>
#include "observation.h"
#include "scoring.h"

typedef struct {
    const char* id;
    Severity severity;
    const char* title;
    const char* explanation;
    bool (*matches)(const AccessObservation* obs);
} AuditRule;

bool rule_legacy_family(const AccessObservation* obs);
bool rule_identifier_only_pattern(const AccessObservation* obs);
bool rule_incomplete_evidence(const AccessObservation* obs);