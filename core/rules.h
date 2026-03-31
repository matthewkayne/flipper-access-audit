#pragma once

#include <stdbool.h>
#include "observation.h"

bool rule_legacy_family(const AccessObservation* obs);
bool rule_identifier_only_pattern(const AccessObservation* obs);
bool rule_incomplete_evidence(const AccessObservation* obs);