#pragma once

#include <stdbool.h>
#include "observation.h"

bool observation_provider_get_demo(AccessObservation* out);
bool observation_provider_get_from_nfc(AccessObservation* out);