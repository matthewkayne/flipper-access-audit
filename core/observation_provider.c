#include "observation_provider.h"
#include "sample_data.h"

bool observation_provider_get_demo(AccessObservation* out) {
    if(!out) return false;

    *out = sample_observation_mifare_classic();
    return true;
}

bool observation_provider_get_from_nfc(AccessObservation* out) {
    if(!out) return false;

    *out = sample_observation_unknown();
    return false;
}