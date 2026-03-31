#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef enum {
    TechTypeUnknown = 0,
    TechTypeRfid125,
    TechTypeNfc13Mhz,
} TechType;

typedef enum {
    CardTypeUnknown = 0,
    CardTypeEm4100Like,
    CardTypeHidProxLike,
    CardTypeMifareClassic,
    CardTypeMifareUltralight,
    CardTypeNtagLike,
} CardType;

typedef struct {
    TechType tech;
    CardType card_type;
    bool uid_present;
    bool user_memory_present;
    bool repeated_reads_identical;
    bool metadata_complete;
    size_t uid_len;
    uint8_t uid[10];
} AccessObservation;