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
    /* 125 kHz RFID family */
    CardTypeEm4100Like,
    CardTypeHidProxLike,    /* HID H10301 26-bit */
    CardTypeHidGeneric,     /* HID generic / extended generic */
    CardTypeIndala,         /* Indala 26-bit */
    CardTypeRfid125,        /* other 125 kHz protocols */
    /* MIFARE Classic family */
    CardTypeMifareClassic,      /* generic fallback */
    CardTypeMifareClassic1K,
    CardTypeMifareClassic4K,
    CardTypeMifareClassicMini,
    /* MIFARE Ultralight / NTAG family */
    CardTypeMifareUltralight,   /* generic fallback */
    CardTypeMifareUltralightC,
    CardTypeNtag203,
    CardTypeNtag213,
    CardTypeNtag215,
    CardTypeNtag216,
    CardTypeNtagI2C,
    /* Other NFC families */
    CardTypeMifareDesfire,
    CardTypeMifarePlus,
    CardTypeIso14443A,
    CardTypeIso14443B,
    CardTypeIso15693,
    CardTypeFelica,
    CardTypeSlix,
    CardTypeSt25tb,
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