#pragma once

#include <stdint.h>

typedef enum {
    SeverityInfo = 0,
    SeverityLow,
    SeverityMedium,
    SeverityHigh,
} Severity;

typedef struct {
    uint8_t score;
    uint8_t confidence;
    Severity max_severity;
} AuditScore;