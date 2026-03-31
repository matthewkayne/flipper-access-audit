#pragma once

#include <stddef.h>
#include "observation.h"
#include "scoring.h"

#define SESSION_MAX_ENTRIES 20

typedef struct {
    AccessObservation obs;
    AuditScore score;
} SessionEntry;

typedef struct {
    SessionEntry entries[SESSION_MAX_ENTRIES];
    size_t count;
} ScanSession;

void session_init(ScanSession* session);

/**
 * Append a completed scan to the session.
 * Returns false (and does nothing) if the session is full.
 */
bool session_append(ScanSession* session, const AccessObservation* obs, const AuditScore* score);
