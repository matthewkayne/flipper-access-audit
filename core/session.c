#include "session.h"
#include <string.h>

void session_init(ScanSession* session) {
    memset(session, 0, sizeof(*session));
}

bool session_append(
    ScanSession* session,
    const AccessObservation* obs,
    const AuditScore* score) {
    if(!session || !obs || !score) return false;
    if(session->count >= SESSION_MAX_ENTRIES) return false;

    session->entries[session->count].obs = *obs;
    session->entries[session->count].score = *score;
    session->count++;
    return true;
}
