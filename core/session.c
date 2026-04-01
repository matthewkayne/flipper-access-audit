#include "session.h"
#include <string.h>
#include <stdint.h>

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

SessionSummary session_summarise(const ScanSession* session) {
    SessionSummary s = {0};
    s.most_common_type = CardTypeUnknown;

    if(!session || session->count == 0) return s;

    /* Count card types to find the most common. */
    uint8_t type_counts[32] = {0}; /* covers all CardType values */

    for(size_t i = 0; i < session->count; i++) {
        const SessionEntry* e = &session->entries[i];
        switch(e->score.max_severity) {
        case SeverityHigh:   s.high++;   break;
        case SeverityMedium: s.medium++; break;
        case SeverityLow:    s.low++;    break;
        default:             s.secure++; break;
        }
        size_t t = (size_t)e->obs.card_type;
        if(t < sizeof(type_counts)) type_counts[t]++;
    }

    uint8_t best = 0;
    for(size_t t = 1; t < sizeof(type_counts); t++) {
        if(type_counts[t] > best) {
            best = type_counts[t];
            s.most_common_type = (CardType)t;
        }
    }

    return s;
}
