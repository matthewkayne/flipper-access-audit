#include "report.h"
#include "rules.h"
#include "scoring.h"
#include <storage/storage.h>
#include <furi_hal_rtc.h>
#include <datetime/datetime.h>
#include <string.h>

#define REPORT_DIR "/ext/apps_data/access_audit"

/* Write a plain C string to the file. */
static void fw(File* f, const char* s) {
    storage_file_write(f, s, strlen(s));
}

static const char* report_risk_label(Severity severity) {
    switch(severity) {
    case SeverityHigh:
        return "HIGH RISK";
    case SeverityMedium:
        return "MODERATE";
    case SeverityLow:
        return "LOW RISK";
    default:
        return "SECURE";
    }
}

static void write_card_entry(
    File* f,
    size_t index,
    size_t total,
    const SessionEntry* entry) {
    char buf[64];

    snprintf(buf, sizeof(buf), "Card %u/%u\n", (unsigned)(index + 1), (unsigned)total);
    fw(f, buf);

    snprintf(buf, sizeof(buf), "  Type:   %s\n", card_type_to_string(entry->obs.card_type));
    fw(f, buf);

    /* UID */
    if(entry->obs.uid_present && entry->obs.uid_len > 0) {
        fw(f, "  UID:    ");
        for(size_t i = 0; i < entry->obs.uid_len; i++) {
            if(i > 0) fw(f, " ");
            snprintf(buf, sizeof(buf), "%02X", entry->obs.uid[i]);
            fw(f, buf);
        }
        fw(f, "\n");
    } else {
        fw(f, "  UID:    unavailable\n");
    }

    snprintf(
        buf, sizeof(buf), "  Risk:   %s\n", report_risk_label(entry->score.max_severity));
    fw(f, buf);

    snprintf(buf, sizeof(buf), "  Score:  %u/100\n", entry->score.score);
    fw(f, buf);

    /* Rules triggered */
    struct {
        const char* name;
        bool hit;
    } checks[] = {
        {"legacy_family", rule_legacy_family(&entry->obs)},
        {"identifier_only", rule_identifier_only_pattern(&entry->obs)},
        {"uid_no_memory", rule_uid_no_memory(&entry->obs)},
        {"modern_crypto", rule_modern_crypto(&entry->obs)},
        {"incomplete_evidence", rule_incomplete_evidence(&entry->obs)},
        {"no_uid", rule_no_uid(&entry->obs)},
    };

    fw(f, "  Rules:  ");
    bool any = false;
    for(size_t i = 0; i < sizeof(checks) / sizeof(checks[0]); i++) {
        if(checks[i].hit) {
            if(any) fw(f, ", ");
            fw(f, checks[i].name);
            any = true;
        }
    }
    if(!any) fw(f, "none");
    fw(f, "\n\n");
}

bool report_save_session(const ScanSession* session) {
    if(!session || session->count == 0) return false;

    DateTime dt;
    furi_hal_rtc_get_datetime(&dt);

    Storage* storage = furi_record_open(RECORD_STORAGE);
    /* Create directory if it doesn't exist — ignore error if already present. */
    storage_common_mkdir(storage, REPORT_DIR);

    char path[72];
    snprintf(
        path,
        sizeof(path),
        REPORT_DIR "/report_%04u%02u%02u_%02u%02u%02u.txt",
        dt.year,
        dt.month,
        dt.day,
        dt.hour,
        dt.minute,
        dt.second);

    File* file = storage_file_alloc(storage);
    bool ok = storage_file_open(file, path, FSAM_WRITE, FSOM_CREATE_ALWAYS);

    if(ok) {
        char buf[64];

        fw(file, "Access Audit Report\n");
        snprintf(
            buf,
            sizeof(buf),
            "%04u-%02u-%02u %02u:%02u:%02u\n",
            dt.year,
            dt.month,
            dt.day,
            dt.hour,
            dt.minute,
            dt.second);
        fw(file, buf);
        snprintf(buf, sizeof(buf), "Cards scanned: %u\n", (unsigned)session->count);
        fw(file, buf);
        fw(file, "----------------------------------------\n\n");

        for(size_t i = 0; i < session->count; i++) {
            write_card_entry(file, i, session->count, &session->entries[i]);
        }

        storage_file_close(file);
    }

    storage_file_free(file);
    furi_record_close(RECORD_STORAGE);
    return ok;
}
