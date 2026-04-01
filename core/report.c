#include "report.h"
#include "rules.h"
#include "scoring.h"
#include <storage/storage.h>
#include <furi_hal_rtc.h>
#include <datetime/datetime.h>
#include <stdlib.h>
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

/* ── Report listing / loading ──────────────────────────────────────────── */

size_t report_list(char names[REPORT_LIST_MAX][REPORT_NAME_LEN]) {
    Storage* storage = furi_record_open(RECORD_STORAGE);
    File* dir = storage_file_alloc(storage);
    size_t count = 0;

    if(storage_dir_open(dir, REPORT_DIR)) {
        char fname[64];
        while(count < REPORT_LIST_MAX &&
              storage_dir_read(dir, NULL, fname, sizeof(fname))) {
            /* Expect "report_YYYYMMDD_HHMMSS.txt" — 26 chars */
            size_t len = strlen(fname);
            if(len >= 26 && strncmp(fname, "report_", 7) == 0) {
                strncpy(names[count], fname + 7, 15);
                names[count][15] = '\0';
                count++;
            }
        }
        storage_dir_close(dir);
    }

    storage_file_free(dir);
    furi_record_close(RECORD_STORAGE);

    /* Sort newest first (YYYYMMDD_HHMMSS sorts lexicographically = chronologically). */
    for(size_t i = 0; i < count; i++) {
        for(size_t j = i + 1; j < count; j++) {
            if(strcmp(names[i], names[j]) < 0) {
                char tmp[REPORT_NAME_LEN];
                memcpy(tmp, names[i], REPORT_NAME_LEN);
                memcpy(names[i], names[j], REPORT_NAME_LEN);
                memcpy(names[j], tmp, REPORT_NAME_LEN);
            }
        }
    }

    return count;
}

bool report_load(const char* name, ReportContent* out) {
    if(!name || !out) return false;

    char path[72];
    snprintf(path, sizeof(path), REPORT_DIR "/report_%s.txt", name);

    Storage* storage = furi_record_open(RECORD_STORAGE);
    File* file = storage_file_alloc(storage);
    bool ok = false;

    if(storage_file_open(file, path, FSAM_READ, FSOM_OPEN_EXISTING)) {
        uint64_t file_size = storage_file_size(file);
        /* Cap at 8 KB — no legitimate report will exceed this. */
        if(file_size > 0 && file_size <= 8192) {
            char* buf = malloc(file_size + 1);
            if(buf) {
                size_t read = storage_file_read(file, buf, (size_t)file_size);
                buf[read] = '\0';

                /* Count lines to size the pointer array. */
                size_t line_count = 0;
                for(size_t i = 0; i < read; i++) {
                    if(buf[i] == '\n') line_count++;
                }
                /* Account for a final line without trailing newline. */
                if(read > 0 && buf[read - 1] != '\n') line_count++;

                char** lines = malloc(line_count * sizeof(char*));
                if(lines) {
                    size_t idx = 0;
                    lines[idx++] = buf;
                    for(size_t i = 0; i < read; i++) {
                        if(buf[i] == '\n') {
                            buf[i] = '\0';
                            if(idx < line_count && i + 1 < read) {
                                lines[idx++] = buf + i + 1;
                            }
                        }
                    }
                    out->buf = buf;
                    out->lines = lines;
                    out->count = idx;
                    ok = true;
                } else {
                    free(buf);
                }
            }
        }
        storage_file_close(file);
    }

    storage_file_free(file);
    furi_record_close(RECORD_STORAGE);
    return ok;
}

void report_content_free(ReportContent* content) {
    if(!content) return;
    free(content->lines);
    free(content->buf);
    content->lines = NULL;
    content->buf = NULL;
    content->count = 0;
}
