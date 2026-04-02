#pragma once

#include <stdbool.h>
#include <stddef.h>
#include "session.h"

/**
 * Save the session as a plain-text report to the SD card.
 *
 * Path: /ext/apps_data/access_audit/report_YYYYMMDD_HHMMSS.txt
 *
 * Returns true on success, false if the session is empty or any
 * storage error occurs.
 */
bool report_save_session(const ScanSession* session);

/* ── Report listing / loading ── */

#define REPORT_LIST_MAX  100
#define REPORT_NAME_LEN  28  /* "YYYYMMDD_HHMMSS\0" (16) + safety */

/**
 * Fill names[] with up to REPORT_LIST_MAX report basenames, newest first.
 * Each entry is the date-time portion only: "YYYYMMDD_HHMMSS".
 * Returns the number of reports found.
 */
size_t report_list(char names[REPORT_LIST_MAX][REPORT_NAME_LEN]);

/**
 * Loaded report content — heap-allocated, free with report_content_free().
 */
typedef struct {
    char*   buf;    /* file bytes with '\n' replaced by '\0' */
    char**  lines;  /* pointers into buf, one per line        */
    size_t  count;  /* number of lines                        */
} ReportContent;

/**
 * Load a report by its basename ("YYYYMMDD_HHMMSS") into out.
 * Returns true on success.
 */
bool report_load(const char* name, ReportContent* out);

/** Free all heap memory owned by a ReportContent. */
void report_content_free(ReportContent* content);

/**
 * Delete a report file by its basename ("YYYYMMDD_HHMMSS").
 * Returns true if the file was removed successfully.
 */
bool report_delete(const char* name);
