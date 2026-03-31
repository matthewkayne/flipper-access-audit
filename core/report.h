#pragma once

#include <stdbool.h>
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
