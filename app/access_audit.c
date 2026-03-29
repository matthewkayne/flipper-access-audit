#include <furi.h>
#include <gui/gui.h>
#include <notification/notification_messages.h>

#include "access_audit.h"

int32_t access_audit_app(void* p) {
    UNUSED(p);

    FURI_LOG_I("AccessAudit", "App started");

    // Minimal placeholder app
    // For now we just log and exit cleanly.
    return 0;
}