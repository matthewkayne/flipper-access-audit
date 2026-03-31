#include <furi.h>
#include <gui/gui.h>
#include <input/input.h>

#include "access_audit.h"
#include "core/observation.h"
#include "core/scoring.h"
#include "core/observation_provider.h"

typedef struct {
    ViewPort* view_port;
    FuriMessageQueue* event_queue;
    AccessObservation obs;
    AuditScore score;
    bool used_demo_data;
} AccessAuditApp;

typedef enum {
    AccessAuditEventTypeInput,
} AccessAuditEventType;

typedef struct {
    AccessAuditEventType type;
    InputEvent input;
} AccessAuditEvent;

static void access_audit_format_uid_line(
    const AccessObservation* obs,
    char* out,
    size_t out_size) {
    if(!obs->uid_present || obs->uid_len == 0) {
        snprintf(out, out_size, "UID: none");
        return;
    }

    if(obs->uid_len <= 4) {
        snprintf(
            out,
            out_size,
            "UID: %02X %02X %02X %02X",
            obs->uid[0],
            obs->uid_len > 1 ? obs->uid[1] : 0,
            obs->uid_len > 2 ? obs->uid[2] : 0,
            obs->uid_len > 3 ? obs->uid[3] : 0);
    } else {
        snprintf(
            out,
            out_size,
            "UID: %02X %02X %02X %02X...",
            obs->uid[0],
            obs->uid[1],
            obs->uid[2],
            obs->uid[3]);
    }
}

static void access_audit_draw_callback(Canvas* canvas, void* context) {
    AccessAuditApp* app = context;

    canvas_clear(canvas);

    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str(canvas, 2, 10, "Access Audit");

    canvas_set_font(canvas, FontSecondary);

    char line[64];

    snprintf(line, sizeof(line), "Type: %s", card_type_to_string(app->obs.card_type));
    canvas_draw_str(canvas, 2, 20, line);

    snprintf(
        line,
        sizeof(line),
        "S:%u C:%u%% R:%s",
        app->score.score,
        app->score.confidence,
        severity_to_string(app->score.max_severity));
    canvas_draw_str(canvas, 2, 30, line);

    access_audit_format_uid_line(&app->obs, line, sizeof(line));
    canvas_draw_str(canvas, 2, 42, line);

    snprintf(line, sizeof(line), "Src: %s", app->used_demo_data ? "Demo" : "NFC");
    canvas_draw_str(canvas, 2, 54, line);

    canvas_draw_str(canvas, 2, 64, "Back: Exit");
}

static void access_audit_input_callback(InputEvent* input_event, void* context) {
    AccessAuditApp* app = context;

    AccessAuditEvent event = {
        .type = AccessAuditEventTypeInput,
        .input = *input_event,
    };

    furi_message_queue_put(app->event_queue, &event, FuriWaitForever);
}

int32_t access_audit_app(void* p) {
    UNUSED(p);

    AccessAuditApp* app = malloc(sizeof(AccessAuditApp));
    if(!app) return -1;

    app->event_queue = furi_message_queue_alloc(8, sizeof(AccessAuditEvent));
    if(!app->event_queue) {
        free(app);
        return -1;
    }

    app->used_demo_data = false;

    if(!observation_provider_get_from_nfc(&app->obs)) {
        app->used_demo_data = true;

        if(!observation_provider_get_demo(&app->obs)) {
            furi_message_queue_free(app->event_queue);
            free(app);
            return -1;
        }
    }

    app->score = score_observation(&app->obs);

    app->view_port = view_port_alloc();
    view_port_draw_callback_set(app->view_port, access_audit_draw_callback, app);
    view_port_input_callback_set(app->view_port, access_audit_input_callback, app);

    Gui* gui = furi_record_open(RECORD_GUI);
    gui_add_view_port(gui, app->view_port, GuiLayerFullscreen);

    view_port_update(app->view_port);

    bool running = true;
    AccessAuditEvent event;

    while(running) {
        if(furi_message_queue_get(app->event_queue, &event, FuriWaitForever) == FuriStatusOk) {
            if(event.type == AccessAuditEventTypeInput) {
                if(event.input.type == InputTypeShort && event.input.key == InputKeyBack) {
                    running = false;
                }
            }
        }
    }

    view_port_enabled_set(app->view_port, false);
    gui_remove_view_port(gui, app->view_port);
    view_port_free(app->view_port);
    furi_record_close(RECORD_GUI);

    furi_message_queue_free(app->event_queue);
    free(app);

    return 0;
}