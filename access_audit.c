#include <furi.h>
#include <gui/gui.h>
#include <input/input.h>

#include "access_audit.h"
#include "core/observation.h"
#include "core/scoring.h"
#include "core/sample_data.h"
#include "core/observation_provider.h"

typedef enum {
    AccessAuditScreenScan,
    AccessAuditScreenResult,
} AccessAuditScreen;

typedef struct {
    ViewPort* view_port;
    FuriMessageQueue* event_queue;
    AccessObservation obs;
    AuditScore score;
    bool used_demo_data;
    AccessAuditScreen screen;
} AccessAuditApp;

typedef enum {
    AccessAuditEventTypeInput,
} AccessAuditEventType;

typedef struct {
    AccessAuditEventType type;
    InputEvent input;
} AccessAuditEvent;

static void access_audit_reset_to_scan(AccessAuditApp* app) {
    app->used_demo_data = false;
    app->screen = AccessAuditScreenScan;
    app->obs = sample_observation_unknown();
    app->score = score_observation(&app->obs);
}

static void access_audit_format_uid_line(
    const AccessObservation* obs,
    char* out,
    size_t out_size) {
    if(!obs->uid_present || obs->uid_len == 0) {
        snprintf(out, out_size, "UID: unavailable");
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

    if(app->screen == AccessAuditScreenScan) {
        canvas_set_font(canvas, FontPrimary);
        canvas_draw_str(canvas, 2, 12, "Access Audit");

        canvas_set_font(canvas, FontSecondary);
        canvas_draw_str(canvas, 2, 30, "Tap NFC card...");
        canvas_draw_str(canvas, 2, 44, "Back: Demo mode");
        return;
    }

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

    canvas_draw_str(canvas, 2, 64, "OK: Rescan  Back: Exit");
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

    access_audit_reset_to_scan(app);

    app->view_port = view_port_alloc();
    view_port_draw_callback_set(app->view_port, access_audit_draw_callback, app);
    view_port_input_callback_set(app->view_port, access_audit_input_callback, app);

    Gui* gui = furi_record_open(RECORD_GUI);
    gui_add_view_port(gui, app->view_port, GuiLayerFullscreen);

    view_port_update(app->view_port);

    bool running = true;
    AccessAuditEvent event;

    while(running) {
        if(app->screen == AccessAuditScreenScan) {
            if(observation_provider_get_from_nfc(&app->obs)) {
                app->used_demo_data = false;
                app->score = score_observation(&app->obs);
                app->screen = AccessAuditScreenResult;
                view_port_update(app->view_port);
            }
        }

        if(furi_message_queue_get(app->event_queue, &event, 100) == FuriStatusOk) {
            if(event.type == AccessAuditEventTypeInput) {
                if(event.input.type == InputTypeShort) {
                    if(app->screen == AccessAuditScreenScan) {
                        if(event.input.key == InputKeyBack) {
                            app->used_demo_data = true;
                            if(observation_provider_get_demo(&app->obs)) {
                                app->score = score_observation(&app->obs);
                                app->screen = AccessAuditScreenResult;
                                view_port_update(app->view_port);
                            } else {
                                running = false;
                            }
                        }
                    } else if(app->screen == AccessAuditScreenResult) {
                        if(event.input.key == InputKeyOk) {
                            access_audit_reset_to_scan(app);
                            view_port_update(app->view_port);
                        } else if(event.input.key == InputKeyBack) {
                            running = false;
                        }
                    }
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