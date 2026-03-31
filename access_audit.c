#include <furi.h>
#include <gui/gui.h>
#include <input/input.h>

#include "access_audit.h"
#include "core/observation.h"
#include "core/scoring.h"

typedef struct {
    ViewPort* view_port;
    FuriMessageQueue* event_queue;
    AccessObservation obs;
    AuditScore score;
} AccessAuditApp;

typedef enum {
    AccessAuditEventTypeInput,
} AccessAuditEventType;

typedef struct {
    AccessAuditEventType type;
    InputEvent input;
} AccessAuditEvent;

static void access_audit_draw_callback(Canvas* canvas, void* context) {
    AccessAuditApp* app = context;

    canvas_clear(canvas);

    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str(canvas, 2, 10, "Access Audit");

    canvas_set_font(canvas, FontSecondary);

    char line[64];

    snprintf(line, sizeof(line), "Type: %s", card_type_to_string(app->obs.card_type));
    canvas_draw_str(canvas, 2, 24, line);

    snprintf(line, sizeof(line), "Score: %u", app->score.score);
    canvas_draw_str(canvas, 2, 36, line);

    snprintf(line, sizeof(line), "Conf: %u%%", app->score.confidence);
    canvas_draw_str(canvas, 2, 48, line);

    snprintf(line, sizeof(line), "Risk: %s", severity_to_string(app->score.max_severity));
    canvas_draw_str(canvas, 2, 60, line);
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

    app->obs = (AccessObservation){
        .tech = TechTypeNfc13Mhz,
        .card_type = CardTypeMifareClassic,
        .uid_present = true,
        .user_memory_present = false,
        .repeated_reads_identical = true,
        .metadata_complete = true,
        .uid_len = 4,
        .uid = {0xDE, 0xAD, 0xBE, 0xEF},
    };

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