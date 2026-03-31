#include <furi.h>
#include <gui/gui.h>
#include <input/input.h>

#include "access_audit.h"
#include "core/observation.h"
#include "core/scoring.h"
#include "core/session.h"
#include "core/report.h"
#include "core/observation_provider.h"

typedef enum {
    AccessAuditScreenScan,
    AccessAuditScreenResult,
    AccessAuditScreenSaved,
} AccessAuditScreen;

typedef struct {
    ViewPort* view_port;
    FuriMessageQueue* event_queue;
    ObservationProvider* provider;
    ScanSession session;
    AccessObservation obs;
    AuditScore score;
    AccessAuditScreen screen;
    int saved_ticks; /* countdown to auto-exit after save confirmation */
} AccessAuditApp;

typedef enum {
    AccessAuditEventTypeInput,
} AccessAuditEventType;

typedef struct {
    AccessAuditEventType type;
    InputEvent input;
} AccessAuditEvent;

static void access_audit_reset_to_scan(AccessAuditApp* app) {
    app->screen = AccessAuditScreenScan;
    app->obs = (AccessObservation){0};
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

static const char* risk_label(Severity severity) {
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

static void access_audit_draw_callback(Canvas* canvas, void* context) {
    AccessAuditApp* app = context;

    canvas_clear(canvas);

    if(app->screen == AccessAuditScreenScan) {
        canvas_set_font(canvas, FontPrimary);
        canvas_draw_str(canvas, 2, 10, "Access Audit");

        canvas_draw_line(canvas, 0, 13, 127, 13);

        canvas_set_font(canvas, FontSecondary);
        canvas_draw_str(canvas, 2, 26, "Tap NFC card...");
        canvas_draw_str(canvas, 2, 38, "Scanning");
        canvas_draw_str(canvas, 2, 62, "Back: exit");
        return;
    }

    if(app->screen == AccessAuditScreenSaved) {
        char line[48];

        canvas_set_font(canvas, FontPrimary);
        canvas_draw_str(canvas, 2, 10, "Access Audit");

        canvas_draw_line(canvas, 0, 13, 127, 13);

        canvas_draw_str(canvas, 2, 32, "Report saved");

        canvas_set_font(canvas, FontSecondary);
        snprintf(line, sizeof(line), "%u card(s) written to SD", (unsigned)app->session.count);
        canvas_draw_str(canvas, 2, 46, line);
        canvas_draw_str(canvas, 2, 62, "Press any key to exit");
        return;
    }

    /* ── Result screen ── */
    char line[64];

    /* Header */
    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str(canvas, 2, 10, "Access Audit");

    /* Session card count, right-aligned */
    canvas_set_font(canvas, FontSecondary);
    snprintf(line, sizeof(line), "[%u]", (unsigned)app->session.count);
    canvas_draw_str_aligned(canvas, 126, 10, AlignRight, AlignBottom, line);

    canvas_draw_line(canvas, 0, 13, 127, 13);

    /* Card type */
    canvas_set_font(canvas, FontSecondary);
    canvas_draw_str(canvas, 2, 24, card_type_to_string(app->obs.card_type));

    /* Risk label — most prominent element */
    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str(canvas, 2, 36, risk_label(app->score.max_severity));

    /* Score, right-aligned on the same baseline as risk label */
    canvas_set_font(canvas, FontSecondary);
    snprintf(line, sizeof(line), "%u/100", app->score.score);
    canvas_draw_str_aligned(canvas, 126, 36, AlignRight, AlignBottom, line);

    /* UID */
    access_audit_format_uid_line(&app->obs, line, sizeof(line));
    canvas_draw_str(canvas, 2, 48, line);

    /* Help row */
    canvas_draw_str(canvas, 2, 62, "OK:rescan  Back:exit");
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

    app->provider = observation_provider_alloc();
    if(!app->provider) {
        furi_message_queue_free(app->event_queue);
        free(app);
        return -1;
    }

    session_init(&app->session);
    access_audit_reset_to_scan(app);

    app->view_port = view_port_alloc();
    view_port_draw_callback_set(app->view_port, access_audit_draw_callback, app);
    view_port_input_callback_set(app->view_port, access_audit_input_callback, app);

    Gui* gui = furi_record_open(RECORD_GUI);
    gui_add_view_port(gui, app->view_port, GuiLayerFullscreen);

    view_port_update(app->view_port);

    observation_provider_start(app->provider);

    bool running = true;
    AccessAuditEvent event;

    while(running) {
        /* Auto-exit after the save confirmation screen. Each queue timeout
           is ~100 ms so 12 ticks ≈ 1.2 s. */
        if(app->screen == AccessAuditScreenSaved) {
            if(--app->saved_ticks <= 0) {
                running = false;
            }
        }

        if(app->screen == AccessAuditScreenScan) {
            AccessObservation candidate;
            if(observation_provider_poll(app->provider, &candidate)) {
                app->obs = candidate;
                app->score = score_observation(&app->obs);
                session_append(&app->session, &app->obs, &app->score);
                app->screen = AccessAuditScreenResult;
                view_port_update(app->view_port);
            }
        }

        if(furi_message_queue_get(app->event_queue, &event, 100) == FuriStatusOk) {
            if(event.type == AccessAuditEventTypeInput && event.input.type == InputTypeShort) {
                if(app->screen == AccessAuditScreenScan) {
                    if(event.input.key == InputKeyBack) {
                        running = false;
                    }
                } else if(app->screen == AccessAuditScreenResult) {
                    if(event.input.key == InputKeyOk) {
                        access_audit_reset_to_scan(app);
                        observation_provider_start(app->provider);
                        view_port_update(app->view_port);
                    } else if(event.input.key == InputKeyBack) {
                        if(app->session.count > 0) {
                            observation_provider_stop(app->provider);
                            report_save_session(&app->session);
                            app->screen = AccessAuditScreenSaved;
                            app->saved_ticks = 12;
                            view_port_update(app->view_port);
                        } else {
                            running = false;
                        }
                    }
                } else if(app->screen == AccessAuditScreenSaved) {
                    /* Any key press skips the countdown and exits immediately. */
                    running = false;
                }
            }
        }
    }

    observation_provider_free(app->provider);

    view_port_enabled_set(app->view_port, false);
    gui_remove_view_port(gui, app->view_port);
    view_port_free(app->view_port);
    furi_record_close(RECORD_GUI);

    furi_message_queue_free(app->event_queue);
    free(app);

    return 0;
}
