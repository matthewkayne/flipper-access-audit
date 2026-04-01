#include <furi.h>
#include <gui/gui.h>
#include <input/input.h>

#include "access_audit.h"
#include "core/observation.h"
#include "core/scoring.h"
#include "core/session.h"
#include "core/report.h"
#include "core/observation_provider.h"
#include "core/rfid_provider.h"

typedef enum {
    AccessAuditScreenScan,
    AccessAuditScreenResult,
    AccessAuditScreenSaved,
    AccessAuditScreenReportList,
    AccessAuditScreenReportViewer,
} AccessAuditScreen;

typedef struct {
    ViewPort* view_port;
    FuriMessageQueue* event_queue;
    ObservationProvider* nfc_provider;
    RfidProvider* rfid_provider;
    ScanSession session;
    AccessObservation obs;
    AuditScore score;
    AccessAuditScreen screen;
    int saved_ticks; /* countdown to auto-exit after save confirmation */
    /* Report list */
    char rlist_names[REPORT_LIST_MAX][REPORT_NAME_LEN];
    size_t rlist_count;
    size_t rlist_top;    /* index of first visible row */
    size_t rlist_cursor; /* index of selected row */
    /* Report viewer */
    ReportContent rviewer;
    size_t rviewer_scroll; /* index of first visible line */
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

static void access_audit_start_scanning(AccessAuditApp* app) {
    observation_provider_start(app->nfc_provider);
    rfid_provider_start(app->rfid_provider);
}

static void access_audit_stop_scanning(AccessAuditApp* app) {
    observation_provider_stop(app->nfc_provider);
    rfid_provider_stop(app->rfid_provider);
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
        canvas_draw_str(canvas, 2, 26, "Tap or hold card...");
        canvas_draw_str(canvas, 2, 38, "Scanning NFC + RFID");
        canvas_draw_str(canvas, 2, 62, "Up:reports  Back:exit");
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

    if(app->screen == AccessAuditScreenReportList) {
        char line[32];

        canvas_set_font(canvas, FontPrimary);
        canvas_draw_str(canvas, 2, 10, "Reports");

        canvas_set_font(canvas, FontSecondary);
        snprintf(line, sizeof(line), "[%u]", (unsigned)app->rlist_count);
        canvas_draw_str_aligned(canvas, 126, 10, AlignRight, AlignBottom, line);

        canvas_draw_line(canvas, 0, 13, 127, 13);

        if(app->rlist_count == 0) {
            canvas_draw_str(canvas, 2, 36, "No reports saved yet");
        } else {
            /* Show up to 3 rows starting at rlist_top */
            for(size_t i = 0; i < 3; i++) {
                size_t idx = app->rlist_top + i;
                if(idx >= app->rlist_count) break;
                int y = 24 + (int)i * 13;
                if(idx == app->rlist_cursor) {
                    canvas_draw_box(canvas, 0, y - 9, 128, 11);
                    canvas_set_color(canvas, ColorWhite);
                }
                canvas_draw_str(canvas, 2, y, app->rlist_names[idx]);
                canvas_set_color(canvas, ColorBlack);
            }
        }

        canvas_set_font(canvas, FontSecondary);
        canvas_draw_str(canvas, 2, 62, "OK:open  Back:exit");
        return;
    }

    if(app->screen == AccessAuditScreenReportViewer) {
        canvas_set_font(canvas, FontSecondary);

        /* Header */
        canvas_draw_str(canvas, 2, 10, app->rlist_names[app->rlist_cursor]);
        canvas_draw_line(canvas, 0, 13, 127, 13);

        /* 4 content lines */
        for(size_t i = 0; i < 4; i++) {
            size_t idx = app->rviewer_scroll + i;
            if(idx >= app->rviewer.count) break;
            canvas_draw_str(canvas, 2, 22 + (int)i * 11, app->rviewer.lines[idx]);
        }

        canvas_draw_str(canvas, 2, 62, "Up/Dn:scroll  Back:list");
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

    app->nfc_provider = observation_provider_alloc();
    if(!app->nfc_provider) {
        furi_message_queue_free(app->event_queue);
        free(app);
        return -1;
    }

    app->rfid_provider = rfid_provider_alloc();
    if(!app->rfid_provider) {
        observation_provider_free(app->nfc_provider);
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

    access_audit_start_scanning(app);

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
            bool got = observation_provider_poll(app->nfc_provider, &candidate);
            if(!got) got = rfid_provider_poll(app->rfid_provider, &candidate);
            if(got) {
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
                    } else if(event.input.key == InputKeyUp) {
                        access_audit_stop_scanning(app);
                        app->rlist_count = report_list(app->rlist_names);
                        app->rlist_top = 0;
                        app->rlist_cursor = 0;
                        app->screen = AccessAuditScreenReportList;
                        view_port_update(app->view_port);
                    }
                } else if(app->screen == AccessAuditScreenReportList) {
                    if(event.input.key == InputKeyBack) {
                        app->screen = AccessAuditScreenScan;
                        access_audit_start_scanning(app);
                        view_port_update(app->view_port);
                    } else if(event.input.key == InputKeyUp) {
                        if(app->rlist_cursor > 0) {
                            app->rlist_cursor--;
                            if(app->rlist_cursor < app->rlist_top) {
                                app->rlist_top = app->rlist_cursor;
                            }
                            view_port_update(app->view_port);
                        }
                    } else if(event.input.key == InputKeyDown) {
                        if(app->rlist_count > 0 &&
                           app->rlist_cursor < app->rlist_count - 1) {
                            app->rlist_cursor++;
                            if(app->rlist_cursor >= app->rlist_top + 3) {
                                app->rlist_top = app->rlist_cursor - 2;
                            }
                            view_port_update(app->view_port);
                        }
                    } else if(event.input.key == InputKeyOk) {
                        if(app->rlist_count > 0) {
                            report_content_free(&app->rviewer);
                            if(report_load(
                                   app->rlist_names[app->rlist_cursor], &app->rviewer)) {
                                app->rviewer_scroll = 0;
                                app->screen = AccessAuditScreenReportViewer;
                                view_port_update(app->view_port);
                            }
                        }
                    }
                } else if(app->screen == AccessAuditScreenReportViewer) {
                    if(event.input.key == InputKeyBack) {
                        report_content_free(&app->rviewer);
                        app->screen = AccessAuditScreenReportList;
                        view_port_update(app->view_port);
                    } else if(event.input.key == InputKeyUp) {
                        if(app->rviewer_scroll > 0) {
                            app->rviewer_scroll--;
                            view_port_update(app->view_port);
                        }
                    } else if(event.input.key == InputKeyDown) {
                        if(app->rviewer.count > 4 &&
                           app->rviewer_scroll + 4 < app->rviewer.count) {
                            app->rviewer_scroll++;
                            view_port_update(app->view_port);
                        }
                    }
                } else if(app->screen == AccessAuditScreenResult) {
                    if(event.input.key == InputKeyOk) {
                        access_audit_reset_to_scan(app);
                        access_audit_start_scanning(app);
                        view_port_update(app->view_port);
                    } else if(event.input.key == InputKeyBack) {
                        if(app->session.count > 0) {
                            access_audit_stop_scanning(app);
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

    report_content_free(&app->rviewer);
    rfid_provider_free(app->rfid_provider);
    observation_provider_free(app->nfc_provider);

    view_port_enabled_set(app->view_port, false);
    gui_remove_view_port(gui, app->view_port);
    view_port_free(app->view_port);
    furi_record_close(RECORD_GUI);

    furi_message_queue_free(app->event_queue);
    free(app);

    return 0;
}
