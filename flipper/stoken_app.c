/*
 * stoken_app.c - RSA SecurID software token for the Flipper Zero
 *
 * Screens:
 *   Code      landing page: current/next tokencode, countdown, UTC clock.
 *             Left/Right switch token, OK types static PIN + code over USB
 *             (when the keyboard is enabled), Back opens the menu.
 *   Menu      list of token nicknames + Settings. Back exits.
 *   Settings  time zone, keyboard on/off, static PIN, Enter after code.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include "stoken_core.h"
#include "stoken_hid.h"
#include "stoken_store.h"

#include <furi.h>
#include <furi_hal.h>
#include <gui/gui.h>
#include <gui/modules/submenu.h>
#include <gui/modules/text_input.h>
#include <gui/modules/variable_item_list.h>
#include <gui/view_dispatcher.h>
#include <notification/notification_messages.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TAG "stoken"

#define TICK_MS          250
#define STATUS_MS        2000
#define EXP_WARN_DAYS    14
#define MENU_SETTINGS_ID 1000
#define MENU_EMPTY_ID    1001

typedef enum {
    StokenViewCode,
    StokenViewMenu,
    StokenViewSettings,
    StokenViewPinInput,
} StokenViewId;

typedef enum {
    StokenEventTick = 1,
    StokenEventType,
    StokenEventPrev,
    StokenEventNext,
    StokenEventPinEntered,
} StokenEvent;

typedef enum {
    SettingsItemTimeZone,
    SettingsItemKeyboard,
    SettingsItemPin,
    SettingsItemClearPin,
    SettingsItemEnter,
} SettingsItem;

typedef struct {
    char nickname[STOKEN_NICKNAME_LEN];
    char code[SECURID_MAX_DIGITS + 1];
    char next_code[SECURID_MAX_DIGITS + 1];
    char error[40];
    char status[32];
    char clock[24];
    uint8_t secs_left;
    uint8_t interval;
    uint8_t index;
    uint8_t count;
    int exp_days;
    bool has_token;
    bool keyboard;
    bool usb_connected;
    bool has_pin;
} CodeModel;

typedef struct {
    Gui* gui;
    ViewDispatcher* view_dispatcher;
    NotificationApp* notifications;
    View* code_view;
    Submenu* menu;
    VariableItemList* settings_list;
    TextInput* pin_input;
    VariableItem* pin_item;
    FuriTimer* timer;

    StokenEntry* tokens;
    size_t token_count;
    size_t current;

    StokenSettings settings;
    bool settings_dirty;
    char pin_buf[SECURID_MAX_PIN + 1];

    StokenViewId view;
    char status[32];
    uint32_t status_until;
} StokenApp;

/********************************************************************
 * Helpers
 ********************************************************************/

static int64_t stoken_now_utc(const StokenApp* app) {
    /* The Flipper RTC holds local wall-clock time; convert to UTC */
    return (int64_t)furi_hal_rtc_get_timestamp() - (int64_t)app->settings.tz_offset_min * 60;
}

static void stoken_set_status(StokenApp* app, const char* msg) {
    snprintf(app->status, sizeof(app->status), "%s", msg);
    app->status_until = furi_get_tick() + furi_ms_to_ticks(STATUS_MS);
}

static void stoken_switch_view(StokenApp* app, StokenViewId view) {
    app->view = view;
    view_dispatcher_switch_to_view(app->view_dispatcher, view);
}

static void stoken_apply_keyboard(StokenApp* app) {
    if(app->settings.keyboard_enabled) {
        if(!stoken_hid_start()) stoken_set_status(app, "USB mode change failed");
    } else {
        stoken_hid_stop();
    }
}

static void stoken_select_token(StokenApp* app, size_t index) {
    if(!app->token_count) return;
    app->current = index % app->token_count;
    snprintf(
        app->settings.last_token,
        sizeof(app->settings.last_token),
        "%s",
        app->tokens[app->current].filename);
    app->settings_dirty = true;
}

/********************************************************************
 * Code view
 ********************************************************************/

static void stoken_update_code_model(StokenApp* app) {
    int64_t utc = stoken_now_utc(app);
    StokenUtcTime t;
    stoken_utc_breakdown(utc, &t);

    with_view_model(
        app->code_view,
        CodeModel * m,
        {
            memset(m, 0, sizeof(*m));
            m->count = (uint8_t)app->token_count;
            m->index = (uint8_t)app->current;
            m->keyboard = app->settings.keyboard_enabled;
            m->usb_connected = stoken_hid_connected();
            m->has_pin = app->settings.static_pin[0] != 0;
            snprintf(m->clock, sizeof(m->clock), "UTC %02d:%02d:%02d", t.hour, t.minute, t.second);

            if(furi_get_tick() < app->status_until)
                snprintf(m->status, sizeof(m->status), "%s", app->status);

            if(app->token_count) {
                const StokenEntry* e = &app->tokens[app->current];
                snprintf(m->nickname, sizeof(m->nickname), "%s", e->nickname);
                if(e->load_err == STOKEN_OK) {
                    int interval = securid_token_interval(&e->token);
                    m->has_token = true;
                    m->interval = (uint8_t)interval;
                    m->secs_left = (uint8_t)(interval - (t.second % interval));
                    securid_compute_tokencode(&e->token, utc, m->code);
                    securid_compute_tokencode(&e->token, utc + interval, m->next_code);
                    m->exp_days = securid_check_exp(&e->token, utc);
                } else {
                    snprintf(m->error, sizeof(m->error), "%s", stoken_errstr(e->load_err));
                }
            } else {
                snprintf(m->nickname, sizeof(m->nickname), "No tokens");
                snprintf(m->error, sizeof(m->error), "Add files to %s", STOKEN_DIR);
            }
        },
        true);
}

static void stoken_code_draw(Canvas* canvas, void* model) {
    CodeModel* m = model;
    char buf[32];

    canvas_clear(canvas);
    canvas_set_color(canvas, ColorBlack);

    /* header: nickname + position */
    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str(canvas, 0, 9, m->nickname);
    if(m->count > 1) {
        snprintf(buf, sizeof(buf), "%u/%u", m->index + 1, m->count);
        canvas_set_font(canvas, FontSecondary);
        canvas_draw_str_aligned(canvas, 128, 1, AlignRight, AlignTop, buf);
    }
    canvas_draw_line(canvas, 0, 11, 127, 11);

    if(m->has_token) {
        canvas_set_font(canvas, FontBigNumbers);
        canvas_draw_str_aligned(canvas, 64, 26, AlignCenter, AlignCenter, m->code);

        canvas_set_font(canvas, FontSecondary);
        snprintf(buf, sizeof(buf), "Next %s", m->next_code);
        canvas_draw_str(canvas, 0, 46, buf);
        if(m->exp_days < 0) {
            canvas_draw_str_aligned(canvas, 128, 46, AlignRight, AlignBottom, "EXPIRED");
        } else if(m->exp_days < EXP_WARN_DAYS) {
            snprintf(buf, sizeof(buf), "Exp %dd", m->exp_days);
            canvas_draw_str_aligned(canvas, 128, 46, AlignRight, AlignBottom, buf);
        } else {
            snprintf(buf, sizeof(buf), "%us", m->secs_left);
            canvas_draw_str_aligned(canvas, 128, 46, AlignRight, AlignBottom, buf);
        }

        /* countdown bar */
        canvas_draw_frame(canvas, 0, 48, 128, 5);
        if(m->interval) {
            int w = (126 * m->secs_left) / m->interval;
            canvas_draw_box(canvas, 1, 49, w, 3);
        }
    } else {
        canvas_set_font(canvas, FontSecondary);
        canvas_draw_str_aligned(canvas, 64, 24, AlignCenter, AlignCenter, m->error);
        canvas_draw_str_aligned(canvas, 64, 36, AlignCenter, AlignCenter, "Back: menu / settings");
    }

    /* footer */
    canvas_set_font(canvas, FontSecondary);
    if(m->status[0]) {
        canvas_draw_str_aligned(canvas, 64, 63, AlignCenter, AlignBottom, m->status);
    } else {
        canvas_draw_str(canvas, 0, 63, m->clock);
        if(m->keyboard && m->has_token) {
            const char* hint = !m->usb_connected ? "USB?" : (m->has_pin ? "OK:PIN+code" : "OK:type");
            canvas_draw_str_aligned(canvas, 128, 63, AlignRight, AlignBottom, hint);
        }
    }
}

static bool stoken_code_input(InputEvent* event, void* context) {
    StokenApp* app = context;

    if(event->type != InputTypeShort && event->type != InputTypeRepeat) return false;

    switch(event->key) {
    case InputKeyOk:
        if(event->type != InputTypeShort) return true;
        view_dispatcher_send_custom_event(app->view_dispatcher, StokenEventType);
        return true;
    case InputKeyLeft:
    case InputKeyUp:
        view_dispatcher_send_custom_event(app->view_dispatcher, StokenEventPrev);
        return true;
    case InputKeyRight:
    case InputKeyDown:
        view_dispatcher_send_custom_event(app->view_dispatcher, StokenEventNext);
        return true;
    default:
        return false; /* Back falls through to navigation */
    }
}

static void stoken_type_code(StokenApp* app) {
    char out[SECURID_MAX_PIN + SECURID_MAX_DIGITS + 1];
    char code[SECURID_MAX_DIGITS + 1];

    if(!app->token_count || app->tokens[app->current].load_err != STOKEN_OK) return;
    if(!app->settings.keyboard_enabled) {
        stoken_set_status(app, "Keyboard off (Settings)");
        return;
    }

    securid_compute_tokencode(&app->tokens[app->current].token, stoken_now_utc(app), code);
    snprintf(out, sizeof(out), "%s%s", app->settings.static_pin, code);

    if(stoken_hid_type_digits(out, app->settings.send_enter) == StokenHidTypeOk) {
        notification_message(app->notifications, &sequence_blink_green_10);
        stoken_set_status(app, "Typed!");
    } else {
        notification_message(app->notifications, &sequence_blink_red_10);
        stoken_set_status(app, "USB not connected");
    }
    stc_memzero(out, sizeof(out));
    stc_memzero(code, sizeof(code));
}

/********************************************************************
 * Menu
 ********************************************************************/

static void stoken_menu_callback(void* context, uint32_t index) {
    StokenApp* app = context;
    if(index == MENU_SETTINGS_ID) {
        stoken_switch_view(app, StokenViewSettings);
    } else if(index < app->token_count) {
        stoken_select_token(app, index);
        stoken_update_code_model(app);
        stoken_switch_view(app, StokenViewCode);
    }
}

static void stoken_menu_build(StokenApp* app) {
    submenu_reset(app->menu);
    submenu_set_header(app->menu, "RSA SecurID tokens");
    for(size_t i = 0; i < app->token_count; i++) {
        submenu_add_item(app->menu, app->tokens[i].nickname, i, stoken_menu_callback, app);
    }
    if(!app->token_count) {
        submenu_add_item(app->menu, "(none in /ext/stoken)", MENU_EMPTY_ID, stoken_menu_callback, app);
    }
    submenu_add_item(app->menu, "Settings", MENU_SETTINGS_ID, stoken_menu_callback, app);
}

/********************************************************************
 * Settings
 ********************************************************************/

static int16_t tz_from_index(uint8_t index) {
    return (int16_t)(STOKEN_TZ_MIN_MINUTES + index * STOKEN_TZ_STEP);
}

static uint8_t tz_to_index(int16_t offset) {
    return (uint8_t)((offset - STOKEN_TZ_MIN_MINUTES) / STOKEN_TZ_STEP);
}

static void stoken_settings_tz_changed(VariableItem* item) {
    StokenApp* app = variable_item_get_context(item);
    char buf[16];
    app->settings.tz_offset_min = tz_from_index(variable_item_get_current_value_index(item));
    stoken_tz_format(app->settings.tz_offset_min, buf, sizeof(buf));
    variable_item_set_current_value_text(item, buf);
    app->settings_dirty = true;
}

static void stoken_settings_kb_changed(VariableItem* item) {
    StokenApp* app = variable_item_get_context(item);
    app->settings.keyboard_enabled = variable_item_get_current_value_index(item) == 1;
    variable_item_set_current_value_text(item, app->settings.keyboard_enabled ? "On" : "Off");
    stoken_apply_keyboard(app);
    app->settings_dirty = true;
}

static void stoken_settings_enter_changed(VariableItem* item) {
    StokenApp* app = variable_item_get_context(item);
    app->settings.send_enter = variable_item_get_current_value_index(item) == 1;
    variable_item_set_current_value_text(item, app->settings.send_enter ? "Yes" : "No");
    app->settings_dirty = true;
}

static void stoken_settings_update_pin_text(StokenApp* app) {
    char buf[SECURID_MAX_PIN + 1];
    size_t n = strlen(app->settings.static_pin);
    if(!n) {
        variable_item_set_current_value_text(app->pin_item, "None");
        return;
    }
    memset(buf, '*', n);
    buf[n] = 0;
    variable_item_set_current_value_text(app->pin_item, buf);
}

static bool stoken_pin_validator(const char* text, FuriString* error, void* context) {
    UNUSED(context);
    size_t n = strlen(text);
    if(n < SECURID_MIN_PIN || n > SECURID_MAX_PIN) {
        furi_string_set(error, "PIN must be\n4-8 digits");
        return false;
    }
    for(size_t i = 0; i < n; i++) {
        if(text[i] < '0' || text[i] > '9') {
            furi_string_set(error, "Digits only");
            return false;
        }
    }
    return true;
}

static void stoken_pin_input_done(void* context) {
    StokenApp* app = context;
    view_dispatcher_send_custom_event(app->view_dispatcher, StokenEventPinEntered);
}

static void stoken_settings_enter(void* context, uint32_t index) {
    StokenApp* app = context;
    if(index == SettingsItemPin) {
        memset(app->pin_buf, 0, sizeof(app->pin_buf));
        text_input_reset(app->pin_input);
        text_input_set_header_text(app->pin_input, "Static PIN (4-8 digits)");
        text_input_set_validator(app->pin_input, stoken_pin_validator, app);
        text_input_set_minimum_length(app->pin_input, SECURID_MIN_PIN);
        text_input_set_result_callback(
            app->pin_input, stoken_pin_input_done, app, app->pin_buf, sizeof(app->pin_buf), true);
        stoken_switch_view(app, StokenViewPinInput);
    } else if(index == SettingsItemClearPin) {
        stc_memzero(app->settings.static_pin, sizeof(app->settings.static_pin));
        stoken_settings_update_pin_text(app);
        app->settings_dirty = true;
        notification_message(app->notifications, &sequence_blink_blue_10);
    }
}

static void stoken_settings_build(StokenApp* app) {
    VariableItemList* list = app->settings_list;
    VariableItem* item;
    char buf[16];

    variable_item_list_reset(list);

    item = variable_item_list_add(
        list, "Time zone", STOKEN_TZ_COUNT, stoken_settings_tz_changed, app);
    variable_item_set_current_value_index(item, tz_to_index(app->settings.tz_offset_min));
    stoken_tz_format(app->settings.tz_offset_min, buf, sizeof(buf));
    variable_item_set_current_value_text(item, buf);

    item = variable_item_list_add(list, "USB keyboard", 2, stoken_settings_kb_changed, app);
    variable_item_set_current_value_index(item, app->settings.keyboard_enabled ? 1 : 0);
    variable_item_set_current_value_text(item, app->settings.keyboard_enabled ? "On" : "Off");

    app->pin_item = variable_item_list_add(list, "Static PIN", 1, NULL, app);
    stoken_settings_update_pin_text(app);

    variable_item_list_add(list, "Clear static PIN", 1, NULL, app);

    item = variable_item_list_add(list, "Press Enter", 2, stoken_settings_enter_changed, app);
    variable_item_set_current_value_index(item, app->settings.send_enter ? 1 : 0);
    variable_item_set_current_value_text(item, app->settings.send_enter ? "Yes" : "No");

    variable_item_list_set_enter_callback(list, stoken_settings_enter, app);
}

/********************************************************************
 * Dispatcher plumbing
 ********************************************************************/

static bool stoken_custom_event(void* context, uint32_t event) {
    StokenApp* app = context;

    switch(event) {
    case StokenEventTick:
        if(app->view == StokenViewCode) stoken_update_code_model(app);
        return true;
    case StokenEventType:
        stoken_type_code(app);
        stoken_update_code_model(app);
        return true;
    case StokenEventPrev:
        if(app->token_count > 1)
            stoken_select_token(app, app->current + app->token_count - 1);
        stoken_update_code_model(app);
        return true;
    case StokenEventNext:
        if(app->token_count > 1) stoken_select_token(app, app->current + 1);
        stoken_update_code_model(app);
        return true;
    case StokenEventPinEntered:
        snprintf(app->settings.static_pin, sizeof(app->settings.static_pin), "%s", app->pin_buf);
        stc_memzero(app->pin_buf, sizeof(app->pin_buf));
        stoken_settings_update_pin_text(app);
        app->settings_dirty = true;
        stoken_switch_view(app, StokenViewSettings);
        return true;
    default:
        return false;
    }
}

static bool stoken_navigation_event(void* context) {
    StokenApp* app = context;

    switch(app->view) {
    case StokenViewCode:
        submenu_set_selected_item(app->menu, (uint32_t)app->current);
        stoken_switch_view(app, StokenViewMenu);
        break;
    case StokenViewSettings:
        if(app->settings_dirty) {
            stoken_settings_save(&app->settings);
            app->settings_dirty = false;
        }
        stoken_switch_view(app, StokenViewMenu);
        break;
    case StokenViewPinInput:
        stc_memzero(app->pin_buf, sizeof(app->pin_buf));
        stoken_switch_view(app, StokenViewSettings);
        break;
    case StokenViewMenu:
    default:
        view_dispatcher_stop(app->view_dispatcher);
        break;
    }
    return true;
}

static void stoken_timer_callback(void* context) {
    StokenApp* app = context;
    view_dispatcher_send_custom_event(app->view_dispatcher, StokenEventTick);
}

static StokenApp* stoken_app_alloc(void) {
    StokenApp* app = malloc(sizeof(StokenApp));
    memset(app, 0, sizeof(*app));

    stoken_settings_load(&app->settings);

    app->tokens = malloc(sizeof(StokenEntry) * STOKEN_MAX_TOKENS);
    app->token_count = stoken_store_load_tokens(app->tokens, STOKEN_MAX_TOKENS);
    for(size_t i = 0; i < app->token_count; i++) {
        if(strcmp(app->tokens[i].filename, app->settings.last_token) == 0) app->current = i;
        if(app->tokens[i].load_err != STOKEN_OK) {
            FURI_LOG_W(
                TAG,
                "%s: %s",
                app->tokens[i].filename,
                stoken_errstr(app->tokens[i].load_err));
        }
    }

    app->gui = furi_record_open(RECORD_GUI);
    app->notifications = furi_record_open(RECORD_NOTIFICATION);

    app->view_dispatcher = view_dispatcher_alloc();
    view_dispatcher_set_event_callback_context(app->view_dispatcher, app);
    view_dispatcher_set_custom_event_callback(app->view_dispatcher, stoken_custom_event);
    view_dispatcher_set_navigation_event_callback(app->view_dispatcher, stoken_navigation_event);
    view_dispatcher_attach_to_gui(app->view_dispatcher, app->gui, ViewDispatcherTypeFullscreen);

    app->code_view = view_alloc();
    view_allocate_model(app->code_view, ViewModelTypeLocking, sizeof(CodeModel));
    view_set_context(app->code_view, app);
    view_set_draw_callback(app->code_view, stoken_code_draw);
    view_set_input_callback(app->code_view, stoken_code_input);
    view_dispatcher_add_view(app->view_dispatcher, StokenViewCode, app->code_view);

    app->menu = submenu_alloc();
    stoken_menu_build(app);
    view_dispatcher_add_view(app->view_dispatcher, StokenViewMenu, submenu_get_view(app->menu));

    app->settings_list = variable_item_list_alloc();
    stoken_settings_build(app);
    view_dispatcher_add_view(
        app->view_dispatcher, StokenViewSettings, variable_item_list_get_view(app->settings_list));

    app->pin_input = text_input_alloc();
    view_dispatcher_add_view(
        app->view_dispatcher, StokenViewPinInput, text_input_get_view(app->pin_input));

    app->timer = furi_timer_alloc(stoken_timer_callback, FuriTimerTypePeriodic, app);

    return app;
}

static void stoken_app_free(StokenApp* app) {
    furi_timer_stop(app->timer);
    furi_timer_free(app->timer);

    view_dispatcher_remove_view(app->view_dispatcher, StokenViewCode);
    view_dispatcher_remove_view(app->view_dispatcher, StokenViewMenu);
    view_dispatcher_remove_view(app->view_dispatcher, StokenViewSettings);
    view_dispatcher_remove_view(app->view_dispatcher, StokenViewPinInput);
    view_free(app->code_view);
    submenu_free(app->menu);
    variable_item_list_free(app->settings_list);
    text_input_free(app->pin_input);
    view_dispatcher_free(app->view_dispatcher);

    furi_record_close(RECORD_NOTIFICATION);
    furi_record_close(RECORD_GUI);

    /* wipe seeds and the static PIN from RAM */
    stc_memzero(app->tokens, sizeof(StokenEntry) * STOKEN_MAX_TOKENS);
    free(app->tokens);
    stc_memzero(app, sizeof(*app));
    free(app);
}

int32_t stoken_app(void* p) {
    UNUSED(p);
    StokenApp* app = stoken_app_alloc();

    stoken_apply_keyboard(app);
    stoken_update_code_model(app);

    /* The tokencode is the landing page; with no tokens, start at the menu */
    stoken_switch_view(app, app->token_count ? StokenViewCode : StokenViewMenu);
    furi_timer_start(app->timer, furi_ms_to_ticks(TICK_MS));

    view_dispatcher_run(app->view_dispatcher);

    furi_timer_stop(app->timer);
    if(app->settings_dirty) stoken_settings_save(&app->settings);
    stoken_hid_stop();
    stoken_app_free(app);
    return 0;
}
