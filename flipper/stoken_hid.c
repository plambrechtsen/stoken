/*
 * stoken_hid.c - USB style keyboard used to type PIN + tokencode
 */

#include "stoken_hid.h"

#include <furi.h>
#include <furi_hal.h>
#include <furi_hal_usb_hid.h>

#define KEY_PRESS_MS   12
#define KEY_RELEASE_MS 12

static FuriHalUsbInterface* usb_prev = NULL;
static bool hid_active = false;

bool stoken_hid_start(void) {
    if(hid_active) return true;
    usb_prev = furi_hal_usb_get_config();
    furi_hal_usb_unlock();
    if(!furi_hal_usb_set_config(&usb_hid, NULL)) {
        usb_prev = NULL;
        return false;
    }
    hid_active = true;
    return true;
}

void stoken_hid_stop(void) {
    if(!hid_active) return;
    furi_hal_hid_kb_release_all();
    furi_hal_usb_set_config(usb_prev, NULL);
    usb_prev = NULL;
    hid_active = false;
}

bool stoken_hid_active(void) {
    return hid_active;
}

bool stoken_hid_connected(void) {
    return hid_active && furi_hal_hid_is_connected();
}

static void tap(uint16_t key) {
    furi_hal_hid_kb_press(key);
    furi_delay_ms(KEY_PRESS_MS);
    furi_hal_hid_kb_release(key);
    furi_delay_ms(KEY_RELEASE_MS);
}

StokenHidTypeResult stoken_hid_type_digits(const char* digits, bool press_enter) {
    if(!stoken_hid_connected()) return StokenHidTypeNotConnected;

    for(const char* p = digits; *p; p++) {
        if(*p == '0')
            tap(HID_KEYBOARD_0);
        else if(*p >= '1' && *p <= '9')
            tap(HID_KEYBOARD_1 + (*p - '1'));
    }
    if(press_enter) tap(HID_KEYBOARD_RETURN);
    return StokenHidTypeOk;
}
