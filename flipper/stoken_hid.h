#pragma once

#include <stdbool.h>

typedef enum {
    StokenHidTypeOk,
    StokenHidTypeNotConnected,
} StokenHidTypeResult;

/* Switch the Flipper's USB port into keyboard mode (remembers the old mode) */
bool stoken_hid_start(void);
/* Restore the previous USB mode */
void stoken_hid_stop(void);
bool stoken_hid_active(void);
bool stoken_hid_connected(void);

/* Type a string of digits (and optionally Enter) on the emulated keyboard */
StokenHidTypeResult stoken_hid_type_digits(const char* digits, bool press_enter);
