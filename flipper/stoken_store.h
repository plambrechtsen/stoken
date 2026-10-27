#pragma once

#include "stoken_core.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define STOKEN_DIR           "/ext/stoken"
#define STOKEN_SETTINGS_FILE STOKEN_DIR "/settings.conf"
#define STOKEN_MAX_TOKENS    16
#define STOKEN_FILENAME_LEN  64

/* Time zone offsets: UTC-12:00 .. UTC+14:00 in 15 minute steps */
#define STOKEN_TZ_MIN_MINUTES (-12 * 60)
#define STOKEN_TZ_MAX_MINUTES (14 * 60)
#define STOKEN_TZ_STEP        15
#define STOKEN_TZ_COUNT       ((STOKEN_TZ_MAX_MINUTES - STOKEN_TZ_MIN_MINUTES) / STOKEN_TZ_STEP + 1)

typedef struct {
    char nickname[STOKEN_NICKNAME_LEN];
    char filename[STOKEN_FILENAME_LEN];
    int load_err; /* STOKEN_OK when token is usable */
    SecuridToken token;
} StokenEntry;

typedef struct {
    /* offset of the Flipper's (local) clock from UTC, in minutes */
    int16_t tz_offset_min;
    bool keyboard_enabled;
    bool send_enter;
    char static_pin[SECURID_MAX_PIN + 1];
    char last_token[STOKEN_FILENAME_LEN];
} StokenSettings;

/* Scan STOKEN_DIR for token files. Returns number of entries filled. */
size_t stoken_store_load_tokens(StokenEntry* entries, size_t max_entries);

void stoken_settings_defaults(StokenSettings* s);
void stoken_settings_load(StokenSettings* s);
bool stoken_settings_save(const StokenSettings* s);

/* "UTC+13:00" style label */
void stoken_tz_format(int16_t offset_min, char* out, size_t out_len);
