/*
 * stoken_store.c - read token files and app settings from the SD card
 *
 * Token files live in /ext/stoken and use the upstream ~/.stokenrc format,
 * plus an optional "nickname" (and "password"/"devid" for protected tokens):
 *
 *   version 1
 *   nickname Work VPN
 *   token 2584917508172107...
 *   pin 1234
 */

#include "stoken_store.h"
#include <furi.h>
#include <storage/storage.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define RC_MAX_FILE_SIZE 4096

static bool has_suffix(const char* s, const char* suffix) {
    size_t ls = strlen(s), lx = strlen(suffix);
    return ls >= lx && strcmp(s + ls - lx, suffix) == 0;
}

static bool is_token_filename(const char* name) {
    return strcmp(name, ".stokenrc") == 0 || has_suffix(name, ".stokenrc") ||
           has_suffix(name, ".rc");
}

/* Read a whole (small) file into a newly allocated NUL terminated buffer */
static char* read_small_file(Storage* storage, const char* path, size_t* out_len) {
    File* file = storage_file_alloc(storage);
    char* buf = NULL;
    *out_len = 0;

    if(storage_file_open(file, path, FSAM_READ, FSOM_OPEN_EXISTING)) {
        uint64_t size = storage_file_size(file);
        if(size > 0 && size <= RC_MAX_FILE_SIZE) {
            buf = malloc((size_t)size + 1);
            size_t got = storage_file_read(file, buf, (size_t)size);
            buf[got] = 0;
            *out_len = got;
        }
    }
    storage_file_close(file);
    storage_file_free(file);
    return buf;
}

static void nickname_from_filename(const char* filename, char* out, size_t out_len) {
    const char* dot = strrchr(filename, '.');
    size_t n = (dot && dot != filename) ? (size_t)(dot - filename) : strlen(filename);
    if(n >= out_len) n = out_len - 1;
    memcpy(out, filename, n);
    out[n] = 0;
    if(!out[0]) snprintf(out, out_len, "%s", "Token");
}

static void load_entry(Storage* storage, const char* filename, StokenEntry* e) {
    char path[sizeof(STOKEN_DIR) + STOKEN_FILENAME_LEN + 1];
    size_t len;
    char* text;
    StokenRc* rc;

    memset(e, 0, sizeof(*e));
    snprintf(e->filename, sizeof(e->filename), "%s", filename);
    nickname_from_filename(filename, e->nickname, sizeof(e->nickname));

    snprintf(path, sizeof(path), "%s/%s", STOKEN_DIR, filename);
    text = read_small_file(storage, path, &len);
    if(!text) {
        e->load_err = STOKEN_ERR_FILE_READ;
        return;
    }

    rc = malloc(sizeof(StokenRc));
    e->load_err = stoken_rc_parse(text, len, rc);
    if(rc->nickname[0]) snprintf(e->nickname, sizeof(e->nickname), "%s", rc->nickname);
    if(e->load_err == STOKEN_OK) e->load_err = stoken_rc_load(rc, &e->token);

    /* the rc text and struct hold the seed/password: wipe before freeing */
    stc_memzero(text, len);
    stc_memzero(rc, sizeof(*rc));
    free(text);
    free(rc);
}

static int entry_cmp(const StokenEntry* a, const StokenEntry* b) {
    return strcasecmp(a->nickname, b->nickname);
}

size_t stoken_store_load_tokens(StokenEntry* entries, size_t max_entries) {
    Storage* storage = furi_record_open(RECORD_STORAGE);
    File* dir = storage_file_alloc(storage);
    FileInfo info;
    char name[STOKEN_FILENAME_LEN];
    size_t count = 0;

    storage_simply_mkdir(storage, STOKEN_DIR);

    if(storage_dir_open(dir, STOKEN_DIR)) {
        while(count < max_entries && storage_dir_read(dir, &info, name, sizeof(name))) {
            if(file_info_is_dir(&info) || !is_token_filename(name)) continue;
            load_entry(storage, name, &entries[count]);
            count++;
        }
    }
    storage_dir_close(dir);
    storage_file_free(dir);
    furi_record_close(RECORD_STORAGE);

    /* simple insertion sort by nickname, done in place to avoid a large temp */
    for(size_t i = 1; i < count; i++) {
        for(size_t j = i; j > 0 && entry_cmp(&entries[j - 1], &entries[j]) > 0; j--) {
            StokenEntry* a = &entries[j - 1];
            StokenEntry* b = &entries[j];
            /* swap byte-by-byte through a small buffer */
            uint8_t tmp[64];
            uint8_t* pa = (uint8_t*)a;
            uint8_t* pb = (uint8_t*)b;
            for(size_t off = 0; off < sizeof(StokenEntry); off += sizeof(tmp)) {
                size_t n = sizeof(StokenEntry) - off;
                if(n > sizeof(tmp)) n = sizeof(tmp);
                memcpy(tmp, pa + off, n);
                memcpy(pa + off, pb + off, n);
                memcpy(pb + off, tmp, n);
            }
            stc_memzero(tmp, sizeof(tmp));
        }
    }
    return count;
}

/********************************************************************
 * Settings
 ********************************************************************/

void stoken_settings_defaults(StokenSettings* s) {
    memset(s, 0, sizeof(*s));
    s->tz_offset_min = 0;
    s->keyboard_enabled = false;
    s->send_enter = true;
}

static bool pin_ok(const char* pin) {
    size_t n = strlen(pin);
    if(n < SECURID_MIN_PIN || n > SECURID_MAX_PIN) return false;
    for(size_t i = 0; i < n; i++)
        if(pin[i] < '0' || pin[i] > '9') return false;
    return true;
}

static void settings_apply_line(StokenSettings* s, char* line) {
    char* val;
    while(*line == ' ' || *line == '\t')
        line++;
    if(!*line || *line == '#') return;

    val = line;
    while(*val && *val != ' ' && *val != '\t')
        val++;
    if(*val) *val++ = 0;
    while(*val == ' ' || *val == '\t')
        val++;
    /* trim trailing whitespace */
    for(char* end = val + strlen(val); end > val && (end[-1] == ' ' || end[-1] == '\t');)
        *--end = 0;

    if(strcmp(line, "tz_offset") == 0) {
        int v = atoi(val);
        if(v >= STOKEN_TZ_MIN_MINUTES && v <= STOKEN_TZ_MAX_MINUTES && v % STOKEN_TZ_STEP == 0)
            s->tz_offset_min = (int16_t)v;
    } else if(strcmp(line, "keyboard") == 0) {
        s->keyboard_enabled = atoi(val) != 0;
    } else if(strcmp(line, "send_enter") == 0) {
        s->send_enter = atoi(val) != 0;
    } else if(strcmp(line, "static_pin") == 0) {
        if(pin_ok(val)) snprintf(s->static_pin, sizeof(s->static_pin), "%s", val);
    } else if(strcmp(line, "last_token") == 0) {
        snprintf(s->last_token, sizeof(s->last_token), "%s", val);
    }
}

void stoken_settings_load(StokenSettings* s) {
    Storage* storage = furi_record_open(RECORD_STORAGE);
    size_t len;
    char* text;

    stoken_settings_defaults(s);
    text = read_small_file(storage, STOKEN_SETTINGS_FILE, &len);
    furi_record_close(RECORD_STORAGE);
    if(!text) return;

    char* p = text;
    while(*p) {
        char* eol = p;
        while(*eol && *eol != '\n' && *eol != '\r')
            eol++;
        char saved = *eol;
        *eol = 0;
        settings_apply_line(s, p);
        if(!saved) break;
        p = eol + 1;
    }
    stc_memzero(text, len);
    free(text);
}

bool stoken_settings_save(const StokenSettings* s) {
    Storage* storage = furi_record_open(RECORD_STORAGE);
    File* file = storage_file_alloc(storage);
    char buf[256];
    bool ok = false;

    storage_simply_mkdir(storage, STOKEN_DIR);
    int n = snprintf(
        buf,
        sizeof(buf),
        "# stoken settings\n"
        "tz_offset %d\n"
        "keyboard %d\n"
        "send_enter %d\n"
        "static_pin %s\n"
        "last_token %s\n",
        s->tz_offset_min,
        s->keyboard_enabled ? 1 : 0,
        s->send_enter ? 1 : 0,
        s->static_pin,
        s->last_token);

    if(n > 0 && (size_t)n < sizeof(buf) &&
       storage_file_open(file, STOKEN_SETTINGS_FILE, FSAM_WRITE, FSOM_CREATE_ALWAYS)) {
        ok = storage_file_write(file, buf, (size_t)n) == (size_t)n;
    }
    storage_file_close(file);
    storage_file_free(file);
    furi_record_close(RECORD_STORAGE);
    stc_memzero(buf, sizeof(buf));
    return ok;
}

void stoken_tz_format(int16_t offset_min, char* out, size_t out_len) {
    if(offset_min == 0) {
        snprintf(out, out_len, "UTC");
        return;
    }
    int a = offset_min < 0 ? -offset_min : offset_min;
    snprintf(out, out_len, "UTC%c%02d:%02d", offset_min < 0 ? '-' : '+', a / 60, a % 60);
}
