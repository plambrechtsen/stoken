/*
 * stoken_core.h - SecurID tokencode generation, ported from stoken for the
 * Flipper Zero.  Platform independent: no file I/O, no SDK headers.
 *
 * Copyright 2012 Kevin Cernekee <cernekee@gmail.com> (original securid.c)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define SECURID_SERIAL_CHARS 12
#define SECURID_MIN_PIN      4
#define SECURID_MAX_PIN      8
#define SECURID_MAX_PASS     40
#define SECURID_MAX_DIGITS   8

/* Rough worst case for a URL-encoded v3/v4 ctf string plus URL prefix */
#define STOKEN_MAX_TOKEN_STR 1400

#define STOKEN_NICKNAME_LEN 32
#define STOKEN_DEVID_LEN    64

enum {
    STOKEN_OK = 0,
    STOKEN_ERR_GENERAL,
    STOKEN_ERR_BAD_LEN,
    STOKEN_ERR_TOKEN_VERSION,
    STOKEN_ERR_CHECKSUM_FAILED,
    STOKEN_ERR_BAD_PASSWORD,
    STOKEN_ERR_MISSING_PASSWORD,
    STOKEN_ERR_DECRYPT_FAILED,
    STOKEN_ERR_BAD_DEVID,
    STOKEN_ERR_NO_MEMORY,
    STOKEN_ERR_FILE_READ,
    STOKEN_ERR_MISSING_DEVID,
    STOKEN_ERR_BAD_PIN,
    STOKEN_ERR_RC_VERSION,
};

/* Matches the binary layout of a decoded v3/v4 ctf blob (0x123 bytes) */
typedef struct {
    uint8_t version;
    uint8_t password_locked;
    uint8_t devid_locked;
    uint8_t nonce_devid_hash[32];
    uint8_t nonce_devid_pass_hash[32];
    uint8_t nonce[16];
    uint8_t enc_payload[0xb0];
    uint8_t mac[32];
} SecuridV3Token;

typedef struct {
    int version;
    char serial[SECURID_SERIAL_CHARS + 1];
    uint16_t flags;
    uint16_t exp_date;
    bool is_smartphone;

    bool has_enc_seed;
    uint8_t enc_seed[16];
    uint16_t dec_seed_hash;
    uint16_t device_id_hash;

    bool has_dec_seed;
    uint8_t dec_seed[16];

    /* token PIN, mathematically merged into the code for PIN-mode tokens */
    char pin[SECURID_MAX_PIN + 1];

    bool is_v3;
    SecuridV3Token v3;
} SecuridToken;

/* One token definition read from a .stokenrc style file */
typedef struct {
    int version;
    char nickname[STOKEN_NICKNAME_LEN];
    char token[STOKEN_MAX_TOKEN_STR];
    char pin[72]; /* plain 4-8 digits, or 64 hex chars encrypted with password */
    char password[SECURID_MAX_PASS + 1];
    char devid[STOKEN_DEVID_LEN];
} StokenRc;

/* Parse a token string (bare digits, ctf URL, or base64 v3/v4 blob) */
int securid_parse_token_string(const char* str, SecuridToken* t);
int securid_decrypt_seed(SecuridToken* t, const char* pass, const char* devid);
int securid_decrypt_pin(const char* enc_pin, const char* password, char* pin_out);
int securid_pin_format_ok(const char* pin);

/* utc: seconds since 1970-01-01 00:00:00 UTC.  code_out >= 9 bytes */
void securid_compute_tokencode(const SecuridToken* t, int64_t utc, char* code_out);

int securid_token_interval(const SecuridToken* t);
int securid_token_digits(const SecuridToken* t);
bool securid_pin_required(const SecuridToken* t);
bool securid_pass_required(const SecuridToken* t);
bool securid_devid_required(const SecuridToken* t);
int64_t securid_unix_exp_date(const SecuridToken* t);
/* days until expiry (negative once expired), includes ~12h grace like stoken */
int securid_check_exp(const SecuridToken* t, int64_t utc);

/*
 * Parse an rc file.  Recognised keys: version, token, pin, nickname,
 * password, devid.  Lines are "key value"; '#' starts a comment.
 * Returns STOKEN_OK if a usable "version 1" + "token" pair was found.
 */
int stoken_rc_parse(const char* text, size_t len, StokenRc* rc);

/*
 * Turn a parsed rc entry into a ready-to-use token: decode, decrypt the
 * seed with password/devid if required, and apply the token PIN.
 */
int stoken_rc_load(const StokenRc* rc, SecuridToken* t);

const char* stoken_errstr(int err);

/* Minimal UTC breakdown (no libc time dependency) */
typedef struct {
    int year, month, day; /* month 1..12 */
    int hour, minute, second;
} StokenUtcTime;

void stoken_utc_breakdown(int64_t utc, StokenUtcTime* out);

/* overwrite memory in a way the compiler should not optimise out */
void stc_memzero(void* p, size_t len);
