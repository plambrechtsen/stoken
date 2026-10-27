/*
 * stoken_core.c - SecurID token handling, ported from stoken's securid.c and
 * library.c for the Flipper Zero.
 *
 * Copyright 2012 Kevin Cernekee <cernekee@gmail.com> (original securid.c)
 *
 * Changes from upstream:
 *  - no file I/O, alloca, ctype or libc time functions (not all are exported
 *    to Flipper apps); time is passed in as a UTC timestamp
 *  - token encoding/export and sdtid (XML) support removed
 *  - rc parsing extended with nickname/password/devid keys
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include "stoken_core.h"
#include <stdio.h>
#include <string.h>

#include <mbedtls/aes.h>
#include <mbedtls/base64.h>
#include <mbedtls/sha256.h>

#define AES_BLOCK_SIZE 16
#define AES_KEY_SIZE   16

#define SHA256_BLOCK_SIZE 64
#define SHA256_HASH_SIZE  32

#define MAGIC_LEN 6

#define VER_CHARS    1
#define SERIAL_CHARS SECURID_SERIAL_CHARS

#define TOKEN_BITS_PER_CHAR 3
#define CHECKSUM_BITS       15
#define CHECKSUM_CHARS      (CHECKSUM_BITS / TOKEN_BITS_PER_CHAR)
#define BINENC_BITS         189
#define BINENC_CHARS        (BINENC_BITS / TOKEN_BITS_PER_CHAR)
#define BINENC_OFS          (VER_CHARS + SERIAL_CHARS)

#define DEVID_CHARS     40
#define V3_DEVID_CHARS  48
#define V3_NONCE_BYTES  16

#define MIN_TOKEN_BITS  189
#define MAX_TOKEN_BITS  255
#define MAX_TOKEN_CHARS (MAX_TOKEN_BITS / TOKEN_BITS_PER_CHAR)
#define MIN_TOKEN_CHARS \
    ((MIN_TOKEN_BITS / TOKEN_BITS_PER_CHAR) + SERIAL_CHARS + VER_CHARS + CHECKSUM_CHARS)

#define BASE64_INPUT_LEN(x) ((4 * ((x) + 2) / 3) + 1)
#define V3_BASE64_BYTES     0x123
#define V3_BASE64_SIZE      (BASE64_INPUT_LEN(V3_BASE64_BYTES))
#define V3_BASE64_MIN_CHARS (V3_BASE64_BYTES * 4 / 3)

#define BIT(x) (1u << (x))

#define FL_128BIT            BIT(14)
#define FL_PASSPROT          BIT(13)
#define FL_SNPROT            BIT(12)
#define FL_APPSEEDS          BIT(11)
#define FL_FEAT4             BIT(10)
#define FL_TIMESEEDS         BIT(9)
#define FLD_DIGIT_SHIFT      6
#define FLD_DIGIT_MASK       (0x07 << FLD_DIGIT_SHIFT)
#define FLD_PINMODE_SHIFT    3
#define FLD_PINMODE_MASK     (0x03 << FLD_PINMODE_SHIFT)
#define FLD_NUMSECONDS_SHIFT 0
#define FLD_NUMSECONDS_MASK  (0x03 << FLD_NUMSECONDS_SHIFT)

/* UNIX time for 2000/01/01 00:00:00 GMT */
#define SECURID_EPOCH      946684800
#define SECURID_EPOCH_DAYS (SECURID_EPOCH / (24 * 60 * 60))
#define SECURID_V3_DAY     337500
#define MAX_TIME_T         0x7fffffff
#define SECURID_MAX_SECS   (MAX_TIME_T - SECURID_EPOCH)
#define SECURID_MAX_DATE   (SECURID_MAX_SECS / (24 * 60 * 60) - 1)

#define V3_ADDPIN_OFF 0x1f

typedef struct {
    char serial[16];
    uint8_t dec_seed[AES_KEY_SIZE];
    uint8_t unk0[2];
    uint8_t mode;
    uint8_t digits;
    uint8_t addpin;
    uint8_t interval;
    uint8_t res0[2];
    uint8_t birth_date[5];
    uint8_t res1[3];
    uint8_t exp_date[5];
    uint8_t res2[0x6b];
    uint8_t padding[0x10];
} V3Payload;

_Static_assert(sizeof(SecuridV3Token) == V3_BASE64_BYTES, "v3 token layout");
_Static_assert(sizeof(V3Payload) == 0xb0, "v3 payload layout");

/********************************************************************
 * Tiny ctype replacements
 ********************************************************************/

static bool is_digit(char c) {
    return c >= '0' && c <= '9';
}
static bool is_xdigit(char c) {
    return is_digit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}
static bool is_alnum(char c) {
    return is_digit(c) || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}
static char to_upper(char c) {
    return (c >= 'a' && c <= 'z') ? (char)(c - 'a' + 'A') : c;
}
static bool is_space(char c) {
    return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

static const char* ci_strstr(const char* hay, const char* needle) {
    size_t n = strlen(needle);
    for(; *hay; hay++) {
        size_t i = 0;
        while(i < n && hay[i] && to_upper(hay[i]) == to_upper(needle[i]))
            i++;
        if(i == n) return hay;
    }
    return NULL;
}

static bool ci_equal(const char* a, const char* b) {
    for(; *a && *b; a++, b++)
        if(to_upper(*a) != to_upper(*b)) return false;
    return *a == *b;
}

static uint8_t hex2nibble(char in) {
    if(in >= '0' && in <= '9') return (uint8_t)(in - '0');
    return (uint8_t)(10 + to_upper(in) - 'A');
}

static uint8_t hex2byte(const char* in) {
    return (uint8_t)((hex2nibble(in[0]) << 4) | hex2nibble(in[1]));
}

/********************************************************************
 * MAC / hash helpers
 ********************************************************************/

/* AES-128 single block; in and out may be the same buffer */
static void aes128_ecb_crypt(int mode, const uint8_t* key, const uint8_t* in, uint8_t* out) {
    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);
    if(mode == MBEDTLS_AES_ENCRYPT)
        mbedtls_aes_setkey_enc(&ctx, key, 128);
    else
        mbedtls_aes_setkey_dec(&ctx, key, 128);
    mbedtls_aes_crypt_ecb(&ctx, mode, in, out);
    mbedtls_aes_free(&ctx); /* zeroises the key schedule */
}

static void aes128_ecb_encrypt(const uint8_t* key, const uint8_t* in, uint8_t* out) {
    aes128_ecb_crypt(MBEDTLS_AES_ENCRYPT, key, in, out);
}

static void aes128_ecb_decrypt(const uint8_t* key, const uint8_t* in, uint8_t* out) {
    aes128_ecb_crypt(MBEDTLS_AES_DECRYPT, key, in, out);
}

/* in_len must be a multiple of AES_BLOCK_SIZE */
static int aes256_cbc_decrypt(
    const uint8_t* key,
    const uint8_t* in,
    size_t in_len,
    const uint8_t* iv,
    uint8_t* out) {
    mbedtls_aes_context ctx;
    uint8_t iv_copy[AES_BLOCK_SIZE]; /* mbedtls updates the IV in place */
    int rc;

    memcpy(iv_copy, iv, AES_BLOCK_SIZE);
    mbedtls_aes_init(&ctx);
    rc = mbedtls_aes_setkey_dec(&ctx, key, 256);
    if(rc == 0) rc = mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_DECRYPT, in_len, iv_copy, in, out);
    mbedtls_aes_free(&ctx);
    stc_memzero(iv_copy, sizeof(iv_copy));
    return rc;
}

static void encrypt_then_xor(const uint8_t* key, uint8_t* work, uint8_t* enc) {
    aes128_ecb_encrypt(key, work, enc);
    for(int i = 0; i < AES_BLOCK_SIZE; i++)
        work[i] ^= enc[i];
}

static void securid_mac(const uint8_t* in, int in_len, uint8_t* out) {
    int i, odd = 0;
    enum { incr = AES_KEY_SIZE };
    uint8_t work[incr], enc[incr], pad[incr], zero[incr], lastblk[incr], *p;

    memset(zero, 0, incr);
    memset(pad, 0, incr);
    memset(lastblk, 0, incr);
    memset(work, 0xff, incr);

    /* padding */
    p = &pad[incr - 1];
    for(i = in_len * 8; i > 0; i >>= 8)
        *(p--) = (uint8_t)i;

    /* handle the bulk of the input data here */
    for(; in_len > incr; in_len -= incr, in += incr, odd = !odd)
        encrypt_then_xor(in, work, enc);

    /* final 0-16 bytes of input data */
    memcpy(lastblk, in, in_len);
    encrypt_then_xor(lastblk, work, enc);

    /* hash an extra block of zeroes, for certain input lengths */
    if(odd) encrypt_then_xor(zero, work, enc);

    /* always hash the padding */
    encrypt_then_xor(pad, work, enc);

    /* run hash over current hash value, then return */
    memcpy(out, work, incr);
    encrypt_then_xor(work, out, enc);
}

static uint16_t securid_shortmac(const uint8_t* in, int in_len) {
    uint8_t hash[AES_BLOCK_SIZE];
    securid_mac(in, in_len, hash);
    return (uint16_t)((hash[0] << 7) | (hash[1] >> 1));
}

static void sha256_hash2(
    uint8_t* out,
    const uint8_t* a,
    size_t a_len,
    const uint8_t* b,
    size_t b_len) {
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0); /* 0 = SHA-256, not SHA-224 */
    mbedtls_sha256_update(&ctx, a, a_len);
    if(b) mbedtls_sha256_update(&ctx, b, b_len);
    mbedtls_sha256_finish(&ctx, out);
    mbedtls_sha256_free(&ctx); /* zeroises the context */
}

static void sha256_hmac(
    const uint8_t* key,
    int key_len,
    const uint8_t* msg,
    int msg_len,
    uint8_t* out) {
    uint8_t tmp_key[SHA256_HASH_SIZE], o_key_pad[SHA256_BLOCK_SIZE],
        i_key_pad[SHA256_BLOCK_SIZE], inner_hash[SHA256_HASH_SIZE];

    if(key_len > SHA256_BLOCK_SIZE) {
        sha256_hash2(tmp_key, key, key_len, NULL, 0);
        key = tmp_key;
        key_len = SHA256_HASH_SIZE;
    }

    memset(o_key_pad, 0x5c, SHA256_BLOCK_SIZE);
    memset(i_key_pad, 0x36, SHA256_BLOCK_SIZE);
    for(int i = 0; i < key_len; i++) {
        o_key_pad[i] ^= key[i];
        i_key_pad[i] ^= key[i];
    }

    sha256_hash2(inner_hash, i_key_pad, SHA256_BLOCK_SIZE, msg, msg_len);
    sha256_hash2(out, o_key_pad, SHA256_BLOCK_SIZE, inner_hash, SHA256_HASH_SIZE);
}

/* salt is always V3_NONCE_BYTES long for our callers */
static void sha256_pbkdf2(
    const uint8_t* pass,
    int pass_len,
    const uint8_t* salt,
    int n_rounds,
    uint8_t* key_out) {
    uint8_t ext_salt[V3_NONCE_BYTES + 4];
    uint8_t hash[SHA256_HASH_SIZE];

    memcpy(ext_salt, salt, V3_NONCE_BYTES);
    /* always 0x00000001, as the output size is fixed at SHA256_HASH_SIZE */
    ext_salt[V3_NONCE_BYTES + 0] = 0;
    ext_salt[V3_NONCE_BYTES + 1] = 0;
    ext_salt[V3_NONCE_BYTES + 2] = 0;
    ext_salt[V3_NONCE_BYTES + 3] = 1;

    sha256_hmac(pass, pass_len, ext_salt, sizeof(ext_salt), key_out);
    memcpy(hash, key_out, SHA256_HASH_SIZE);

    for(int round = 2; round <= n_rounds; round++) {
        sha256_hmac(pass, pass_len, hash, SHA256_HASH_SIZE, hash);
        for(int i = 0; i < SHA256_HASH_SIZE; i++)
            key_out[i] ^= hash[i];
    }
}

/********************************************************************
 * V1/V2 token handling
 ********************************************************************/

static void numinput_to_bits(const char* in, uint8_t* out, unsigned int n_bits) {
    int bitpos = 13;

    memset(out, 0, (n_bits + 7) / 8);
    for(; n_bits; n_bits -= TOKEN_BITS_PER_CHAR, in++) {
        uint16_t decoded = (uint16_t)((*in - '0') & 0x07);
        decoded <<= bitpos;
        out[0] |= (uint8_t)(decoded >> 8);
        out[1] |= (uint8_t)(decoded & 0xff);

        bitpos -= TOKEN_BITS_PER_CHAR;
        if(bitpos < 0) {
            bitpos += 8;
            out++;
        }
    }
}

static uint32_t get_bits(const uint8_t* in, unsigned int start, int n_bits) {
    uint32_t out = 0;

    in += start / 8;
    start %= 8;

    for(; n_bits > 0; n_bits--) {
        out <<= 1;
        if((*in << start) & 0x80) out |= 0x01;
        start++;
        if(start == 8) {
            start = 0;
            in++;
        }
    }
    return out;
}

static int v2_decode_token(const char* in, SecuridToken* t) {
    uint8_t d[MAX_TOKEN_BITS / 8 + 2];
    int len = (int)strlen(in);
    uint16_t token_mac, computed_mac;

    if(len < MIN_TOKEN_CHARS || len > MAX_TOKEN_CHARS) return STOKEN_ERR_BAD_LEN;

    /* the last 5 digits provide a checksum for the rest of the string */
    numinput_to_bits(&in[len - CHECKSUM_CHARS], d, 15);
    token_mac = (uint16_t)get_bits(d, 0, 15);
    computed_mac = securid_shortmac((const uint8_t*)in, len - CHECKSUM_CHARS);

    if(token_mac != computed_mac) return STOKEN_ERR_CHECKSUM_FAILED;

    t->version = in[0] - '0';
    memcpy(t->serial, &in[VER_CHARS], SERIAL_CHARS);
    t->serial[SERIAL_CHARS] = 0;

    numinput_to_bits(&in[BINENC_OFS], d, BINENC_BITS);
    memcpy(t->enc_seed, d, AES_KEY_SIZE);
    t->has_enc_seed = true;

    t->flags = (uint16_t)get_bits(d, 128, 16);
    t->exp_date = (uint16_t)get_bits(d, 144, 14);
    t->dec_seed_hash = (uint16_t)get_bits(d, 159, 15);
    t->device_id_hash = (uint16_t)get_bits(d, 174, 15);

    return STOKEN_OK;
}

static int generate_key_hash(
    uint8_t* key_hash,
    const char* pass,
    const char* devid,
    uint16_t* device_id_hash,
    const SecuridToken* t) {
    uint8_t key[SECURID_MAX_PASS + DEVID_CHARS + MAGIC_LEN + 1], *devid_buf;
    int pos = 0, devid_len = t->is_smartphone ? 40 : 32;
    const uint8_t magic[] = {0xd8, 0xf5, 0x32, 0x53, 0x82, 0x89, 0x00};

    memset(key, 0, sizeof(key));

    if(pass) {
        pos = (int)strlen(pass);
        if(pos > SECURID_MAX_PASS) return STOKEN_ERR_BAD_PASSWORD;
        memcpy(key, pass, pos);
    }

    devid_buf = &key[pos];
    if(devid) {
        int len = 0;
        /*
         * iPhone/Android ctf strings: 40 bytes of hex digits + zero padding.
         * Other ctf strings: 32 bytes of decimal digits + zero padding.
         */
        for(; *devid; devid++) {
            if(++len > devid_len) break;
            if((t->version == 1 && is_digit(*devid)) || (t->version >= 2 && !is_xdigit(*devid)))
                continue;
            key[pos++] = (uint8_t)to_upper(*devid);
        }
    }
    if(device_id_hash) *device_id_hash = securid_shortmac(devid_buf, devid_len);

    memcpy(&key[pos], magic, MAGIC_LEN);
    securid_mac(key, pos + MAGIC_LEN, key_hash);
    stc_memzero(key, sizeof(key));

    return STOKEN_OK;
}

static int v2_decrypt_seed(SecuridToken* t, const char* pass, const char* devid) {
    uint8_t key_hash[AES_BLOCK_SIZE], dec_seed_hash[AES_BLOCK_SIZE];
    uint16_t computed_mac;
    uint16_t device_id_hash;
    int rc;

    rc = generate_key_hash(key_hash, pass, devid, &device_id_hash, t);
    if(rc) return rc;

    if((t->flags & FL_SNPROT) && device_id_hash != t->device_id_hash) return STOKEN_ERR_BAD_DEVID;

    aes128_ecb_decrypt(key_hash, t->enc_seed, t->dec_seed);
    stc_memzero(key_hash, sizeof(key_hash));
    securid_mac(t->dec_seed, AES_KEY_SIZE, dec_seed_hash);
    computed_mac = (uint16_t)((dec_seed_hash[0] << 7) | (dec_seed_hash[1] >> 1));

    if(computed_mac != t->dec_seed_hash) {
        stc_memzero(t->dec_seed, sizeof(t->dec_seed));
        return STOKEN_ERR_DECRYPT_FAILED;
    }
    t->has_dec_seed = true;

    return STOKEN_OK;
}

static void key_from_time(
    const uint8_t* bcd_time,
    int bcd_time_bytes,
    const char* serial,
    uint8_t* key) {
    memset(key, 0xaa, 8);
    memcpy(key, bcd_time, bcd_time_bytes);
    memset(key + 12, 0xbb, 4);

    /* write BCD-encoded partial serial number */
    key += 8;
    for(int i = 4; i < 12; i += 2)
        *(key++) = (uint8_t)(((serial[i] - '0') << 4) | (serial[i + 1] - '0'));
}

static void bcd_write(uint8_t* out, int val, unsigned int bytes) {
    out += bytes - 1;
    for(; bytes; bytes--) {
        *out = (uint8_t)(val % 10);
        val /= 10;
        *(out--) |= (uint8_t)((val % 10) << 4);
        val /= 10;
    }
}

/********************************************************************
 * V3/V4 token handling
 ********************************************************************/

static void v3_derive_key(
    const char* pass,
    const char* devid,
    const uint8_t* salt,
    int key_id,
    int version,
    uint8_t* out) {
    enum { MAX_BUF = V3_DEVID_CHARS + 16 + V3_NONCE_BYTES + SECURID_MAX_PASS };
    uint8_t buf0[MAX_BUF], buf1[MAX_BUF / 2 + 1];
    const uint8_t* pbkdf_in = buf0;
    int pass_len = pass ? (int)strlen(pass) : 0;
    int buf_len;
    static const uint8_t key0[] = {
        0xd0, 0x14, 0x43, 0x3c, 0x6d, 0x17, 0x9f, 0xeb,
        0xda, 0x09, 0xab, 0xfc, 0x32, 0x49, 0x63, 0x4c};
    static const uint8_t key1[] = {
        0x3b, 0xaf, 0xff, 0x4d, 0x91, 0x8d, 0x89, 0xb6,
        0x81, 0x60, 0xde, 0x44, 0x4e, 0x05, 0xc0, 0xdd};

    if(pass_len > SECURID_MAX_PASS) pass_len = SECURID_MAX_PASS;
    buf_len = V3_DEVID_CHARS + 16 + V3_NONCE_BYTES + pass_len;

    memset(buf0, 0, sizeof(buf0));
    if(pass) memcpy(buf0, pass, pass_len);
    if(devid) strncpy((char*)&buf0[pass_len], devid, V3_DEVID_CHARS);
    memcpy(&buf0[pass_len + V3_DEVID_CHARS], key_id ? key1 : key0, 16);
    memcpy(&buf0[pass_len + V3_DEVID_CHARS + 16], salt, V3_NONCE_BYTES);

    /* for v3 the PBKDF2 password is "every 2nd byte of the input";
     * v4 uses the full buffer */
    if(version == 3) {
        for(int i = 1; i < buf_len; i += 2)
            buf1[i >> 1] = buf0[i];
        buf_len >>= 1;
        pbkdf_in = buf1;
    }

    sha256_pbkdf2(pbkdf_in, buf_len, salt, 1000, out);
    stc_memzero(buf0, sizeof(buf0));
    stc_memzero(buf1, sizeof(buf1));
}

static int v3_decode_token(const char* in, SecuridToken* t) {
    char decoded[V3_BASE64_SIZE];
    int i, j;
    size_t actual;

    /* remove URL-encoding */
    for(i = 0, j = 0; in[i];) {
        if(j == V3_BASE64_SIZE - 1) return STOKEN_ERR_BAD_LEN;
        if(in[i] == '%') {
            if(!is_xdigit(in[i + 1]) || !is_xdigit(in[i + 2])) return STOKEN_ERR_BAD_LEN;
            decoded[j++] = (char)hex2byte(&in[i + 1]);
            i += 3;
        } else {
            decoded[j++] = in[i++];
        }
    }
    decoded[j] = 0;

    if(mbedtls_base64_decode(
           (uint8_t*)&t->v3,
           sizeof(SecuridV3Token),
           &actual,
           (const uint8_t*)decoded,
           strlen(decoded)) != 0 ||
       actual != sizeof(SecuridV3Token) || (t->v3.version != 0x03 && t->v3.version != 0x04)) {
        memset(&t->v3, 0, sizeof(t->v3));
        return STOKEN_ERR_GENERAL;
    }

    t->is_v3 = true;
    t->version = t->v3.version;

    /* more flags will get populated later when we decrypt the payload */
    t->flags = t->v3.password_locked ? FL_PASSPROT : 0;
    t->flags |= t->v3.devid_locked ? FL_SNPROT : 0;

    return STOKEN_OK;
}

static uint16_t v3_parse_date(const uint8_t* in) {
    uint64_t longdate = ((uint64_t)in[0] << 32) | ((uint64_t)in[1] << 24) |
                        ((uint64_t)in[2] << 16) | ((uint64_t)in[3] << 8) | ((uint64_t)in[4]);
    longdate /= SECURID_V3_DAY;
    longdate -= SECURID_EPOCH_DAYS;
    return (uint16_t)(longdate <= SECURID_MAX_DATE ? longdate : SECURID_MAX_DATE);
}

static void v3_compute_hash(const char* pass, const char* devid, const uint8_t* salt, uint8_t* hash) {
    uint8_t hash_buf[V3_NONCE_BYTES + V3_DEVID_CHARS + SECURID_MAX_PASS];
    size_t pass_len = 0;

    memset(hash_buf, 0, sizeof(hash_buf));
    memcpy(&hash_buf[0], salt, V3_NONCE_BYTES);

    if(devid) strncpy((char*)&hash_buf[V3_NONCE_BYTES], devid, V3_DEVID_CHARS);

    if(pass) {
        pass_len = strlen(pass);
        if(pass_len > SECURID_MAX_PASS) pass_len = SECURID_MAX_PASS;
        memcpy(&hash_buf[V3_NONCE_BYTES + V3_DEVID_CHARS], pass, pass_len);
    }
    sha256_hash2(hash, hash_buf, V3_NONCE_BYTES + V3_DEVID_CHARS + pass_len, NULL, 0);
    stc_memzero(hash_buf, sizeof(hash_buf));
}

static void v3_compute_hmac(
    const SecuridV3Token* v3,
    const char* pass,
    const char* devid,
    uint8_t* out) {
    uint8_t hash[SHA256_HASH_SIZE];

    v3_derive_key(pass, devid, v3->nonce, 0, v3->version, hash);
    sha256_hmac(hash, SHA256_HASH_SIZE, (const uint8_t*)v3, sizeof(*v3) - SHA256_HASH_SIZE, out);
    stc_memzero(hash, sizeof(hash));
}

static void v3_scrub_devid(const char* in, char* out) {
    int j = 0;
    for(; in && *in && j < V3_DEVID_CHARS; in++) {
        if(is_alnum(*in)) out[j++] = to_upper(*in);
    }
    out[j] = 0;
}

static int v3_decrypt_seed(SecuridToken* t, const char* pass, const char* raw_devid) {
    V3Payload payload;
    uint8_t hash[SHA256_HASH_SIZE];
    char devid[V3_DEVID_CHARS + 1];
    int rc = STOKEN_OK;

    v3_scrub_devid(raw_devid, devid);

    v3_compute_hash(NULL, devid, t->v3.nonce, hash);
    if(memcmp(hash, t->v3.nonce_devid_hash, SHA256_HASH_SIZE) != 0) return STOKEN_ERR_BAD_DEVID;

    v3_compute_hash(pass, devid, t->v3.nonce, hash);
    if(memcmp(hash, t->v3.nonce_devid_pass_hash, SHA256_HASH_SIZE) != 0)
        return STOKEN_ERR_DECRYPT_FAILED;

    v3_compute_hmac(&t->v3, pass, devid, hash);
    if(memcmp(hash, t->v3.mac, SHA256_HASH_SIZE) != 0) return STOKEN_ERR_CHECKSUM_FAILED;

    v3_derive_key(pass, devid, t->v3.nonce, 1, t->version, hash);
    _Static_assert(sizeof(V3Payload) % AES_BLOCK_SIZE == 0, "v3 payload is whole AES blocks");
    _Static_assert(V3_NONCE_BYTES == AES_BLOCK_SIZE, "v3 nonce is used as the CBC IV");
    if(aes256_cbc_decrypt(
           hash, t->v3.enc_payload, sizeof(V3Payload), t->v3.nonce, (uint8_t*)&payload) != 0) {
        stc_memzero(hash, sizeof(hash));
        rc = STOKEN_ERR_GENERAL;
        goto out;
    }
    stc_memzero(hash, sizeof(hash));

    /* serial must be exactly 12 chars followed by a NUL (strnlen isn't exported) */
    if(memchr(payload.serial, 0, SERIAL_CHARS) != NULL || payload.serial[SERIAL_CHARS] != 0) {
        rc = STOKEN_ERR_GENERAL;
        goto out;
    }
    memcpy(t->serial, payload.serial, SERIAL_CHARS);
    t->serial[SERIAL_CHARS] = 0;

    memcpy(t->dec_seed, payload.dec_seed, AES_KEY_SIZE);
    t->has_dec_seed = true;

    t->flags |= FL_TIMESEEDS | FL_128BIT;
    t->flags |= payload.mode ? FL_FEAT4 : 0;
    t->flags |= ((payload.digits - 1) << FLD_DIGIT_SHIFT) & FLD_DIGIT_MASK;
    t->flags |= (payload.addpin != V3_ADDPIN_OFF) ? (0x2 << FLD_PINMODE_SHIFT) : 0;
    t->flags |= payload.interval == 60 ? (1 << FLD_NUMSECONDS_SHIFT) : 0;

    t->exp_date = v3_parse_date(payload.exp_date);

out:
    stc_memzero(&payload, sizeof(payload));
    return rc;
}

/********************************************************************
 * Public functions
 ********************************************************************/

static int securid_decode_token(const char* in, SecuridToken* t) {
    /*
     * V1/V2 tokens start with the ASCII version digit.
     * V3/V4 tokens start with a base64-encoded 0x03/0x04 byte ('A' / 'B').
     */
    if(in[0] == '1' || in[0] == '2')
        return v2_decode_token(in, t);
    else if(strlen(in) >= V3_BASE64_MIN_CHARS && (in[0] == 'A' || in[0] == 'B'))
        return v3_decode_token(in, t);
    else
        return STOKEN_ERR_TOKEN_VERSION;
}

static bool starts_with(const char* s, const char* prefix) {
    return strncmp(s, prefix, strlen(prefix)) == 0;
}

int securid_parse_token_string(const char* str, SecuridToken* t) {
    char buf[STOKEN_MAX_TOKEN_STR];
    const char* p;
    int i, ret;

    memset(t, 0, sizeof(*t));

    do {
        /* try to handle broken quoted-printable input */
        p = ci_strstr(str, "ctfData=3D");
        if(p) {
            p += 10;
            break;
        }
        /* normal iPhone/Android soft token URLs */
        p = ci_strstr(str, "ctfData=");
        if(p) {
            p += 8;
            break;
        }
        p = str;
        if(is_digit(*p) || *p == 'A' || *p == 'B') break;
        /* bogus token string (sdtid XML is not supported on the Flipper) */
        return STOKEN_ERR_GENERAL;
    } while(0);

    if(p[0] == '1' || p[0] == '2') {
        for(i = 0; *p; p++) {
            if(i >= (int)sizeof(buf) - 1) return STOKEN_ERR_BAD_LEN;
            if(is_digit(*p))
                buf[i++] = *p;
            else if(*p != '-')
                break;
        }
    } else if(p[0] == 'A' || p[0] == 'B') {
        for(i = 0; *p && !is_space(*p); p++) {
            if(i >= (int)sizeof(buf) - 1) return STOKEN_ERR_BAD_LEN;
            buf[i++] = *p;
        }
    } else
        return STOKEN_ERR_GENERAL;

    buf[i] = 0;
    ret = securid_decode_token(buf, t);

    if(starts_with(str, "com.rsa.securid.iphone://ctf") || starts_with(str, "com.rsa.securid://ctf") ||
       starts_with(str, "http://127.0.0.1/securid/ctf"))
        t->is_smartphone = true;
    return ret;
}

int securid_decrypt_seed(SecuridToken* t, const char* pass, const char* devid) {
    if(t->flags & FL_PASSPROT) {
        if(!pass || !pass[0]) return STOKEN_ERR_MISSING_PASSWORD;
        if(strlen(pass) > SECURID_MAX_PASS) return STOKEN_ERR_BAD_PASSWORD;
    } else
        pass = NULL;

    if(t->flags & FL_SNPROT) {
        if(!devid || !devid[0]) return STOKEN_ERR_MISSING_DEVID;
    } else
        devid = NULL;

    if(t->is_v3)
        return v3_decrypt_seed(t, pass, devid);
    else
        return v2_decrypt_seed(t, pass, devid);
}

void securid_compute_tokencode(const SecuridToken* t, int64_t utc, char* code_out) {
    uint8_t bcd_time[8];
    uint8_t key0[AES_KEY_SIZE], key1[AES_KEY_SIZE];
    int i, j;
    uint32_t tokencode;
    StokenUtcTime gmt;
    int pin_len = (int)strlen(t->pin);
    int is_30 = securid_token_interval(t) == 30;

    stoken_utc_breakdown(utc, &gmt);
    bcd_write(&bcd_time[0], gmt.year, 2);
    bcd_write(&bcd_time[2], gmt.month, 1);
    bcd_write(&bcd_time[3], gmt.day, 1);
    bcd_write(&bcd_time[4], gmt.hour, 1);
    bcd_write(&bcd_time[5], gmt.minute & ~(is_30 ? 0x01 : 0x03), 1);
    bcd_time[6] = bcd_time[7] = 0;

    key_from_time(bcd_time, 2, t->serial, key0);
    aes128_ecb_encrypt(t->dec_seed, key0, key0);
    key_from_time(bcd_time, 3, t->serial, key1);
    aes128_ecb_encrypt(key0, key1, key1);
    key_from_time(bcd_time, 4, t->serial, key0);
    aes128_ecb_encrypt(key1, key0, key0);
    key_from_time(bcd_time, 5, t->serial, key1);
    aes128_ecb_encrypt(key0, key1, key1);
    key_from_time(bcd_time, 8, t->serial, key0);
    aes128_ecb_encrypt(key1, key0, key0);

    /* key0 now contains 4 consecutive token codes */
    if(is_30)
        i = ((gmt.minute & 0x01) << 3) | ((gmt.second >= 30) << 2);
    else
        i = (gmt.minute & 0x03) << 2;

    tokencode = ((uint32_t)key0[i + 0] << 24) | ((uint32_t)key0[i + 1] << 16) |
                ((uint32_t)key0[i + 2] << 8) | ((uint32_t)key0[i + 3]);

    /* populate code_out backwards, adding PIN digits if available */
    j = securid_token_digits(t);
    code_out[j--] = 0;
    for(i = 0; j >= 0; j--, i++) {
        uint8_t c = tokencode % 10;
        tokencode /= 10;
        if(i < pin_len) c += (uint8_t)(t->pin[pin_len - i - 1] - '0');
        code_out[j] = (char)(c % 10 + '0');
    }

    stc_memzero(key0, sizeof(key0));
    stc_memzero(key1, sizeof(key1));
}

int securid_token_interval(const SecuridToken* t) {
    return (((t->flags & FLD_NUMSECONDS_MASK) >> FLD_NUMSECONDS_SHIFT) == 0) ? 30 : 60;
}

int securid_token_digits(const SecuridToken* t) {
    return ((t->flags & FLD_DIGIT_MASK) >> FLD_DIGIT_SHIFT) + 1;
}

int64_t securid_unix_exp_date(const SecuridToken* t) {
    if(t->version >= 3 && !t->exp_date) return MAX_TIME_T;
    if(t->exp_date > SECURID_MAX_DATE) return MAX_TIME_T;
    return SECURID_EPOCH + ((int64_t)t->exp_date + 1) * 60 * 60 * 24;
}

int securid_check_exp(const SecuridToken* t, int64_t utc) {
    const int64_t halfday = 60 * 60 * 12, wholeday = 60 * 60 * 24;
    int64_t remaining = securid_unix_exp_date(t) + halfday - utc;
    return (int)(remaining / wholeday);
}

int securid_pin_format_ok(const char* pin) {
    int len = (int)strlen(pin);
    if(len < SECURID_MIN_PIN || len > SECURID_MAX_PIN) return STOKEN_ERR_BAD_LEN;
    for(int i = 0; i < len; i++)
        if(!is_digit(pin[i])) return STOKEN_ERR_GENERAL;
    return STOKEN_OK;
}

bool securid_pin_required(const SecuridToken* t) {
    return ((t->flags & FLD_PINMODE_MASK) >> FLD_PINMODE_SHIFT) >= 2;
}

bool securid_pass_required(const SecuridToken* t) {
    return !!(t->flags & FL_PASSPROT);
}

bool securid_devid_required(const SecuridToken* t) {
    return !!(t->flags & FL_SNPROT);
}

int securid_decrypt_pin(const char* enc_pin, const char* password, char* pin_out) {
    uint8_t buf[AES_BLOCK_SIZE + 1], iv[AES_BLOCK_SIZE], passhash[AES_BLOCK_SIZE];
    int rc = STOKEN_OK;

    if(strlen(enc_pin) != AES_BLOCK_SIZE * 2 * 2) return STOKEN_ERR_BAD_LEN;
    for(int i = 0; i < AES_BLOCK_SIZE * 4; i++)
        if(!is_xdigit(enc_pin[i])) return STOKEN_ERR_BAD_LEN;

    for(int i = 0; i < AES_BLOCK_SIZE; i++) {
        iv[i] = hex2byte(&enc_pin[i * 2]);
        buf[i] = hex2byte(&enc_pin[(i + AES_BLOCK_SIZE) * 2]);
    }

    securid_mac((const uint8_t*)password, (int)strlen(password), passhash);
    aes128_ecb_decrypt(passhash, buf, buf);

    for(int i = 0; i < AES_BLOCK_SIZE; i++)
        buf[i] ^= iv[i];
    buf[AES_BLOCK_SIZE] = 0;

    if(buf[AES_BLOCK_SIZE - 2] != 0 || buf[AES_BLOCK_SIZE - 1] != strlen((char*)buf) ||
       securid_pin_format_ok((char*)buf) != STOKEN_OK) {
        rc = STOKEN_ERR_GENERAL;
    } else {
        strcpy(pin_out, (char*)buf);
    }

    stc_memzero(buf, sizeof(buf));
    stc_memzero(passhash, sizeof(passhash));
    return rc;
}

/********************************************************************
 * rc file handling
 ********************************************************************/

/* copy [start, end) to dst, trimming whitespace, always NUL terminated */
static void copy_trimmed(char* dst, size_t dst_len, const char* start, const char* end) {
    size_t n;
    while(start < end && is_space(*start))
        start++;
    while(end > start && is_space(end[-1]))
        end--;
    n = (size_t)(end - start);
    if(n >= dst_len) n = dst_len - 1;
    memcpy(dst, start, n);
    dst[n] = 0;
}

static void parse_rcline(StokenRc* rc, const char* line, const char* end) {
    char key[16];
    const char* p = line;
    const char* key_end;
    const char* word_end;

    while(p < end && is_space(*p))
        p++;
    if(p == end || *p == '#') return; /* empty line or comment */

    key_end = p;
    while(key_end < end && !is_space(*key_end))
        key_end++;
    copy_trimmed(key, sizeof(key), p, key_end);

    /* single-word value */
    p = key_end;
    while(p < end && is_space(*p))
        p++;
    word_end = p;
    while(word_end < end && !is_space(*word_end))
        word_end++;

    if(ci_equal(key, "version")) {
        char tmp[8];
        copy_trimmed(tmp, sizeof(tmp), p, word_end);
        rc->version = 0;
        for(char* c = tmp; is_digit(*c); c++)
            rc->version = rc->version * 10 + (*c - '0');
    } else if(ci_equal(key, "token")) {
        copy_trimmed(rc->token, sizeof(rc->token), p, word_end);
    } else if(ci_equal(key, "pin")) {
        copy_trimmed(rc->pin, sizeof(rc->pin), p, word_end);
    } else if(ci_equal(key, "devid")) {
        copy_trimmed(rc->devid, sizeof(rc->devid), p, word_end);
    } else if(ci_equal(key, "nickname") || ci_equal(key, "name")) {
        /* free text: rest of the line */
        copy_trimmed(rc->nickname, sizeof(rc->nickname), p, end);
    } else if(ci_equal(key, "password")) {
        copy_trimmed(rc->password, sizeof(rc->password), p, end);
    }
    /* unknown keys are ignored, as in upstream stoken */
}

int stoken_rc_parse(const char* text, size_t len, StokenRc* rc) {
    const char* p = text;
    const char* end = text + len;

    memset(rc, 0, sizeof(*rc));
    while(p < end) {
        const char* eol = p;
        while(eol < end && *eol != '\n' && *eol != '\r' && *eol != 0)
            eol++;
        parse_rcline(rc, p, eol);
        if(eol < end && *eol == 0) break;
        p = eol + 1;
    }

    if(!rc->token[0]) return STOKEN_ERR_GENERAL;
    if(rc->version != 1) return STOKEN_ERR_RC_VERSION;
    return STOKEN_OK;
}

int stoken_rc_load(const StokenRc* rc, SecuridToken* t) {
    int ret = securid_parse_token_string(rc->token, t);
    if(ret != STOKEN_OK) return ret;

    ret = securid_decrypt_seed(t, rc->password, rc->devid);
    if(ret != STOKEN_OK) return ret;

    /* like upstream, the token PIN is only merged in for PIN-mode tokens */
    if(rc->pin[0] && securid_pin_required(t)) {
        if(securid_pin_format_ok(rc->pin) == STOKEN_OK) {
            strcpy(t->pin, rc->pin);
        } else if(strlen(rc->pin) == AES_BLOCK_SIZE * 4) {
            /* "stoken setpin" stores the PIN encrypted with the token password */
            if(!rc->password[0]) return STOKEN_ERR_MISSING_PASSWORD;
            if(securid_decrypt_pin(rc->pin, rc->password, t->pin) != STOKEN_OK)
                return STOKEN_ERR_BAD_PIN;
        } else {
            return STOKEN_ERR_BAD_PIN;
        }
    }

    /* the encrypted blob is no longer needed once the seed is recovered */
    stc_memzero(&t->v3, sizeof(t->v3));
    stc_memzero(t->enc_seed, sizeof(t->enc_seed));
    return STOKEN_OK;
}

const char* stoken_errstr(int err) {
    switch(err) {
    case STOKEN_OK:
        return "OK";
    case STOKEN_ERR_BAD_LEN:
        return "Bad token length";
    case STOKEN_ERR_TOKEN_VERSION:
        return "Unsupported token";
    case STOKEN_ERR_CHECKSUM_FAILED:
        return "Token checksum bad";
    case STOKEN_ERR_BAD_PASSWORD:
        return "Password too long";
    case STOKEN_ERR_MISSING_PASSWORD:
        return "Password required";
    case STOKEN_ERR_DECRYPT_FAILED:
        return "Wrong password";
    case STOKEN_ERR_BAD_DEVID:
        return "Wrong device ID";
    case STOKEN_ERR_NO_MEMORY:
        return "Out of memory";
    case STOKEN_ERR_FILE_READ:
        return "Can't read file";
    case STOKEN_ERR_MISSING_DEVID:
        return "Device ID required";
    case STOKEN_ERR_BAD_PIN:
        return "Bad PIN in file";
    case STOKEN_ERR_RC_VERSION:
        return "Need 'version 1'";
    default:
        return "Invalid token";
    }
}

/********************************************************************
 * Time
 ********************************************************************/

void stoken_utc_breakdown(int64_t utc, StokenUtcTime* out) {
    int64_t days = utc / 86400;
    int64_t secs = utc % 86400;
    if(secs < 0) {
        secs += 86400;
        days--;
    }
    out->hour = (int)(secs / 3600);
    out->minute = (int)((secs % 3600) / 60);
    out->second = (int)(secs % 60);

    /* civil_from_days, Howard Hinnant's algorithm */
    days += 719468;
    int64_t era = (days >= 0 ? days : days - 146096) / 146097;
    int64_t doe = days - era * 146097;
    int64_t yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    int64_t y = yoe + era * 400;
    int64_t doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    int64_t mp = (5 * doy + 2) / 153;
    int64_t d = doy - (153 * mp + 2) / 5 + 1;
    int64_t m = mp < 10 ? mp + 3 : mp - 9;
    out->year = (int)(y + (m <= 2));
    out->month = (int)m;
    out->day = (int)d;
}

void stc_memzero(void* p, size_t len) {
    volatile uint8_t* v = (volatile uint8_t*)p;
    while(len--)
        *v++ = 0;
}
