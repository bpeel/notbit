/*
 * Notbit - A Bitmessage client
 * Copyright (C) 2013  Neil Roberts
 *
 * Permission to use, copy, modify, distribute, and sell this software and its
 * documentation for any purpose is hereby granted without fee, provided that
 * the above copyright notice appear in all copies and that both that copyright
 * notice and this permission notice appear in supporting documentation, and
 * that the name of the copyright holders not be used in advertising or
 * publicity pertaining to distribution of the software without specific,
 * written prior permission.  The copyright holders make no representations
 * about the suitability of this software for any purpose.  It is provided "as
 * is" without express or implied warranty.
 *
 * THE COPYRIGHT HOLDERS DISCLAIM ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO
 * EVENT SHALL THE COPYRIGHT HOLDERS BE LIABLE FOR ANY SPECIAL, INDIRECT OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE,
 * DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
 * TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE
 * OF THIS SOFTWARE.
 */

#ifndef NTB_PROTO_H
#define NTB_PROTO_H

#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>
#include <openssl/sha.h>
#include <openssl/ecdsa.h>

#include "ntb-buffer.h"
#include "ntb-netaddress.h"

extern struct ntb_error_domain
ntb_proto_error;

enum ntb_proto_error {
        NTB_PROTO_ERROR_PROTOCOL
};

enum ntb_proto_inv_type {
        NTB_PROTO_INV_TYPE_GETPUBKEY,
        NTB_PROTO_INV_TYPE_PUBKEY,
        NTB_PROTO_INV_TYPE_MSG,
        NTB_PROTO_INV_TYPE_BROADCAST
};

enum ntb_proto_argument {
        NTB_PROTO_ARGUMENT_8,
        NTB_PROTO_ARGUMENT_16,
        NTB_PROTO_ARGUMENT_32,
        NTB_PROTO_ARGUMENT_64,
        NTB_PROTO_ARGUMENT_BOOL,
        NTB_PROTO_ARGUMENT_VAR_INT,
        NTB_PROTO_ARGUMENT_NETADDRESS,
        NTB_PROTO_ARGUMENT_VAR_STR,
        NTB_PROTO_ARGUMENT_VAR_INT_LIST,
        NTB_PROTO_ARGUMENT_END
};

struct ntb_proto_object_header {
        uint64_t nonce;
        int64_t expires_time;
        uint32_t type;
        uint64_t version;
        uint64_t stream;
};

struct ntb_proto_var_str {
        uint64_t length;
        const char *data;
};

struct ntb_proto_var_int_list {
        uint64_t n_ints;
        const uint8_t *values;
};

struct ntb_proto_decrypted_msg {
        const uint8_t *sender_signing_key;
        const uint8_t *sender_encryption_key;
        uint64_t sender_address_version;
        uint64_t sender_stream_number;
        uint32_t sender_behaviors;
        uint64_t pow_per_byte;
        uint64_t pow_extra_bytes;
        const uint8_t *destination_ripe;
        uint64_t encoding;
        const uint8_t *message, *ack, *sig;
        uint64_t message_length, ack_length, sig_length;
        size_t signed_data_length;
};

struct ntb_proto_pubkey {
        struct ntb_proto_object_header header;

        uint32_t behaviours;

        const uint8_t *public_signing_key;
        const uint8_t *public_encryption_key;

        uint64_t pow_per_byte;
        uint64_t pow_extra_bytes;

        uint64_t signature_length;
        const uint8_t *signature;

        size_t signed_data_length;
        const uint8_t *signed_data;

        const uint8_t *tag;

        size_t encrypted_data_length;
        const uint8_t *encrypted_data;
};

#define NTB_PROTO_HEADER_SIZE (4 + 12 + 4 + 4)

#define NTB_PROTO_VERSION UINT32_C(3)

#define NTB_PROTO_NETWORK_NODE UINT64_C(1)
#define NTB_PROTO_SERVICES (NTB_PROTO_NETWORK_NODE)

/* The hashes in Bitmessage are an SHA512 digest but only the first 32
 * bytes are used */
#define NTB_PROTO_HASH_LENGTH (SHA512_DIGEST_LENGTH / 2)

#define NTB_PROTO_MIN_POW_PER_BYTE 1000
#define NTB_PROTO_MIN_POW_EXTRA_BYTES 1000

/* In addition to the maximum age of an object defined by the
 * protocol, we won't delete objects on disk for this amount of extra
 * time so that we can cope with clocks that are a bit different and
 * won't request objects from peers */
#define NTB_PROTO_EXTRA_AGE (6 * 60 * 60 /* 6 hours */)

#define NTB_PROTO_MAX_AGE ((28 * 24 + 3) * 3600 /* 28 days and 3 hours */)

#define NTB_PROTO_DEFAULT_PORT 8444

/* We send acknowledgements */
#define NTB_PROTO_PUBKEY_BEHAVIORS UINT32_C(0x00000001)

#define NTB_PROTO_ACKDATA_SIZE 32

/* Give pubkey objects an expiry time of 28 days. This is what
 * PyBitMessage does. */
#define NTB_PROTO_PUBKEY_EXPIRY_TIME (28 * 24 * 60 * 60)
/* 7 days for messages. FIXME: PyBitMessage does something more
 * complicated and doubles the time at each retry. */
#define NTB_PROTO_MSG_EXPIRY_TIME (7 * 24 * 60 * 60)
/* 5 days for getpubkey. FIXME: PyBitMessage does something more
 * complicated and doubles the time at each retry. */
#define NTB_PROTO_GETPUBKEY_EXPIRY_TIME (5 * 24 * 60 * 60)

extern const uint8_t
ntb_proto_magic[4];

void
ntb_proto_double_hash(const void *data,
                      int length,
                      uint8_t *hash);

void
ntb_proto_address_hash(const void *data,
                       int length,
                       uint8_t *hash);

bool
ntb_proto_check_command_string(const uint8_t *command_string);

static inline uint8_t
ntb_proto_get_8(const uint8_t *p)
{
        return *p;
}

uint16_t
ntb_proto_get_16(const uint8_t *p);

uint32_t
ntb_proto_get_32(const uint8_t *p);

uint64_t
ntb_proto_get_64(const uint8_t *p);

bool
ntb_proto_get_var_int(const uint8_t **p_ptr,
                      uint32_t *length_ptr,
                      uint64_t *result);

bool
ntb_proto_get_var_str(const uint8_t **p_ptr,
                      uint32_t *length_ptr,
                      struct ntb_proto_var_str *result);

bool
ntb_proto_get_var_int_list(const uint8_t **p_ptr,
                           uint32_t *length_ptr,
                           struct ntb_proto_var_int_list *result);

ssize_t
ntb_proto_get_command_va_list(const uint8_t *data,
                              uint32_t length,
                              va_list ap);

ssize_t
ntb_proto_get_command(const uint8_t *data,
                      uint32_t length,
                      ...);

bool
ntb_proto_get_decrypted_msg(const uint8_t *data,
                            uint32_t length,
                            struct ntb_proto_decrypted_msg *msg);

bool
ntb_proto_get_pubkey(bool decrypted,
                     const uint8_t *data,
                     uint32_t length,
                     struct ntb_proto_pubkey *pubkey);

ssize_t
ntb_proto_get_object_header(const uint8_t *data,
                            uint32_t length,
                            struct ntb_proto_object_header *header);

static inline void
ntb_proto_add_8(struct ntb_buffer *buf,
                uint8_t value)
{
        ntb_buffer_append_c(buf, value);
}

static inline void
ntb_proto_add_16(struct ntb_buffer *buf,
                 uint16_t value)
{
        value = NTB_UINT16_TO_BE(value);
        ntb_buffer_append(buf, (uint8_t *) &value, sizeof value);
}

static inline void
ntb_proto_add_32(struct ntb_buffer *buf,
                 uint32_t value)
{
        value = NTB_UINT32_TO_BE(value);
        ntb_buffer_append(buf, (uint8_t *) &value, sizeof value);
}

static inline void
ntb_proto_add_64(struct ntb_buffer *buf,
                 uint64_t value)
{
        value = NTB_UINT64_TO_BE(value);
        ntb_buffer_append(buf, (uint8_t *) &value, sizeof value);
}

static inline void
ntb_proto_add_bool(struct ntb_buffer *buf,
                   int value)
{
        ntb_proto_add_8(buf, !!value);
}

void
ntb_proto_add_var_int(struct ntb_buffer *buf,
                      uint64_t value);

void
ntb_proto_add_netaddress(struct ntb_buffer *buf,
                         const struct ntb_netaddress *address);

void
ntb_proto_add_var_str(struct ntb_buffer *buf,
                      const char *str);

void
ntb_proto_add_public_key(struct ntb_buffer *buf,
                         const EC_KEY *key);

void
ntb_proto_begin_command(struct ntb_buffer *buf,
                        const char *command);

void
ntb_proto_end_command(struct ntb_buffer *buf,
                      size_t command_start);

void
ntb_proto_add_command(struct ntb_buffer *buf,
                      const char *command,
                      ...);

void
ntb_proto_add_command_va_list(struct ntb_buffer *buf,
                              const char *command,
                              va_list ap);

#endif /* NTB_PROTO_H */
