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

#ifndef NTB_KEY_H
#define NTB_KEY_H

#include <stdint.h>
#include <stddef.h>
#include <openssl/ripemd.h>
#include <openssl/ec.h>

#include "ntb-proto.h"
#include "ntb-ref-count.h"
#include "ntb-ecc.h"
#include "ntb-address.h"

/* Private keys are immutable and reference counted. The ref-count is
 * thread-safe so that the key can be passed off to the store thread
 * to be written to disk. */

struct ntb_key {
        struct ntb_ref_count ref_count;

        struct ntb_address address;
        uint8_t tag[NTB_ADDRESS_TAG_SIZE];
        uint8_t tag_private_key[NTB_ECC_PRIVATE_KEY_SIZE];

        char *label;

        int pow_per_byte;
        int pow_extra_bytes;
        int64_t last_pubkey_send_time;

        EC_KEY *signing_key;
        EC_KEY *encryption_key;

        bool enabled;
        bool decoy;
};

enum ntb_key_param {
        NTB_KEY_PARAM_LABEL = (1 << 0),
        NTB_KEY_PARAM_VERSION = (1 << 1),
        NTB_KEY_PARAM_STREAM = (1 << 2),
        NTB_KEY_PARAM_PRIVATE_KEYS = (1 << 3),
        NTB_KEY_PARAM_PUBLIC_KEYS = (1 << 4),
        NTB_KEY_PARAM_POW_DIFFICULTY = (1 << 5),
        NTB_KEY_PARAM_LAST_PUBKEY_SEND_TIME = (1 << 6),
        NTB_KEY_PARAM_ENABLED = (1 << 7),
        NTB_KEY_PARAM_DECOY = (1 << 8),
        NTB_KEY_PARAM_RIPE = (1 << 9)
};

/* Optional parameters for ntb_key_new */
struct ntb_key_params {
        /* Flags of parameters that are filled in. Everything is
         * optional except that at least one of
         * NTB_KEY_PARAM_PRIVATE_KEYS and NTB_KEY_PARAM_PUBLIC_KEYS
         * must be provided. Any parameters that don't have the
         * corresponding flag set will be set to the default */
        enum ntb_key_param flags;

        /* NTB_KEY_PARAM_LABEL */
        const char *label;

        /* NTB_KEY_PARAM_VERSION */
        uint64_t version;
        /* NTB_KEY_PARAM_STREAM */
        uint64_t stream;

        /* NTB_KEY_PARAM_PRIVATE_KEYS */
        const uint8_t *private_signing_key;
        const uint8_t *private_encryption_key;

        /* NTB_KEY_PARAM_PUBLIC_KEYS */
        const uint8_t *public_signing_key;
        const uint8_t *public_encryption_key;

        /* NTB_KEY_PARAM_POW_DIFFICULTY */
        int pow_per_byte;
        int pow_extra_bytes;

        /* NTB_KEY_PARAM_RIPE */
        const uint8_t *ripe;

        /* NTB_KEY_PARAM_LAST_PUBKEY_SEND_TIME */
        int64_t last_pubkey_send_time;

        /* NTB_KEY_PARAM_ENABLED */
        bool enabled;

        /* NTB_KEY_PARAM_DECOY */
        bool decoy;
};

struct ntb_key *
ntb_key_new(struct ntb_ecc *ecc,
            const struct ntb_key_params *params);

struct ntb_key *
ntb_key_ref(struct ntb_key *key);

struct ntb_key *
ntb_key_copy(struct ntb_key *key);

void
ntb_key_unref(struct ntb_key *key);

bool
ntb_key_has_private(struct ntb_key *key);

#endif /* NTB_KEY_H */
