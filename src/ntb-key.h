/*
 * Notbit - A Bitmessage client
 * Copyright (C) 2013  Neil Roberts
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
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

#define NTB_KEY_TAG_SIZE 32

struct ntb_key {
        struct ntb_ref_count ref_count;

        struct ntb_address address;
        uint8_t tag[NTB_KEY_TAG_SIZE];
        uint8_t tag_private_key[NTB_ECC_PRIVATE_KEY_SIZE];

        char *label;

        int nonce_trials_per_byte;
        int payload_length_extra_bytes;
        int64_t last_pubkey_send_time;

        EC_KEY *signing_key;
        EC_KEY *encryption_key;

        bool enabled;
        bool decoy;
};

struct ntb_key *
ntb_key_new(struct ntb_ecc *ecc,
            const char *label,
            uint64_t version,
            uint64_t stream,
            const uint8_t *private_signing_key,
            const uint8_t *private_encryption_key);

struct ntb_key *
ntb_key_new_with_public(struct ntb_ecc *ecc,
                        const char *label,
                        const struct ntb_address *address,
                        const uint8_t *private_signing_key,
                        const uint8_t *public_signing_key,
                        const uint8_t *private_encryption_key,
                        const uint8_t *public_encryption_key);

struct ntb_key *
ntb_key_ref(struct ntb_key *key);

struct ntb_key *
ntb_key_copy(struct ntb_key *key);

void
ntb_key_unref(struct ntb_key *key);

#endif /* NTB_KEY_H */
