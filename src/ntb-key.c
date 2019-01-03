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

#include "config.h"

#include <string.h>
#include <openssl/obj_mac.h>
#include <openssl/ecdh.h>
#include <assert.h>

#include "ntb-key.h"
#include "ntb-util.h"
#include "ntb-buffer.h"
#include "ntb-proto.h"

static void
generate_ripe(struct ntb_ecc *ecc,
              struct ntb_key *key)
{
        SHA512_CTX sha_ctx;
        uint8_t public_key[NTB_ECC_PUBLIC_KEY_SIZE];
        uint8_t sha_hash[SHA512_DIGEST_LENGTH];

        SHA512_Init(&sha_ctx);

        ntb_ecc_get_pub_key(ecc, key->signing_key, public_key);
        SHA512_Update(&sha_ctx, public_key, NTB_ECC_PUBLIC_KEY_SIZE);

        ntb_ecc_get_pub_key(ecc, key->encryption_key, public_key);
        SHA512_Update(&sha_ctx, public_key, NTB_ECC_PUBLIC_KEY_SIZE);

        SHA512_Final(sha_hash, &sha_ctx);

        RIPEMD160(sha_hash, SHA512_DIGEST_LENGTH, key->address.ripe);
}

struct ntb_key *
ntb_key_new(struct ntb_ecc *ecc,
            const struct ntb_key_params *params)
{
        struct ntb_key *key = ntb_alloc(sizeof *key);
        const uint8_t *public_signing_key;
        const uint8_t *public_encryption_key;
        const uint8_t *private_signing_key;
        const uint8_t *private_encryption_key;

        /* At least one of NTB_KEY_PARAM_PRIVATE/PUBLIC_KEYS must be
         * provided */
        assert((params->flags & (NTB_KEY_PARAM_PRIVATE_KEYS |
                                 NTB_KEY_PARAM_PUBLIC_KEYS)) != 0);

        ntb_ref_count_init(&key->ref_count);

        if ((params->flags & NTB_KEY_PARAM_LABEL))
                key->label = ntb_strdup(params->label);
        else
                key->label = ntb_strdup("");

        if ((params->flags & NTB_KEY_PARAM_VERSION))
                key->address.version = params->version;
        else
                key->address.version = 4;

        if ((params->flags & NTB_KEY_PARAM_STREAM))
                key->address.stream = params->stream;
        else
                key->address.stream = 1;

        if ((params->flags & NTB_KEY_PARAM_POW_DIFFICULTY)) {
                key->pow_per_byte = params->pow_per_byte;
                key->pow_extra_bytes = params->pow_extra_bytes;
        } else {
                key->pow_per_byte = NTB_PROTO_MIN_POW_PER_BYTE;
                key->pow_extra_bytes = NTB_PROTO_MIN_POW_EXTRA_BYTES;
        }

        if ((params->flags & NTB_KEY_PARAM_LAST_PUBKEY_SEND_TIME))
                key->last_pubkey_send_time = params->last_pubkey_send_time;
        else
                key->last_pubkey_send_time = 0;

        if ((params->flags & NTB_KEY_PARAM_ENABLED))
                key->enabled = params->enabled;
        else
                key->enabled = true;

        if ((params->flags & NTB_KEY_PARAM_DECOY))
                key->decoy = params->decoy;
        else
                key->decoy = false;

        if ((params->flags & NTB_KEY_PARAM_PRIVATE_KEYS)) {
                private_signing_key = params->private_signing_key;
                private_encryption_key = params->private_encryption_key;
        } else {
                private_signing_key = NULL;
                private_encryption_key = NULL;
        }

        if ((params->flags & NTB_KEY_PARAM_PUBLIC_KEYS)) {
                public_signing_key = params->public_signing_key;
                public_encryption_key = params->public_encryption_key;

                key->signing_key =
                        ntb_ecc_create_key_with_public(ecc,
                                                       private_signing_key,
                                                       public_signing_key);
                key->encryption_key =
                        ntb_ecc_create_key_with_public(ecc,
                                                       private_encryption_key,
                                                       public_encryption_key);
        } else {
                key->signing_key =
                        ntb_ecc_create_key(ecc, private_signing_key);
                key->encryption_key =
                        ntb_ecc_create_key(ecc, private_encryption_key);
        }

        if (private_encryption_key)
                EC_KEY_set_method(key->encryption_key, EC_KEY_OpenSSL());

        if ((params->flags & NTB_KEY_PARAM_RIPE)) {
                memcpy(key->address.ripe,
                       params->ripe,
                       RIPEMD160_DIGEST_LENGTH);
        } else {
                generate_ripe(ecc, key);
        }

        ntb_address_get_tag(&key->address, key->tag, key->tag_private_key);

        return key;
}

struct ntb_key *
ntb_key_copy(struct ntb_key *key)
{
        key = ntb_memdup(key, sizeof *key);

        ntb_ref_count_init(&key->ref_count);

        key->label = ntb_strdup(key->label);

        key->signing_key = EC_KEY_dup(key->signing_key);
        assert(key->signing_key);
        key->encryption_key = EC_KEY_dup(key->encryption_key);
        assert(key->encryption_key);

        return key;
}

struct ntb_key *
ntb_key_ref(struct ntb_key *key)
{
        ntb_ref_count_ref(&key->ref_count);

        return key;
}

void
ntb_key_unref(struct ntb_key *key)
{
        if (ntb_ref_count_unref(&key->ref_count) <= 1) {
                EC_KEY_free(key->signing_key);
                EC_KEY_free(key->encryption_key);
                ntb_ref_count_destroy(&key->ref_count);
                ntb_free(key->label);
                ntb_free(key);
        }
}

bool
ntb_key_has_private(struct ntb_key *key)
{
        return (EC_KEY_get0_private_key(key->signing_key) &&
                EC_KEY_get0_private_key(key->encryption_key));
}
