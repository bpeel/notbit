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
generate_tag(struct ntb_key *key)
{
        struct ntb_buffer buffer;
        uint8_t hash1[SHA512_DIGEST_LENGTH];
        uint8_t hash2[SHA512_DIGEST_LENGTH];
        SHA512_CTX sha_ctx;

        ntb_buffer_init(&buffer);
        ntb_proto_add_var_int(&buffer, key->address.version);
        ntb_proto_add_var_int(&buffer, key->address.stream);

        SHA512_Init(&sha_ctx);
        SHA512_Update(&sha_ctx, buffer.data, buffer.length);

        ntb_buffer_destroy(&buffer);

        SHA512_Update(&sha_ctx, key->address.ripe, RIPEMD160_DIGEST_LENGTH);
        SHA512_Final(hash1, &sha_ctx);

        SHA512_Init(&sha_ctx);
        SHA512_Update(&sha_ctx, hash1, SHA512_DIGEST_LENGTH);
        SHA512_Final(hash2, &sha_ctx);

        memcpy(key->tag_private_key, hash2, NTB_ECC_PRIVATE_KEY_SIZE);
        memcpy(key->tag, hash2 + NTB_ECC_PRIVATE_KEY_SIZE, NTB_KEY_TAG_SIZE);
}

static struct ntb_key *
new_key(const char *label,
        uint64_t version,
        uint64_t stream,
        EC_KEY *signing_key,
        EC_KEY *encryption_key)
{
        struct ntb_key *key = ntb_alloc(sizeof *key);

        ntb_ref_count_init(&key->ref_count);

        key->label = ntb_strdup(label);
        key->address.version = version;
        key->address.stream = stream;
        key->nonce_trials_per_byte = NTB_PROTO_MIN_NONCE_TRIALS_PER_BYTE;
        key->payload_length_extra_bytes = NTB_PROTO_MIN_EXTRA_BYTES;
        key->last_pubkey_send_time = 0;
        key->enabled = true;
        key->decoy = false;

        key->signing_key = signing_key;
        key->encryption_key = encryption_key;

        return key;
}

struct ntb_key *
ntb_key_new_with_public(struct ntb_ecc *ecc,
                        const char *label,
                        const struct ntb_address *address,
                        const uint8_t *private_signing_key,
                        const uint8_t *public_signing_key,
                        const uint8_t *private_encryption_key,
                        const uint8_t *public_encryption_key)
{
        struct ntb_key *key;
        EC_KEY *signing_key;
        EC_KEY *encryption_key;

        signing_key = ntb_ecc_create_key_with_public(ecc,
                                                     private_signing_key,
                                                     public_signing_key);
        encryption_key = ntb_ecc_create_key_with_public(ecc,
                                                        private_encryption_key,
                                                        public_encryption_key);

        key = new_key(label,
                      address->version,
                      address->stream,
                      signing_key,
                      encryption_key);

        memcpy(key->address.ripe, address->ripe, RIPEMD160_DIGEST_LENGTH);

        generate_tag(key);

        return key;
}

struct ntb_key *
ntb_key_new(struct ntb_ecc *ecc,
            const char *label,
            uint64_t version,
            uint64_t stream,
            const uint8_t *private_signing_key,
            const uint8_t *private_encryption_key)
{
        struct ntb_key *key;
        EC_KEY *signing_key;
        EC_KEY *encryption_key;
        SHA512_CTX sha_ctx;
        uint8_t public_key[NTB_ECC_PUBLIC_KEY_SIZE];
        uint8_t sha_hash[SHA_DIGEST_LENGTH];

        signing_key = ntb_ecc_create_key(ecc, private_signing_key);
        encryption_key = ntb_ecc_create_key(ecc, private_encryption_key);

        ECDH_set_method(encryption_key, ECDH_OpenSSL());

        key = new_key(label,
                      version,
                      stream,
                      signing_key,
                      encryption_key);

        SHA512_Init(&sha_ctx);

        ntb_ecc_get_pub_key(ecc, signing_key, public_key);
        SHA512_Update(&sha_ctx, public_key, NTB_ECC_PUBLIC_KEY_SIZE);

        ntb_ecc_get_pub_key(ecc, encryption_key, public_key);
        SHA512_Update(&sha_ctx, public_key, NTB_ECC_PUBLIC_KEY_SIZE);

        SHA512_Final(sha_hash, &sha_ctx);

        RIPEMD160(sha_hash, SHA512_DIGEST_LENGTH, key->address.ripe);

        generate_tag(key);

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
