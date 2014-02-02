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

#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <assert.h>
#include <string.h>

#include "ntb-address.h"
#include "ntb-base58.h"
#include "ntb-buffer.h"
#include "ntb-proto.h"
#include "ntb-ecc.h"

static void
calc_checksum(uint8_t version,
              uint8_t stream,
              const uint8_t *ripe,
              size_t ripe_length,
              uint8_t *output)
{
        SHA512_CTX sha_ctx;
        uint8_t hash1[SHA512_DIGEST_LENGTH];
        uint8_t hash2[SHA512_DIGEST_LENGTH];

        SHA512_Init(&sha_ctx);
        SHA512_Update(&sha_ctx, &version, 1);
        SHA512_Update(&sha_ctx, &stream, 1);
        SHA512_Update(&sha_ctx, ripe, ripe_length);
        SHA512_Final(hash1, &sha_ctx);

        SHA512_Init(&sha_ctx);
        SHA512_Update(&sha_ctx, hash1, SHA512_DIGEST_LENGTH);
        SHA512_Final(hash2, &sha_ctx);

        memcpy(output, hash2, 4);
}

void
ntb_address_encode(const struct ntb_address *address,
                   char *output)
{
        uint8_t bin_address[1 + 1 + RIPEMD160_DIGEST_LENGTH + 4];
        const uint8_t *ripe = address->ripe;
        uint8_t *p;
        int ripe_length;
        int max_trim;
        size_t address_length;
        uint8_t checksum[4];
        int i;

        ripe_length = RIPEMD160_DIGEST_LENGTH;

        if (address->version >= 4)
                max_trim = RIPEMD160_DIGEST_LENGTH;
        else
                max_trim = 2;

        for (i = 0; i < max_trim && *ripe == 0; i++) {
                ripe++;
                ripe_length--;
        }

        calc_checksum(address->version,
                      address->stream,
                      ripe,
                      ripe_length,
                      checksum);

        p = bin_address;
        *(p++) = address->version;
        *(p++) = address->stream;
        memcpy(p, ripe, ripe_length);
        p += ripe_length;
        memcpy(p, checksum, sizeof checksum);
        p += 4;

        assert(p - bin_address <= sizeof bin_address);

        memcpy(output, "BM-", 3);
        address_length = ntb_base58_encode(bin_address,
                                           p - bin_address,
                                           output + 3);
        output[address_length + 3] = '\0';
}

bool
ntb_address_decode(struct ntb_address *address,
                   const char *address_string)
{
        uint8_t bin_address[1 + 1 + RIPEMD160_DIGEST_LENGTH + 4];
        uint8_t checksum[4];
        ssize_t bin_address_length;
        const uint8_t *ripe_start = bin_address + 1 + 1;
        ssize_t ripe_length;

        if (!strncmp(address_string, "BM-", 3))
                address_string += 3;

        bin_address_length = ntb_base58_decode(address_string,
                                               strlen(address_string),
                                               bin_address,
                                               sizeof bin_address);
        if (bin_address_length == -1)
                return false;

        ripe_length = bin_address_length - 1 - 1 - 4;

        if (ripe_length < 0)
                return false;

        calc_checksum(bin_address[0],
                      bin_address[1],
                      ripe_start, ripe_length,
                      checksum);

        if (memcmp(checksum, ripe_start + ripe_length, 4))
                return false;

        memset(address->ripe, 0, RIPEMD160_DIGEST_LENGTH - ripe_length);
        memcpy(address->ripe + RIPEMD160_DIGEST_LENGTH - ripe_length,
               ripe_start,
               ripe_length);
        address->version = bin_address[0];
        address->stream = bin_address[1];

        return true;
}

bool
ntb_address_equal(const struct ntb_address *a,
                  const struct ntb_address *b)
{
        return (a->version == b->version &&
                a->stream == b->stream &&
                !memcmp(a->ripe, b->ripe, RIPEMD160_DIGEST_LENGTH));
}

void
ntb_address_from_network_keys(struct ntb_address *address,
                              uint8_t version,
                              uint8_t stream,
                              const uint8_t *public_signing_key,
                              const uint8_t *public_encryption_key)
{
        SHA512_CTX sha_ctx;
        uint8_t sha_hash[SHA_DIGEST_LENGTH];
        uint8_t key_prefix = 0x04;

        address->version = version;
        address->stream = stream;

        /* The keys from the network commands don't include the 0x04
         * prefix so we have to separately add it in */
        SHA512_Init(&sha_ctx);
        SHA512_Update(&sha_ctx, &key_prefix, 1);
        SHA512_Update(&sha_ctx,
                      public_signing_key,
                      NTB_ECC_PUBLIC_KEY_SIZE - 1);
        SHA512_Update(&sha_ctx, &key_prefix, 1);
        SHA512_Update(&sha_ctx,
                      public_encryption_key,
                      NTB_ECC_PUBLIC_KEY_SIZE - 1);
        SHA512_Final(sha_hash, &sha_ctx);

        RIPEMD160(sha_hash, SHA512_DIGEST_LENGTH, address->ripe);
}

void
ntb_address_get_tag(const struct ntb_address *address,
                    uint8_t *tag,
                    uint8_t *tag_private_key)
{
        struct ntb_buffer buffer;
        uint8_t hash1[SHA512_DIGEST_LENGTH];
        uint8_t hash2[SHA512_DIGEST_LENGTH];
        SHA512_CTX sha_ctx;

        ntb_buffer_init(&buffer);
        ntb_proto_add_var_int(&buffer, address->version);
        ntb_proto_add_var_int(&buffer, address->stream);

        SHA512_Init(&sha_ctx);
        SHA512_Update(&sha_ctx, buffer.data, buffer.length);

        ntb_buffer_destroy(&buffer);

        SHA512_Update(&sha_ctx, address->ripe, RIPEMD160_DIGEST_LENGTH);
        SHA512_Final(hash1, &sha_ctx);

        SHA512_Init(&sha_ctx);
        SHA512_Update(&sha_ctx, hash1, SHA512_DIGEST_LENGTH);
        SHA512_Final(hash2, &sha_ctx);

        if (tag) {
                memcpy(tag,
                       hash2 + NTB_ECC_PRIVATE_KEY_SIZE,
                       NTB_ADDRESS_TAG_SIZE);
        }
        if (tag_private_key) {
                memcpy(tag_private_key, hash2, NTB_ECC_PRIVATE_KEY_SIZE);
        }
}
