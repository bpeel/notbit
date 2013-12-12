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

#include "ntb-key.h"
#include "ntb-util.h"

struct ntb_key *
ntb_key_new(const uint8_t *address,
            const uint8_t *private_signing_key,
            const uint8_t *public_signing_key,
            const uint8_t *private_encryption_key,
            const uint8_t *public_encryption_key)
{
        struct ntb_key *key = ntb_alloc(sizeof *key);

        ntb_ref_count_init(&key->ref_count);

        memcpy(key->address, address, RIPEMD160_DIGEST_LENGTH);

        memcpy(key->private_signing_key,
               private_signing_key,
               NTB_KEY_PRIVATE_SIZE);
        memcpy(key->public_signing_key,
               public_signing_key,
               NTB_KEY_PUBLIC_SIZE);

        memcpy(key->private_encryption_key,
               private_encryption_key,
               NTB_KEY_PRIVATE_SIZE);
        memcpy(key->public_encryption_key,
               public_encryption_key,
               NTB_KEY_PUBLIC_SIZE);

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
                ntb_ref_count_destroy(&key->ref_count);
                ntb_free(key);
        }
}
