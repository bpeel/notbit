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
#include <assert.h>
#include <string.h>

#include "ntb-pow.h"
#include "ntb-util.h"

bool
ntb_pow_check(const uint8_t *payload,
              size_t length,
              int payload_extra_bytes,
              int average_trials_per_byte)
{
        uint8_t initial_hash[8 + SHA512_DIGEST_LENGTH];
        uint8_t hash1[SHA512_DIGEST_LENGTH];
        uint8_t hash2[SHA512_DIGEST_LENGTH];
        uint64_t pow_value, target;
        uint64_t high, low;

        assert(length >= 8);

        /* Initial hash is nonce + hash(rest of the data) */
        memcpy(initial_hash, payload, 8);
        SHA512(payload + 8, length - 8, initial_hash + 8);

        /* Get the result hash into hash2 */
        SHA512(initial_hash, sizeof initial_hash, hash1);
        SHA512(hash1, sizeof hash1, hash2);

        /* The POW value is the first 8 bytes of that as a big-endian
         * number */
        memcpy(&pow_value, hash2, sizeof pow_value);
        pow_value = NTB_UINT64_FROM_BE(pow_value);

        target = ((length + (uint64_t) payload_extra_bytes) *
                  average_trials_per_byte);

        /* We need to divide 2⁶⁴ by target. We obviously can't do that
         * with a simple division with a 64-bit representation. This
         * tries to do it in a couple of steps */
        high = (UINT64_C(1) << 32) / target;
        low = (((UINT64_C(1) << 32) % target) << 32) / target;

        target = (high << 32) | low;

        return pow_value <= target;
}
