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

#ifndef NTB_ADDRESS_H
#define NTB_ADDRESS_H

#include <stdint.h>
#include <stdbool.h>
#include <openssl/ripemd.h>

struct ntb_address {
        uint8_t version;
        uint8_t stream;
        uint8_t ripe[RIPEMD160_DIGEST_LENGTH];
};

/* Maximum length that an encoded BitMessage address can be */
/* The largest number in hex is:
 *   0xff - The maximum version number
 *   0xff - The maximum stream number
 *   0xff × 20 - The ripe
 *   0xff × 4 - The checksum
 *
 * In base58 that is 8qfKFDmPNA1uDdWpLJyhogk4u4W7taoE15Pc
 * With three characters for the "BM-" prefix that makes 39
 */
#define NTB_ADDRESS_MAX_LENGTH 39

void
ntb_address_encode(const struct ntb_address *address,
                   char *output);

bool
ntb_address_decode(struct ntb_address *address,
                   const char *address_string);

#endif /* NTB_ADDRESS_H */
