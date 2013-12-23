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

#ifndef NTB_ECC_H
#define NTB_ECC_H

#include <stdint.h>
#include <stddef.h>
#include <openssl/ripemd.h>
#include <openssl/ec.h>

#include "ntb-buffer.h"

#define NTB_ECC_PRIVATE_KEY_SIZE 32
#define NTB_ECC_PUBLIC_KEY_SIZE 65 /* includes the 0x04 prefix */

struct ntb_ecc;

struct ntb_ecc *
ntb_ecc_new(void);

EC_POINT *
ntb_ecc_make_pub_key_point(struct ntb_ecc *ecc,
                           const uint8_t *private_key);

void
ntb_ecc_make_pub_key_bin(struct ntb_ecc *ecc,
                         const uint8_t *private_key,
                         uint8_t *public_key);

EC_KEY *
ntb_ecc_create_key(struct ntb_ecc *ecc,
                   const uint8_t *private_key);


EC_KEY *
ntb_ecc_create_key_with_public(struct ntb_ecc *ecc,
                               const uint8_t *private_key,
                               const uint8_t *public_key);

EC_KEY *
ntb_ecc_create_random_key(struct ntb_ecc *ecc);

void
ntb_ecc_get_pub_key(struct ntb_ecc *ecc,
                    EC_KEY *key,
                    uint8_t *public_key);

void
ntb_ecc_free(struct ntb_ecc *ecc);

void
ntb_ecc_encrypt_with_point(struct ntb_ecc *ecc,
                           const EC_POINT *public_key,
                           const uint8_t *data_in,
                           size_t data_in_length,
                           struct ntb_buffer *data_out);

bool
ntb_ecc_decrypt(struct ntb_ecc *ecc,
                EC_KEY *key,
                const uint8_t *data_in,
                size_t data_in_length,
                struct ntb_buffer *data_out);

#endif /* NTB_ECC_H */
