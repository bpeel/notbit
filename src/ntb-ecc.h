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
ntb_ecc_encrypt_with_point_begin(struct ntb_ecc *ecc,
                                 const EC_POINT *public_key,
                                 struct ntb_buffer *data_out);

void
ntb_ecc_encrypt_update(struct ntb_ecc *ecc,
                       const uint8_t *data_in,
                       size_t data_in_length,
                       struct ntb_buffer *data_out);

void
ntb_ecc_encrypt_end(struct ntb_ecc *ecc,
                    struct ntb_buffer *data_out);

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
