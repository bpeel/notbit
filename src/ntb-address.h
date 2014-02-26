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

#define NTB_ADDRESS_TAG_SIZE 32

void
ntb_address_encode(const struct ntb_address *address,
                   char *output);

bool
ntb_address_decode(struct ntb_address *address,
                   const char *address_string);

bool
ntb_address_equal(const struct ntb_address *a,
                  const struct ntb_address *b);

void
ntb_address_from_network_keys(struct ntb_address *address,
                              uint8_t version,
                              uint8_t stream,
                              const uint8_t *public_signing_key,
                              const uint8_t *public_encryption_key);

void
ntb_address_get_tag(const struct ntb_address *address,
                    uint8_t *tag,
                    uint8_t *tag_private_key);

#endif /* NTB_ADDRESS_H */
