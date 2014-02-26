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

#ifndef NTB_KEYRING_H
#define NTB_KEYRING_H

#include <stdbool.h>
#include <stdint.h>

#include "ntb-network.h"
#include "ntb-key.h"
#include "ntb-address.h"
#include "ntb-error.h"

struct ntb_keyring;

struct ntb_keyring_cookie;

extern struct ntb_error_domain
ntb_keyring_error;

enum ntb_keyring_error {
        NTB_KEYRING_ERROR_UNKNOWN_FROM_ADDRESS
};

typedef void
(* ntb_keyring_create_key_func)(struct ntb_key *key,
                                void *user_data);

struct ntb_keyring *
ntb_keyring_new(struct ntb_network *nw);

void
ntb_keyring_start(struct ntb_keyring *keyring);

void
ntb_keyring_load_store(struct ntb_keyring *keyring);

bool
ntb_keyring_send_message(struct ntb_keyring *keyring,
                         const struct ntb_address *from_address,
                         const struct ntb_address *to_addresses,
                         int n_to_addresses,
                         int content_encoding,
                         struct ntb_blob *content,
                         struct ntb_error **error);

struct ntb_keyring_cookie *
ntb_keyring_create_key(struct ntb_keyring *keyring,
                       const struct ntb_key_params *params,
                       int leading_zeroes,
                       ntb_keyring_create_key_func func,
                       void *user_data);

void
ntb_keyring_cancel_task(struct ntb_keyring_cookie *cookie);

void
ntb_keyring_free(struct ntb_keyring *crypto);

#endif /* NTB_KEYRING_H */
