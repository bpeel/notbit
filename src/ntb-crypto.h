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

#ifndef NTB_CRYPTO_H
#define NTB_CRYPTO_H

#include <stdbool.h>
#include <stdint.h>

#include "ntb-error.h"
#include "ntb-key.h"
#include "ntb-blob.h"

struct ntb_crypto;

struct ntb_crypto_cookie;

typedef void
(* ntb_crypto_create_key_func)(struct ntb_key *key,
                               void *user_data);

typedef void
(* ntb_crypto_create_pubkey_blob_func)(struct ntb_blob *blob,
                                       void *user_data);

struct ntb_crypto *
ntb_crypto_new(void);

struct ntb_crypto_cookie *
ntb_crypto_create_key(struct ntb_crypto *crypto,
                      const char *label,
                      int leading_zeroes,
                      ntb_crypto_create_key_func callback,
                      void *user_data);

struct ntb_crypto_cookie *
ntb_crypto_create_pubkey_blob(struct ntb_crypto *crypto,
                              struct ntb_key *key,
                              ntb_crypto_create_pubkey_blob_func callback,
                              void *user_data);

void
ntb_crypto_cancel_task(struct ntb_crypto_cookie *cookie);

void
ntb_crypto_free(struct ntb_crypto *crypto);

#endif /* NTB_CRYPTO_H */
