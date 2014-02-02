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
#include "ntb-address.h"

struct ntb_crypto;

struct ntb_crypto_cookie;

typedef void
(* ntb_crypto_create_key_func)(struct ntb_key *key,
                               void *user_data);

typedef void
(* ntb_crypto_create_pubkey_blob_func)(struct ntb_blob *blob,
                                       void *user_data);

typedef void
(* ntb_crypto_create_msg_blob_func)(struct ntb_blob *blob,
                                    void *user_data);

/* If the decryption failed, the key and blob will be NULL. The blob
 * will have the msg type but it isn't a real msg and instead it
 * contains the decrypted data */
typedef void
(* ntb_crypto_decrypt_msg_func)(struct ntb_key *key,
                                struct ntb_blob *blob,
                                void *user_data);

typedef void
(* ntb_crypto_generate_ackdata_func)(const uint8_t *ackdata,
                                     void *user_data);


#define NTB_CRYPTO_ACKDATA_SIZE 32

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

struct ntb_crypto_cookie *
ntb_crypto_create_msg_blob(struct ntb_crypto *crypto,
                           int64_t timestamp,
                           struct ntb_key *from_key,
                           struct ntb_key *to_key,
                           struct ntb_blob *content,
                           ntb_crypto_create_msg_blob_func callback,
                           void *user_data);

struct ntb_crypto_cookie *
ntb_crypto_create_public_key(struct ntb_crypto *crypto,
                             uint8_t version,
                             uint8_t stream,
                             const uint8_t *signing_key,
                             const uint8_t *encryption_key,
                             ntb_crypto_create_key_func callback,
                             void *user_data);

struct ntb_crypto_cookie *
ntb_crypto_check_pubkey(struct ntb_crypto *crypto,
                        const struct ntb_address *address,
                        struct ntb_blob *blob,
                        ntb_crypto_create_key_func callback,
                        void *user_data);

struct ntb_crypto_cookie *
ntb_crypto_decrypt_msg(struct ntb_crypto *crypto,
                       struct ntb_blob *msg,
                       struct ntb_key * const *keys,
                       int n_keys,
                       ntb_crypto_decrypt_msg_func callback,
                       void *user_data);

struct ntb_crypto_cookie *
ntb_crypto_generate_ackdata(struct ntb_crypto *crypto,
                            ntb_crypto_generate_ackdata_func callback,
                            void *user_data);

void
ntb_crypto_cancel_task(struct ntb_crypto_cookie *cookie);

void
ntb_crypto_free(struct ntb_crypto *crypto);

#endif /* NTB_CRYPTO_H */
