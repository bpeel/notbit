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


struct ntb_crypto *
ntb_crypto_new(void);

/* Creates a new private key. The key parameters must not be given
 * because they will be generated */
struct ntb_crypto_cookie *
ntb_crypto_create_key(struct ntb_crypto *crypto,
                      const struct ntb_key_params *params,
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

/* The private keys must not be given but the public keys must */
struct ntb_crypto_cookie *
ntb_crypto_create_public_key(struct ntb_crypto *crypto,
                             const struct ntb_key_params *params,
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
