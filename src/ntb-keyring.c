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

#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <stdlib.h>

#include "ntb-keyring.h"
#include "ntb-util.h"
#include "ntb-main-context.h"
#include "ntb-log.h"
#include "ntb-crypto.h"
#include "ntb-key.h"
#include "ntb-list.h"
#include "ntb-store.h"
#include "ntb-signal.h"
#include "ntb-proto.h"
#include "ntb-pointer-list.h"
#include "ntb-buffer.h"
#include "ntb-pow.h"

struct ntb_keyring {
        struct ntb_network *nw;
        struct ntb_crypto *crypto;
        struct ntb_pow *pow;
        struct ntb_list keys;
        struct ntb_list tasks;
        struct ntb_listener new_object_listener;
};

struct ntb_keyring_cookie {
        struct ntb_keyring *keyring;
        ntb_keyring_create_key_func func;
        void *user_data;
        struct ntb_crypto_cookie *crypto_cookie;
};

struct ntb_keyring_task {
        struct ntb_keyring *keyring;
        struct ntb_crypto_cookie *crypto_cookie;
        struct ntb_pow_cookie *pow_cookie;
        struct ntb_blob *blob;
        struct ntb_list link;
};

static void
save_keyring(struct ntb_keyring *keyring)
{
        struct ntb_key **keys;
        struct ntb_pointer_list *plist;
        int n_keys = 0, i = 0;

        ntb_list_for_each(plist, &keyring->keys, link)
                n_keys++;

        keys = alloca(sizeof (struct ntb_key *) * n_keys);

        ntb_list_for_each(plist, &keyring->keys, link)
                keys[i++] = plist->data;

        ntb_store_save_keys(NULL /* default store */, keys, n_keys);
}

static void
add_key(struct ntb_keyring *keyring,
        struct ntb_key *key)
{
        ntb_pointer_list_insert(&keyring->keys, ntb_key_ref(key));
}

static void
for_each_key_cb(struct ntb_key *key,
                void *user_data)
{
        struct ntb_keyring *keyring = user_data;

        add_key(keyring, key);
}

static struct ntb_keyring_task *
add_task(struct ntb_keyring *keyring)
{
        struct ntb_keyring_task *task = ntb_alloc(sizeof *task);

        task->keyring = keyring;
        task->crypto_cookie = NULL;
        task->pow_cookie = NULL;
        task->blob = NULL;

        ntb_list_insert(&keyring->tasks, &task->link);

        return task;
}

static void
free_task(struct ntb_keyring_task *task)
{
        if (task->crypto_cookie)
                ntb_crypto_cancel_task(task->crypto_cookie);
        if (task->pow_cookie)
                ntb_pow_cancel(task->pow_cookie);
        if (task->blob)
                ntb_blob_unref(task->blob);
        ntb_list_remove(&task->link);
        ntb_free(task);
}

static void
create_pubkey_pow_cb(uint64_t nonce,
                     void *user_data)
{
        struct ntb_keyring_task *task = user_data;
        struct ntb_keyring *keyring = task->keyring;

        ntb_log("Finished calculating proof-of-work for pubkey command. "
                "Nonce is %" PRIu64,
                nonce);

        nonce = NTB_UINT64_TO_BE(nonce);

        memcpy(task->blob->data, &nonce, sizeof nonce);

        ntb_network_add_object(keyring->nw, task->blob, true /* delay */);

        task->pow_cookie = NULL;
        free_task(task);
}

static void
create_pubkey_blob_cb(struct ntb_blob *blob,
                      void *user_data)
{
        struct ntb_keyring_task *task = user_data;
        struct ntb_keyring *keyring = task->keyring;

        ntb_log("Doing proof-of-work calculation to send pubkey command");

        task->crypto_cookie = NULL;
        task->pow_cookie =
                ntb_pow_calculate(keyring->pow,
                                  blob->data + sizeof (uint64_t),
                                  blob->size - sizeof (uint64_t),
                                  NTB_PROTO_MIN_EXTRA_BYTES,
                                  NTB_PROTO_MIN_NONCE_TRIALS_PER_BYTE,
                                  create_pubkey_pow_cb,
                                  task);
        task->blob = ntb_blob_ref(blob);
}

static void
maybe_post_key(struct ntb_keyring *keyring,
               struct ntb_pointer_list *key_link)
{
        struct ntb_key *key = key_link->data;
        struct ntb_key *tmp_key;
        int64_t now, last_send_age;
        struct ntb_keyring_task *task;

        now = ntb_main_context_get_wall_clock(NULL);

        last_send_age = now - key->last_pubkey_send_time;

        if (last_send_age <
            ntb_proto_get_max_age_for_type(NTB_PROTO_INV_TYPE_PUBKEY)) {
                ntb_log("Ignoring getpubkey command for key that was broadcast "
                        "%" PRIi64 " seconds ago because it should still be in "
                        "the network",
                        last_send_age);
                return;
        }

        /* Update the last send age now so that a peer can't keep us
         * busy by queueing loads of getpubkey requests before we've
         * had a chance to notice that we've already started one
         * request. The keys are immutable so we need to use a copy.
         * The timestamp is obsucated with a random number so that a
         * peer can't tell how quickly we responded */
        tmp_key = ntb_key_copy(key);
        tmp_key->last_pubkey_send_time = now + rand() % 600 - 300;
        ntb_key_unref(key);
        key_link->data = tmp_key;

        save_keyring(keyring);

        ntb_log("Generating pubkey command for the key \"%s\"",
                tmp_key->label);

        task = add_task(keyring);
        task->crypto_cookie =
                ntb_crypto_create_pubkey_blob(keyring->crypto,
                                              tmp_key,
                                              create_pubkey_blob_cb,
                                              task);
}

static void
handle_getpubkey_with_ripe(struct ntb_keyring *keyring,
                           uint64_t address_version,
                           uint64_t stream_number,
                           const uint8_t *ripe)
{
        struct ntb_pointer_list *plist;
        struct ntb_key *key;

        ntb_list_for_each(plist, &keyring->keys, link) {
                key = plist->data;

                if (!memcmp(key->ripe, ripe, RIPEMD160_DIGEST_LENGTH)) {
                        if (key->version != address_version ||
                            key->stream != stream_number) {
                                ntb_log("getpubkey requested for key with the "
                                        "wrong version or stream number");
                        } else {
                                maybe_post_key(keyring, plist);
                        }
                        break;
                }
        }
}

static void
handle_getpubkey_with_tag(struct ntb_keyring *keyring,
                          uint64_t address_version,
                          uint64_t stream_number,
                          const uint8_t *tag)
{
        struct ntb_pointer_list *plist;
        struct ntb_key *key;

        ntb_list_for_each(plist, &keyring->keys, link) {
                key = plist->data;

                if (!memcmp(key->tag, tag, NTB_KEY_TAG_SIZE)) {
                        if (key->version != address_version ||
                            key->stream != stream_number) {
                                ntb_log("getpubkey requested for key with the "
                                        "wrong version or stream number");
                        } else {
                                maybe_post_key(keyring, plist);
                        }
                        break;
                }
        }
}

static void
handle_getpubkey(struct ntb_keyring *keyring,
                 struct ntb_blob *blob)
{
        const uint8_t *ripe_or_tag;
        uint64_t nonce;
        int64_t timestamp;
        uint64_t address_version;
        ssize_t header_length;
        uint64_t stream_number;

        header_length = ntb_proto_get_command(blob->data,
                                              blob->size,

                                              NTB_PROTO_ARGUMENT_64,
                                              &nonce,

                                              NTB_PROTO_ARGUMENT_TIMESTAMP,
                                              &timestamp,

                                              NTB_PROTO_ARGUMENT_VAR_INT,
                                              &address_version,

                                              NTB_PROTO_ARGUMENT_VAR_INT,
                                              &stream_number,

                                              NTB_PROTO_ARGUMENT_END);

        if (header_length == -1) {
                ntb_log("Invalid getpubkey message received");
                return;
        }

        if (address_version < 2 || address_version > 4) {
                ntb_log("getpubkey with unsupported address version "
                        "%" PRIu64 " received",
                        address_version);
                return;
        }

        ripe_or_tag = blob->data + header_length;

        if (address_version < 4) {
                if (blob->size - header_length < RIPEMD160_DIGEST_LENGTH) {
                        ntb_log("Invalid getpubkey message received");
                        return;
                }

                handle_getpubkey_with_ripe(keyring,
                                           address_version,
                                           stream_number,
                                           ripe_or_tag);
        } else {
                if (blob->size - header_length < NTB_KEY_TAG_SIZE) {
                        ntb_log("Invalid getpubkey message received");
                        return;
                }

                handle_getpubkey_with_tag(keyring,
                                          address_version,
                                          stream_number,
                                          ripe_or_tag);
        }
}

static void
handle_pubkey(struct ntb_keyring *keyring,
              struct ntb_blob *blob)
{
}

static void
handle_msg(struct ntb_keyring *keyring,
           struct ntb_blob *blob)
{
}

static void
handle_broadcast(struct ntb_keyring *keyring,
                 struct ntb_blob *blob)
{
}

static bool
new_object_cb(struct ntb_listener *listener,
              void *data)
{
        struct ntb_keyring *keyring =
                ntb_container_of(listener, keyring, new_object_listener);
        struct ntb_blob *blob = data;

        switch (blob->type) {
        case NTB_PROTO_INV_TYPE_GETPUBKEY:
                handle_getpubkey(keyring, blob);
                break;
        case NTB_PROTO_INV_TYPE_PUBKEY:
                handle_pubkey(keyring, blob);
                break;
        case NTB_PROTO_INV_TYPE_MSG:
                handle_msg(keyring, blob);
                break;
        case NTB_PROTO_INV_TYPE_BROADCAST:
                handle_broadcast(keyring, blob);
                break;
        }

        return true;
}

struct ntb_keyring *
ntb_keyring_new(struct ntb_network *nw)
{
        struct ntb_keyring *keyring;

        keyring = ntb_alloc(sizeof *keyring);

        keyring->nw = nw;

        ntb_list_init(&keyring->tasks);

        keyring->new_object_listener.notify = new_object_cb;
        ntb_signal_add(ntb_network_get_new_object_signal(nw),
                       &keyring->new_object_listener);

        keyring->crypto = ntb_crypto_new();
        keyring->pow = ntb_pow_new();
        ntb_list_init(&keyring->keys);

        ntb_store_for_each_key(NULL, /* default store */
                               for_each_key_cb,
                               keyring);

        return keyring;
}

static void
create_key_cb(struct ntb_key *key,
              void *user_data)
{
        struct ntb_keyring_cookie *cookie = user_data;
        struct ntb_keyring *keyring = cookie->keyring;

        add_key(keyring, key);
        save_keyring(keyring);

        if (cookie->func)
                cookie->func(key, cookie->user_data);

        ntb_free(cookie);
}

struct ntb_keyring_cookie *
ntb_keyring_create_key(struct ntb_keyring *keyring,
                       const char *label,
                       int leading_zeroes,
                       ntb_keyring_create_key_func func,
                       void *user_data)
{
        struct ntb_keyring_cookie *cookie;

        cookie = ntb_alloc(sizeof *cookie);
        cookie->keyring = keyring;
        cookie->func = func;
        cookie->user_data = user_data;

        cookie->crypto_cookie = ntb_crypto_create_key(keyring->crypto,
                                                      label,
                                                      leading_zeroes,
                                                      create_key_cb,
                                                      cookie);

        return cookie;
}

void
ntb_keyring_cancel_task(struct ntb_keyring_cookie *cookie)
{
        ntb_crypto_cancel_task(cookie->crypto_cookie);
        ntb_free(cookie);
}

static void
cancel_tasks(struct ntb_keyring *keyring)
{
        struct ntb_keyring_task *task, *tmp;

        ntb_list_for_each_safe(task, tmp, &keyring->tasks, link)
                free_task(task);
}

void
ntb_keyring_free(struct ntb_keyring *keyring)
{
        struct ntb_pointer_list *plist, *tmp;

        ntb_list_remove(&keyring->new_object_listener.link);

        cancel_tasks(keyring);

        ntb_list_for_each_safe(plist, tmp, &keyring->keys, link) {
                ntb_key_unref(plist->data);
                ntb_pointer_list_free(plist);
        }

        ntb_pow_free(keyring->pow);
        ntb_crypto_free(keyring->crypto);
        ntb_free(keyring);
}
