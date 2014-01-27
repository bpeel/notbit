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
#include <assert.h>

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
#include "ntb-buffer.h"
#include "ntb-pow.h"
#include "ntb-pointer-array.h"
#include "ntb-address.h"
#include "ntb-slice.h"
#include "ntb-hash-table.h"

struct ntb_keyring {
        struct ntb_network *nw;
        struct ntb_crypto *crypto;
        struct ntb_pow *pow;
        struct ntb_buffer keys;
        struct ntb_list tasks;
        struct ntb_listener new_object_listener;

        /* Hash table of pubkey blobs indexed by either the ripe
         * (for v2/3 keys) or the tag (v4 keys) */
        struct ntb_hash_table *pubkey_blob_table;
        /* Pubkey blobs with the same tag or ripe are grouped together
         * within this list. The hash table entry points to the first
         * entry in the group */
        struct ntb_list pubkey_blob_list;

        struct ntb_main_context_source *gc_source;

        /* The message contents are given a unique id using this
         * counter. The ID is used for the filename in the store */
        uint64_t next_message_content_id;

        struct ntb_list messages;
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

        union {
                struct {
                        int64_t timestamp;
                } msg;
        };
};

enum ntb_keyring_message_state {
        NTB_KEYRING_MESSAGE_STATE_GENERATING_ACKDATA,
        NTB_KEYRING_MESSAGE_STATE_LOADING_CONTENT,
        NTB_KEYRING_MESSAGE_STATE_CALCULATING_ACKDATA_POW,
        NTB_KEYRING_MESSAGE_STATE_CREATE_MSG_BLOB,
        NTB_KEYRING_MESSAGE_STATE_CALCULATING_MSG_POW,
        NTB_KEYRING_MESSAGE_STATE_AWAITING_ACKNOWLEDGEMENT
};

struct ntb_keyring_message {
        struct ntb_keyring *keyring;

        enum ntb_keyring_message_state state;

        struct ntb_key *from_key;
        struct ntb_address to_address;
        struct ntb_key *to_key;

        uint64_t content_id;
        int content_encoding;

        uint8_t ackdata[NTB_CRYPTO_ACKDATA_SIZE];

        struct ntb_crypto_cookie *crypto_cookie;
        struct ntb_pow_cookie *pow_cookie;
        struct ntb_store_cookie *store_cookie;
        struct ntb_blob *blob;

        size_t blob_ackdata_offset;
        uint32_t blob_ackdata_length;

        int64_t last_send_time;

        struct ntb_list link;
};

struct ntb_keyring_pubkey_blob {
        /* This struct is used to index the pubkey objects by either
         * the ripe or the tag so that when we want to use a new
         * public key we can first check if it's already in the
         * network */

        struct ntb_list link;
        int64_t timestamp;
        uint8_t ripe_or_tag[NTB_PROTO_HASH_LENGTH];
        uint8_t hash[NTB_PROTO_HASH_LENGTH];
};

_Static_assert(RIPEMD160_DIGEST_LENGTH <= NTB_PROTO_HASH_LENGTH,
               "The ripe is too long to fit in a hash");
_Static_assert(NTB_KEY_TAG_SIZE <= NTB_PROTO_HASH_LENGTH,
               "The tag is too long to fit in a hash");

/* Time in minutes between each garbage collection run */
#define NTB_KEYRING_GC_TIMEOUT 10

NTB_SLICE_ALLOCATOR(struct ntb_keyring_pubkey_blob,
                    ntb_keyring_pubkey_blob_allocator);

struct ntb_error_domain
ntb_keyring_error;

static void
free_message(struct ntb_keyring_message *message)
{
        ntb_key_unref(message->from_key);

        if (message->to_key)
                ntb_key_unref(message->to_key);

        if (message->crypto_cookie)
                ntb_crypto_cancel_task(message->crypto_cookie);

        if (message->pow_cookie)
                ntb_pow_cancel(message->pow_cookie);

        if (message->store_cookie)
                ntb_store_cancel_task(message->store_cookie);

        if (message->blob)
                ntb_blob_unref(message->blob);

        ntb_list_remove(&message->link);

        ntb_free(message);
}

static void
maybe_delete_message_content(struct ntb_keyring *keyring,
                             uint64_t content_id)
{
        struct ntb_keyring_message *message;

        /* Check if any messages are still using this content */
        ntb_list_for_each(message, &keyring->messages, link) {
                if (message->content_id == content_id)
                        return;
        }

        ntb_store_delete_message_content(NULL, content_id);
}

static void
save_keyring(struct ntb_keyring *keyring)
{
        ntb_store_save_keys(NULL /* default store */,
                            (struct ntb_key **) keyring->keys.data,
                            ntb_pointer_array_length(&keyring->keys));
}

static void
add_key(struct ntb_keyring *keyring,
        struct ntb_key *key)
{
        ntb_pointer_array_append(&keyring->keys, ntb_key_ref(key));
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

        ntb_network_add_blob(keyring->nw,
                             task->blob,
                             NTB_NETWORK_DELAY |
                             NTB_NETWORK_SKIP_VALIDATION,
                             "pubkey response");

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
               int key_index)
{
        struct ntb_key *key = ntb_pointer_array_get(&keyring->keys, key_index);
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
        ntb_pointer_array_set(&keyring->keys, key_index, tmp_key);

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
        struct ntb_key *key;
        int i;

        for (i = 0; i < ntb_pointer_array_length(&keyring->keys); i++) {
                key = ntb_pointer_array_get(&keyring->keys, i);

                if (!ntb_key_has_private(key))
                        continue;

                if (!memcmp(key->address.ripe, ripe, RIPEMD160_DIGEST_LENGTH)) {
                        if (key->address.version != address_version ||
                            key->address.stream != stream_number) {
                                ntb_log("getpubkey requested for key with the "
                                        "wrong version or stream number");
                        } else {
                                maybe_post_key(keyring, i);
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
        struct ntb_key *key;
        int i;

        for (i = 0; i < ntb_pointer_array_length(&keyring->keys); i++) {
                key = ntb_pointer_array_get(&keyring->keys, i);

                if (!ntb_key_has_private(key))
                        continue;

                if (!memcmp(key->tag, tag, NTB_KEY_TAG_SIZE)) {
                        if (key->address.version != address_version ||
                            key->address.stream != stream_number) {
                                ntb_log("getpubkey requested for key with the "
                                        "wrong version or stream number");
                        } else {
                                maybe_post_key(keyring, i);
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
        struct ntb_proto_pubkey pubkey;
        struct ntb_keyring_pubkey_blob *pubkey_blob;
        struct ntb_keyring_pubkey_blob *insert_pos;
        struct ntb_address address;

        if (!ntb_proto_get_pubkey(blob->data, blob->size, &pubkey))
                return;

        pubkey_blob = ntb_slice_alloc(&ntb_keyring_pubkey_blob_allocator);

        pubkey_blob->timestamp = pubkey.timestamp;

        ntb_proto_double_hash(blob->data, blob->size, pubkey_blob->hash);

        if (pubkey.tag) {
                memcpy(pubkey_blob->ripe_or_tag,
                       pubkey.tag,
                       NTB_PROTO_HASH_LENGTH);
                memset(pubkey_blob->ripe_or_tag + NTB_KEY_TAG_SIZE,
                       0,
                       NTB_PROTO_HASH_LENGTH - NTB_KEY_TAG_SIZE);
        } else {
                ntb_address_from_network_keys(&address,
                                              pubkey.address_version,
                                              pubkey.stream,
                                              pubkey.public_signing_key,
                                              pubkey.public_encryption_key);
                memcpy(pubkey_blob->ripe_or_tag,
                       address.ripe,
                       RIPEMD160_DIGEST_LENGTH);
                memset(pubkey_blob->ripe_or_tag + RIPEMD160_DIGEST_LENGTH,
                       0,
                       NTB_PROTO_HASH_LENGTH - RIPEMD160_DIGEST_LENGTH);
        }

        insert_pos = ntb_hash_table_get(keyring->pubkey_blob_table,
                                        pubkey_blob->ripe_or_tag);

        if (insert_pos == NULL) {
                ntb_list_insert(&keyring->pubkey_blob_list, &pubkey_blob->link);
                ntb_hash_table_set(keyring->pubkey_blob_table, pubkey_blob);
        } else {
                ntb_list_insert(&insert_pos->link, &pubkey_blob->link);
        }
}

static void
send_acknowledgement(struct ntb_keyring *keyring,
                     const uint8_t *ack,
                     size_t ack_length)
{
        enum ntb_proto_inv_type type;
        const char *command_name;

        if (ack_length == 0) {
                ntb_log("The decrypted message contains no "
                        "acknowledgement data");
                return;
        }

        if (ack_length < NTB_PROTO_HEADER_SIZE ||
            !ntb_proto_check_command_string(ack + 4)) {
                ntb_log("The acknowledgement message in the decrypted message "
                        "is invalid");
                return;
        }

        command_name = (const char *) ack + 4;
        ack += NTB_PROTO_HEADER_SIZE;
        ack_length -= NTB_PROTO_HEADER_SIZE;

        for (type = 0; type < 4; type++) {
                if (!strcmp(ntb_proto_get_command_name_for_type(type),
                            command_name)) {
                        ntb_network_add_object_from_data(keyring->nw,
                                                         type,
                                                         ack,
                                                         ack_length,
                                                         NTB_NETWORK_DELAY,
                                                         "acknowledgement "
                                                         "data");
                        return;
                }
        }

        ntb_log("The acknowledgement data contains an unknown command “%s”",
                ack + 4);
}

static void
create_public_key_cb(struct ntb_key *public_key,
                     void *user_data)
{
        struct ntb_keyring_task *task = user_data;
        struct ntb_keyring *keyring = task->keyring;
        struct ntb_key *key;
        int i;

        task->crypto_cookie = NULL;
        free_task(task);

        /* Check if we already have the key. It could have been added
         * in the time between queuing the crypto to create the key
         * and getting the result */
        for (i = 0; i < ntb_pointer_array_length(&keyring->keys); i++) {
                key = ntb_pointer_array_get(&keyring->keys, i);

                if (ntb_address_equal(&public_key->address, &key->address))
                        return;
        }

        add_key(keyring, public_key);
        save_keyring(keyring);
}

static void
add_public_key(struct ntb_keyring *keyring,
               const struct ntb_address *address,
               const uint8_t *public_signing_key,
               const uint8_t *public_encryption_key)
{
        uint8_t full_public_signing_key[NTB_ECC_PUBLIC_KEY_SIZE];
        uint8_t full_public_encryption_key[NTB_ECC_PUBLIC_KEY_SIZE];
        struct ntb_keyring_task *task;
        struct ntb_key *key;
        int i;

        /* Check if we already have the key */
        for (i = 0; i < ntb_pointer_array_length(&keyring->keys); i++) {
                key = ntb_pointer_array_get(&keyring->keys, i);

                if (ntb_address_equal(address, &key->address))
                        return;
        }

        /* The keys from the network don't have the 0x04 prefix so we
         * have to add it */
        full_public_signing_key[0] = 0x04;
        memcpy(full_public_signing_key + 1,
               public_signing_key,
               NTB_ECC_PUBLIC_KEY_SIZE);
        full_public_encryption_key[0] = 0x04;
        memcpy(full_public_encryption_key + 1,
               public_encryption_key,
               NTB_ECC_PUBLIC_KEY_SIZE);

        task = add_task(keyring);
        task->crypto_cookie =
                ntb_crypto_create_public_key(keyring->crypto,
                                             address->version,
                                             address->stream,
                                             full_public_signing_key,
                                             full_public_encryption_key,
                                             create_public_key_cb,
                                             task);
}

static void
decrypt_msg_cb(struct ntb_key *key,
               struct ntb_blob *blob,
               void *user_data)
{
        struct ntb_keyring_task *task = user_data;
        struct ntb_keyring *keyring = task->keyring;
        struct ntb_proto_decrypted_msg msg;
        struct ntb_address sender_address;
        char sender_address_string[NTB_ADDRESS_MAX_LENGTH + 1];
        char to_address_string[NTB_ADDRESS_MAX_LENGTH + 1];

        task->crypto_cookie = NULL;

        free_task(task);

        /* If we couldn't decrypt it then the key will be NULL */
        if (key == NULL)
                return;

        if (!ntb_proto_get_decrypted_msg(blob->data,
                                         blob->size,
                                         &msg))
                goto invalid;

        /* We can't encode the address if these numbers are too high
         * so instead we'll just assume the message is invalid */
        if (msg.sender_stream_number > 255 ||
            msg.sender_address_version > 255)
                goto invalid;

        if (memcmp(key->address.ripe,
                   msg.destination_ripe,
                   RIPEMD160_DIGEST_LENGTH)) {
                ntb_log("The key that was used to encrypt the message does "
                        "not match the destination address embedded in the "
                        "message. This could be a surreptitious forwarding "
                        "attack");
                return;
        }

        ntb_address_from_network_keys(&sender_address,
                                      msg.sender_address_version,
                                      msg.sender_stream_number,
                                      msg.sender_signing_key,
                                      msg.sender_encryption_key);
        ntb_address_encode(&sender_address, sender_address_string);

        /* Store the public key so we don't have to request it if we reply */
        add_public_key(keyring,
                       &sender_address,
                       msg.sender_signing_key,
                       msg.sender_encryption_key);

        ntb_address_encode(&key->address, to_address_string);

        ntb_log("Accepted message from %s", sender_address_string);

        send_acknowledgement(keyring, msg.ack, msg.ack_length);

        ntb_store_save_message(NULL, /* default store */
                               task->msg.timestamp,
                               sender_address_string,
                               to_address_string,
                               blob);

        return;

invalid:
        ntb_log("Decrypted message is invalid");
}

static void
message_acknowledged(struct ntb_keyring_message *message)
{
        struct ntb_keyring *keyring = message->keyring;
        char to_address_string[NTB_ADDRESS_MAX_LENGTH + 1];
        uint64_t content_id;

        ntb_address_encode(&message->to_address,
                           to_address_string);
        ntb_log("Received acknowledgement for message from %s",
                to_address_string);

        content_id = message->content_id;

        free_message(message);

        maybe_delete_message_content(keyring, content_id);
}

static bool
check_msg_acknowledgement(struct ntb_keyring *keyring,
                          const uint8_t *content,
                          size_t content_length)
{
        struct ntb_keyring_message *message;

        if (content_length != NTB_CRYPTO_ACKDATA_SIZE)
                return false;

        ntb_list_for_each(message, &keyring->messages, link) {
                if (message->state !=
                    NTB_KEYRING_MESSAGE_STATE_GENERATING_ACKDATA &&
                    !memcmp(message->ackdata,
                            content,
                            NTB_CRYPTO_ACKDATA_SIZE)) {
                        message_acknowledged(message);
                        return true;
                }
        }

        return false;
}

static void
handle_msg(struct ntb_keyring *keyring,
           struct ntb_blob *blob)
{
        struct ntb_keyring_task *task;
        uint64_t nonce;
        int64_t timestamp;
        ssize_t header_length;
        uint64_t stream_number;

        header_length = ntb_proto_get_command(blob->data,
                                              blob->size,

                                              NTB_PROTO_ARGUMENT_64,
                                              &nonce,

                                              NTB_PROTO_ARGUMENT_TIMESTAMP,
                                              &timestamp,

                                              NTB_PROTO_ARGUMENT_VAR_INT,
                                              &stream_number,

                                              NTB_PROTO_ARGUMENT_END);

        if (header_length == -1) {
                ntb_log("Invalid msg command received");
                return;
        }

        if (check_msg_acknowledgement(keyring,
                                      blob->data + header_length,
                                      blob->size - header_length))
            return;

        task = add_task(keyring);
        task->crypto_cookie =
                ntb_crypto_decrypt_msg(keyring->crypto,
                                       blob,
                                       (struct ntb_key * const *)
                                       keyring->keys.data,
                                       ntb_pointer_array_length(&keyring->keys),
                                       decrypt_msg_cb,
                                       task);
        task->msg.timestamp = timestamp;
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

static void
remove_pubkey_blob(struct ntb_keyring *keyring,
                   struct ntb_keyring_pubkey_blob *pubkey)
{
        struct ntb_keyring_pubkey_blob *prev, *next;

        prev = ntb_container_of(pubkey->link.prev, pubkey, link);
        next = ntb_container_of(pubkey->link.next, pubkey, link);

        ntb_list_remove(&pubkey->link);

        /* If this key is the first of its group then we need to move
         * the hash table index to the next key in the group */
        if (&prev->link == &keyring->pubkey_blob_list ||
            memcmp(prev->ripe_or_tag,
                   pubkey->ripe_or_tag,
                   NTB_PROTO_HASH_LENGTH)) {
                if (&next->link == &keyring->pubkey_blob_list ||
                    memcmp(next->ripe_or_tag,
                           pubkey->ripe_or_tag,
                           NTB_PROTO_HASH_LENGTH))
                        ntb_hash_table_remove(keyring->pubkey_blob_table,
                                              pubkey);
                else
                        ntb_hash_table_set(keyring->pubkey_blob_table, next);
        }

        ntb_slice_free(&ntb_keyring_pubkey_blob_allocator, pubkey);
}

static void
gc_timeout_cb(struct ntb_main_context_source *source,
              void *user_data)
{
        struct ntb_keyring *keyring = user_data;
        struct ntb_keyring_pubkey_blob *pubkey, *tmp;
        int64_t now = ntb_main_context_get_wall_clock(NULL);
        int64_t max_age =
                ntb_proto_get_max_age_for_type(NTB_PROTO_INV_TYPE_PUBKEY);
        int64_t age;


        ntb_list_for_each_safe(pubkey, tmp, &keyring->pubkey_blob_list, link) {
                age = now - pubkey->timestamp;

                if (age >= max_age)
                        remove_pubkey_blob(keyring, pubkey);
        }
}

struct ntb_keyring *
ntb_keyring_new(struct ntb_network *nw)
{
        struct ntb_keyring *keyring;
        const size_t pubkey_blob_hash_offset =
                NTB_STRUCT_OFFSET(struct ntb_keyring_pubkey_blob, ripe_or_tag);

        keyring = ntb_alloc(sizeof *keyring);

        keyring->nw = nw;

        keyring->next_message_content_id = 0;

        ntb_list_init(&keyring->tasks);

        keyring->new_object_listener.notify = new_object_cb;
        ntb_signal_add(ntb_network_get_new_object_signal(nw),
                       &keyring->new_object_listener);

        keyring->crypto = ntb_crypto_new();
        keyring->pow = ntb_pow_new();
        ntb_buffer_init(&keyring->keys);

        ntb_list_init(&keyring->messages);

        ntb_list_init(&keyring->pubkey_blob_list);
        keyring->pubkey_blob_table =
                ntb_hash_table_new(pubkey_blob_hash_offset);

        ntb_store_for_each_key(NULL, /* default store */
                               for_each_key_cb,
                               keyring);

        keyring->gc_source = ntb_main_context_add_timer(NULL,
                                                        NTB_KEYRING_GC_TIMEOUT,
                                                        gc_timeout_cb,
                                                        keyring);

        return keyring;
}

static void
for_each_pubkey_blob_cb(const uint8_t *hash,
                        int64_t timestamp,
                        struct ntb_blob *blob,
                        void *user_data)
{
        struct ntb_keyring *keyring = user_data;

        handle_pubkey(keyring, blob);
}

void
ntb_keyring_load_store(struct ntb_keyring *keyring)
{
        ntb_store_for_each_pubkey_blob(NULL,
                                       for_each_pubkey_blob_cb,
                                       keyring);
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

static struct ntb_key *
get_private_key_for_address(struct ntb_keyring *keyring,
                            const struct ntb_address *address)
{
        struct ntb_key *key;
        int i;

        for (i = 0; i < ntb_pointer_array_length(&keyring->keys); i++) {
                key = ntb_pointer_array_get(&keyring->keys, i);

                if (ntb_key_has_private(key) &&
                    ntb_address_equal(&key->address, address))
                        return key;
        }

        return NULL;
}

static struct ntb_key *
get_any_key_for_address(struct ntb_keyring *keyring,
                        const struct ntb_address *address)
{
        struct ntb_key *key;
        int i;

        for (i = 0; i < ntb_pointer_array_length(&keyring->keys); i++) {
                key = ntb_pointer_array_get(&keyring->keys, i);

                if (ntb_address_equal(&key->address, address))
                        return key;
        }

        return NULL;
}

static void
msg_pow_cb(uint64_t nonce,
           void *user_data)
{
        struct ntb_keyring_message *message = user_data;
        struct ntb_keyring *keyring = message->keyring;

        message->pow_cookie = NULL;

        ntb_log("Finished calculating proof-of-work for msg. Nonce is %" PRIu64,
                nonce);

        nonce = NTB_UINT64_TO_BE(nonce);

        memcpy(message->blob->data, &nonce, sizeof nonce);

        ntb_network_add_blob(keyring->nw,
                             message->blob,
                             NTB_NETWORK_SKIP_VALIDATION,
                             "outgoing message");

        ntb_blob_unref(message->blob);
        message->blob = NULL;

        message->state = NTB_KEYRING_MESSAGE_STATE_AWAITING_ACKNOWLEDGEMENT;
}

static void
create_msg_blob_cb(struct ntb_blob *blob,
                   void *user_data)
{
        struct ntb_keyring_message *message = user_data;
        struct ntb_keyring *keyring = message->keyring;

        message->crypto_cookie = NULL;

        ntb_blob_unref(message->blob);
        message->blob = ntb_blob_ref(blob);

        ntb_log("Doing proof-of-work calculation for msg");

        message->state = NTB_KEYRING_MESSAGE_STATE_CALCULATING_MSG_POW;

        message->pow_cookie =
                ntb_pow_calculate(keyring->pow,
                                  blob->data + sizeof (uint64_t),
                                  blob->size - sizeof (uint64_t),
                                  NTB_PROTO_MIN_EXTRA_BYTES,
                                  NTB_PROTO_MIN_NONCE_TRIALS_PER_BYTE,
                                  msg_pow_cb,
                                  message);
}

static void
ackdata_pow_cb(uint64_t nonce,
               void *user_data)
{
        uint8_t hash[SHA512_DIGEST_LENGTH];
        struct ntb_keyring_message *message = user_data;
        struct ntb_keyring *keyring = message->keyring;

        message->pow_cookie = NULL;

        ntb_log("Finished calculating proof-of-work for acknowledgement data. "
                "Nonce is %" PRIu64,
                nonce);

        nonce = NTB_UINT64_TO_BE(nonce);

        memcpy(message->blob->data +
               message->blob_ackdata_offset +
               NTB_PROTO_HEADER_SIZE,
               &nonce,
               sizeof nonce);

        SHA512(message->blob->data + message->blob_ackdata_offset +
               NTB_PROTO_HEADER_SIZE,
               message->blob_ackdata_length - NTB_PROTO_HEADER_SIZE,
               hash);
        memcpy(message->blob->data + message->blob_ackdata_offset + 20,
               hash,
               4);

        message->last_send_time =
                ntb_main_context_get_wall_clock(NULL) +
                rand() % 600 - 300;

        message->state = NTB_KEYRING_MESSAGE_STATE_CREATE_MSG_BLOB;

        message->crypto_cookie =
                ntb_crypto_create_msg_blob(keyring->crypto,
                                           message->last_send_time,
                                           message->from_key,
                                           message->to_key,
                                           message->blob,
                                           create_msg_blob_cb,
                                           message);
}

static void
add_ackdata_to_message(struct ntb_keyring_message *message,
                       size_t message_offset,
                       struct ntb_buffer *buffer)
{
        uint32_t msg_length, payload_length, payload_length_be;
        size_t ack_offset;

        /* Leave space for the acknowledgement length. This is a
         * varint but we should never need a length that would tip it
         * over a single byte */
        ntb_buffer_set_length(buffer, buffer->length + 1);

        ack_offset = buffer->length;

        ntb_buffer_append(buffer, ntb_proto_magic, 4);
        ntb_buffer_append(buffer, "msg\0\0\0\0\0\0\0\0\0", 12);

        /* Leave space for the message length, checksum and POW */
        ntb_buffer_set_length(buffer,
                              buffer->length +
                              sizeof (uint32_t) +
                              sizeof (uint32_t) +
                              sizeof (uint64_t));

        ntb_proto_add_64(buffer,
                         ntb_main_context_get_wall_clock(NULL) +
                         rand() % 600 - 300);
        ntb_proto_add_var_int(buffer, message->from_key->address.stream);
        ntb_buffer_append(buffer, message->ackdata, NTB_CRYPTO_ACKDATA_SIZE);

        msg_length = buffer->length - ack_offset;

        /* If this fails then the length won't fit in a byte and we
         * haven't reserved enough space */
        assert(msg_length < 0xfd);

        buffer->data[ack_offset - 1] = msg_length;

        payload_length = msg_length - NTB_PROTO_HEADER_SIZE;
        payload_length_be = NTB_UINT32_TO_BE(payload_length);

        memcpy(buffer->data + ack_offset + 16,
               &payload_length_be,
               sizeof payload_length_be);

        message->blob_ackdata_offset = ack_offset - message_offset;
        message->blob_ackdata_length = msg_length;
}

static void
load_message_content_cb(struct ntb_blob *content_blob,
                        void *user_data)
{
        struct ntb_keyring_message *message = user_data;
        struct ntb_keyring *keyring = message->keyring;
        struct ntb_key *from_key = message->from_key;
        struct ntb_buffer buffer;
        size_t message_offset;

        message->store_cookie = NULL;

        ntb_blob_dynamic_init(&buffer, NTB_PROTO_INV_TYPE_MSG);

        message_offset = buffer.length;

        /* Build the unencrypted message */

        ntb_proto_add_var_int(&buffer, 1 /* message version */);
        ntb_proto_add_var_int(&buffer, message->from_key->address.version);
        ntb_proto_add_var_int(&buffer, message->from_key->address.stream);
        ntb_proto_add_32(&buffer, NTB_PROTO_PUBKEY_BEHAVIORS);
        ntb_proto_add_public_key(&buffer, from_key->signing_key);
        ntb_proto_add_public_key(&buffer, from_key->encryption_key);
        if (message->from_key->address.version >= 3) {
                ntb_proto_add_var_int(&buffer, from_key->nonce_trials_per_byte);
                ntb_proto_add_var_int(&buffer,
                                      from_key->payload_length_extra_bytes);
        }
        ntb_buffer_append(&buffer,
                          message->to_address.ripe,
                          RIPEMD160_DIGEST_LENGTH);
        ntb_proto_add_var_int(&buffer, message->content_encoding);

        ntb_proto_add_var_int(&buffer, content_blob->size);
        ntb_buffer_append(&buffer, content_blob->data, content_blob->size);

        add_ackdata_to_message(message, message_offset, &buffer);

        message->blob = ntb_blob_dynamic_end(&buffer);

        message->state = NTB_KEYRING_MESSAGE_STATE_CALCULATING_ACKDATA_POW;

        ntb_log("Doing proof-of-work calculation for acknowledgement data");

        message->pow_cookie =
                ntb_pow_calculate(keyring->pow,
                                  message->blob->data +
                                  message->blob_ackdata_offset +
                                  NTB_PROTO_HEADER_SIZE +
                                  sizeof (uint64_t),
                                  message->blob_ackdata_length -
                                  NTB_PROTO_HEADER_SIZE -
                                  sizeof (uint64_t),
                                  NTB_PROTO_MIN_EXTRA_BYTES,
                                  NTB_PROTO_MIN_NONCE_TRIALS_PER_BYTE,
                                  ackdata_pow_cb,
                                  message);
}

static void
generate_ackdata_cb(const uint8_t *ackdata,
                    void *user_data)
{
        struct ntb_keyring_message *message = user_data;
        uint64_t content_id = message->content_id;

        memcpy(message->ackdata, ackdata, NTB_CRYPTO_ACKDATA_SIZE);

        message->crypto_cookie = NULL;

        if (message->to_key == NULL) {
                /* FIXME! */
                ntb_log("FIXME: The public key isn't available for this "
                        "message so it will be abandoned");
                free_message(message);
                maybe_delete_message_content(message->keyring, content_id);
                return;
        }

        message->state = NTB_KEYRING_MESSAGE_STATE_LOADING_CONTENT;

        message->store_cookie =
                ntb_store_load_message_content(NULL,
                                               message->content_id,
                                               load_message_content_cb,
                                               message);
}

static struct ntb_keyring_message *
create_message(struct ntb_keyring *keyring,
               struct ntb_key *from_key,
               const struct ntb_address *to_address,
               int content_encoding,
               uint64_t content_id)
{
        struct ntb_keyring_message *message;

        message = ntb_alloc(sizeof *message);

        message->keyring = keyring;

        message->from_key = ntb_key_ref(from_key);

        message->to_address = *to_address;

        message->to_key = get_any_key_for_address(keyring, to_address);

        if (message->to_key)
                ntb_key_ref(message->to_key);

        message->content_encoding = content_encoding;
        message->content_id = content_id;

        message->pow_cookie = NULL;
        message->crypto_cookie = NULL;

        message->last_send_time = 0;

        ntb_list_insert(&keyring->messages, &message->link);

        return message;
}

bool
ntb_keyring_send_message(struct ntb_keyring *keyring,
                         const struct ntb_address *from_address,
                         const struct ntb_address *to_addresses,
                         int n_to_addresses,
                         int content_encoding,
                         struct ntb_blob *content,
                         struct ntb_error **error)
{
        struct ntb_key *from_key;
        uint64_t content_id;
        struct ntb_keyring_message *message;
        int i;

        ntb_return_val_if_fail(n_to_addresses >= 1, false);

        from_key = get_private_key_for_address(keyring, from_address);

        if (from_key == NULL) {
                ntb_set_error(error,
                              &ntb_keyring_error,
                              NTB_KEYRING_ERROR_UNKNOWN_FROM_ADDRESS,
                              "The private key for the from address is not "
                              "available");
                return false;
        }

        content_id = keyring->next_message_content_id++;

        ntb_store_save_message_content(NULL, content_id, content);

        for (i = 0; i < n_to_addresses; i++) {
                message = create_message(keyring,
                                         from_key,
                                         to_addresses + i,
                                         content_encoding,
                                         content_id);

                message->state = NTB_KEYRING_MESSAGE_STATE_GENERATING_ACKDATA;
                message->crypto_cookie =
                        ntb_crypto_generate_ackdata(keyring->crypto,
                                                    generate_ackdata_cb,
                                                    message);
        }

        return true;
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

static void
free_pubkey_blobs(struct ntb_keyring *keyring)
{
        struct ntb_keyring_pubkey_blob *pubkey, *tmp;

        ntb_list_for_each_safe(pubkey, tmp, &keyring->pubkey_blob_list, link)
                ntb_slice_free(&ntb_keyring_pubkey_blob_allocator, pubkey);
        ntb_hash_table_free(keyring->pubkey_blob_table);
}

static void
free_messages(struct ntb_keyring *keyring)
{
        struct ntb_keyring_message *message, *tmp;

        ntb_list_for_each_safe(message, tmp, &keyring->messages, link)
                free_message(message);
}

void
ntb_keyring_free(struct ntb_keyring *keyring)
{
        int i;

        ntb_main_context_remove_source(keyring->gc_source);

        ntb_list_remove(&keyring->new_object_listener.link);

        free_pubkey_blobs(keyring);
        cancel_tasks(keyring);
        free_messages(keyring);

        for (i = 0; i < ntb_pointer_array_length(&keyring->keys); i++)
                ntb_key_unref(ntb_pointer_array_get(&keyring->keys, i));
        ntb_buffer_destroy(&keyring->keys);

        ntb_pow_free(keyring->pow);
        ntb_crypto_free(keyring->crypto);
        ntb_free(keyring);
}
