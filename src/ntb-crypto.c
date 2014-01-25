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

#include <stdbool.h>
#include <string.h>
#include <openssl/ripemd.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <assert.h>

#include "ntb-crypto.h"
#include "ntb-util.h"
#include "ntb-slice.h"
#include "ntb-list.h"
#include "ntb-main-context.h"
#include "ntb-log.h"
#include "ntb-address.h"
#include "ntb-ecc.h"
#include "ntb-proto.h"

struct ntb_crypto {
        pthread_mutex_t mutex;
        pthread_cond_t cond;
        pthread_t thread;
        bool quit;

        struct ntb_slice_allocator cookie_allocator;

        struct ntb_list queue;

        struct ntb_ecc *ecc;
};

enum ntb_crypto_cookie_type {
        NTB_CRYPTO_COOKIE_CREATE_KEY,
        NTB_CRYPTO_COOKIE_CREATE_PUBKEY_BLOB,
        NTB_CRYPTO_COOKIE_DECRYPT_MSG
};

struct ntb_crypto_cookie {
        int ref_count;

        enum ntb_crypto_cookie_type type;

        void *func;
        void *user_data;

        struct ntb_list link;

        struct ntb_main_context_source *idle_source;

        struct ntb_crypto *crypto;

        bool in_queue;
        bool cancelled;

        union {
                struct {
                        struct ntb_key *key;
                        char *label;
                        int leading_zeroes;
                } create_key;

                struct {
                        struct ntb_key *key;
                        struct ntb_blob *blob;
                } create_pubkey_blob;

                struct {
                        struct ntb_blob *blob;
                        struct ntb_key **keys;
                        struct ntb_key *chosen_key;
                        struct ntb_blob *result;
                        int n_keys;
                } decrypt_msg;
        };
};

/* We send acknowledgements */
#define NTB_CRYPTO_PUBKEY_BEHAVIORS UINT32_C(0x00000001)

static struct ntb_crypto_cookie *
new_cookie(struct ntb_crypto *crypto,
           enum ntb_crypto_cookie_type type,
           void *func,
           void *user_data)
{
        struct ntb_crypto_cookie *cookie;

        /* This should only be called with the lock */

        cookie = ntb_slice_alloc(&crypto->cookie_allocator);
        /* One ref for the caller and one ref for being in the queue */
        cookie->ref_count = 2;
        cookie->type = type;
        cookie->cancelled = false;
        cookie->func = func;
        cookie->user_data = user_data;
        cookie->idle_source = NULL;
        cookie->crypto = crypto;
        cookie->in_queue = true;

        ntb_list_insert(crypto->queue.prev, &cookie->link);
        pthread_cond_signal(&crypto->cond);

        return cookie;
}

static void
unref_cookie(struct ntb_crypto_cookie *cookie)
{
        int i;

        /* This should only be called with the lock */

        if (--cookie->ref_count <= 0) {
                switch (cookie->type) {
                case NTB_CRYPTO_COOKIE_CREATE_KEY:
                        if (cookie->create_key.key)
                                ntb_key_unref(cookie->create_key.key);
                        ntb_free(cookie->create_key.label);
                        break;
                case NTB_CRYPTO_COOKIE_CREATE_PUBKEY_BLOB:
                        if (cookie->create_key.key)
                                ntb_key_unref(cookie->create_pubkey_blob.key);
                        if (cookie->create_pubkey_blob.blob)
                                ntb_blob_unref(cookie->create_pubkey_blob.blob);
                        break;
                case NTB_CRYPTO_COOKIE_DECRYPT_MSG:
                        for (i = 0; i < cookie->decrypt_msg.n_keys; i++)
                                ntb_key_unref(cookie->decrypt_msg.keys[i]);
                        ntb_free(cookie->decrypt_msg.keys);
                        if (cookie->decrypt_msg.result)
                                ntb_blob_unref(cookie->decrypt_msg.result);
                        if (cookie->decrypt_msg.chosen_key)
                                ntb_key_unref(cookie->decrypt_msg.chosen_key);
                        ntb_blob_unref(cookie->decrypt_msg.blob);
                        break;
                }

                ntb_slice_free(&cookie->crypto->cookie_allocator, cookie);
        }
}

static void
create_key(struct ntb_crypto *crypto,
           uint8_t *private_key,
           uint8_t *public_key)
{
        int result;

        result = RAND_bytes(private_key, NTB_ECC_PRIVATE_KEY_SIZE);
        assert(result);

        ntb_ecc_make_pub_key_bin(crypto->ecc,
                                 private_key,
                                 public_key);
}

static int
count_leading_zeroes(const uint8_t *hash)
{
        int count = 0;

        while (hash[count] == 0 && count < RIPEMD160_DIGEST_LENGTH)
                count++;

        return count;
}

static void
handle_create_key(struct ntb_crypto_cookie *cookie)
{
        struct ntb_crypto *crypto = cookie->crypto;
        uint8_t private_signing_key[NTB_ECC_PRIVATE_KEY_SIZE];
        uint8_t pub_signing_key[NTB_ECC_PUBLIC_KEY_SIZE];
        uint8_t private_encryption_key[NTB_ECC_PRIVATE_KEY_SIZE];
        uint8_t pub_encryption_key[NTB_ECC_PUBLIC_KEY_SIZE];
        uint8_t sha_hash[SHA512_DIGEST_LENGTH];
        uint8_t ripemd_hash[RIPEMD160_DIGEST_LENGTH];
        char address[NTB_ADDRESS_MAX_LENGTH + 1];
        SHA512_CTX sha_ctx;
        int attempts = 0;

        ntb_log("Generating key pair");

        create_key(crypto, private_signing_key, pub_signing_key);

        /* Keep generating random keys until we've reached an address
         * with a certain number of leading zeroes */
        do {
                create_key(crypto, private_encryption_key, pub_encryption_key);

                SHA512_Init(&sha_ctx);
                SHA512_Update(&sha_ctx,
                              pub_signing_key,
                              NTB_ECC_PUBLIC_KEY_SIZE);
                SHA512_Update(&sha_ctx,
                              pub_encryption_key,
                              NTB_ECC_PUBLIC_KEY_SIZE);
                SHA512_Final(sha_hash, &sha_ctx);

                RIPEMD160(sha_hash, SHA512_DIGEST_LENGTH, ripemd_hash);

                attempts++;
        } while (count_leading_zeroes(ripemd_hash) <
                 cookie->create_key.leading_zeroes);

        cookie->create_key.key =
                ntb_key_new_with_public(crypto->ecc,
                                        cookie->create_key.label,
                                        ripemd_hash,
                                        4, /* version */
                                        1, /* stream */
                                        private_signing_key,
                                        pub_signing_key,
                                        private_encryption_key,
                                        pub_encryption_key);

        ntb_address_encode(cookie->create_key.key->version,
                           cookie->create_key.key->stream,
                           ripemd_hash,
                           address);

        ntb_log("Key pair generated after %i attempt%s. Address is %s",
                attempts,
                attempts == 1 ? "" : "s",
                address);
}

static void
append_public_key(struct ntb_buffer *buffer,
                  const EC_KEY *key)
{
        size_t oct_size;

        ntb_buffer_ensure_size(buffer,
                               buffer->length + NTB_ECC_PUBLIC_KEY_SIZE);

        oct_size = EC_POINT_point2oct(EC_KEY_get0_group(key),
                                      EC_KEY_get0_public_key(key),
                                      POINT_CONVERSION_UNCOMPRESSED,
                                      buffer->data + buffer->length,
                                      NTB_ECC_PUBLIC_KEY_SIZE,
                                      NULL);
        assert(oct_size == NTB_ECC_PUBLIC_KEY_SIZE);

        /* Remove the 0x04 prefix */
        memmove(buffer->data + buffer->length,
                buffer->data + buffer->length + 1,
                NTB_ECC_PUBLIC_KEY_SIZE - 1);

        buffer->length += NTB_ECC_PUBLIC_KEY_SIZE - 1;
}

static void
append_key_base(struct ntb_key *key,
                struct ntb_buffer *buffer,
                size_t *behaviors_offset)
{
        /* Leave space for the nonce. The caller will have to
         * calculate this */
        ntb_buffer_set_length(buffer, buffer->length + sizeof (uint64_t));

        ntb_proto_add_64(buffer, key->last_pubkey_send_time);
        ntb_proto_add_var_int(buffer, key->version);
        ntb_proto_add_var_int(buffer, key->stream);

        if (behaviors_offset)
                *behaviors_offset = buffer->length;

        ntb_proto_add_32(buffer, NTB_CRYPTO_PUBKEY_BEHAVIORS);
        append_public_key(buffer, key->signing_key);
        append_public_key(buffer, key->encryption_key);
}

static void
append_signature(struct ntb_buffer *buffer,
                 struct ntb_key *key,
                 const uint8_t *data,
                 size_t length)
{
        uint8_t digest[SHA_DIGEST_LENGTH];
        unsigned int sig_length = ECDSA_size(key->signing_key);
        uint8_t *sig = alloca(sig_length);
        int int_ret;

        SHA1(data, length, digest);

        int_ret = ECDSA_sign(0, /* type (ignored) */
                             digest,
                             SHA_DIGEST_LENGTH,
                             sig,
                             &sig_length,
                             key->signing_key);
        assert(int_ret);

        ntb_proto_add_var_int(buffer, sig_length);
        ntb_buffer_append(buffer, sig, sig_length);
}

static void
append_v34_key_base(struct ntb_key *key,
                    struct ntb_buffer *buffer,
                    size_t *behaviors_offset)
{
        append_key_base(key, buffer, behaviors_offset);

        ntb_proto_add_var_int(buffer, key->nonce_trials_per_byte);
        ntb_proto_add_var_int(buffer, key->payload_length_extra_bytes);

        append_signature(buffer,
                         key,
                         buffer->data + sizeof (uint64_t),
                         buffer->length - sizeof (uint64_t));
}

static struct ntb_blob *
create_v4_key(struct ntb_crypto *crypto,
              struct ntb_key *key)
{
        struct ntb_blob *blob;
        struct ntb_buffer buffer;
        size_t behaviors_offset;
        EC_POINT *tag_public_key_point;
        struct ntb_buffer encrypted_buffer;

        ntb_buffer_init(&buffer);
        ntb_blob_dynamic_init(&encrypted_buffer,
                              NTB_PROTO_INV_TYPE_PUBKEY);

        append_v34_key_base(key, &buffer, &behaviors_offset);

        tag_public_key_point =
                ntb_ecc_make_pub_key_point(crypto->ecc,
                                           key->tag_private_key);

        ntb_buffer_append(&encrypted_buffer,
                          buffer.data,
                          behaviors_offset);
        ntb_buffer_append(&encrypted_buffer,
                          key->tag,
                          NTB_KEY_TAG_SIZE);

        ntb_ecc_encrypt_with_point(crypto->ecc,
                                   tag_public_key_point,
                                   buffer.data + behaviors_offset,
                                   buffer.length - behaviors_offset,
                                   &encrypted_buffer);

        EC_POINT_free(tag_public_key_point);

        blob = ntb_blob_dynamic_end(&encrypted_buffer);

        ntb_buffer_destroy(&buffer);

        return blob;
}

static struct ntb_blob *
create_v3_key(struct ntb_key *key)
{
        struct ntb_buffer buffer;

        ntb_blob_dynamic_init(&buffer, NTB_PROTO_INV_TYPE_PUBKEY);

        append_v34_key_base(key, &buffer, NULL);

        return ntb_blob_dynamic_end(&buffer);
}

static struct ntb_blob *
create_v2_key(struct ntb_key *key)
{
        struct ntb_buffer buffer;

        ntb_blob_dynamic_init(&buffer, NTB_PROTO_INV_TYPE_PUBKEY);

        append_key_base(key, &buffer, NULL);

        return ntb_blob_dynamic_end(&buffer);
}

static void
handle_create_pubkey_blob(struct ntb_crypto_cookie *cookie)
{
        struct ntb_key *key = cookie->create_pubkey_blob.key;

        switch (key->version) {
        case 4:
                cookie->create_pubkey_blob.blob =
                        create_v4_key(cookie->crypto, key);
                break;
        case 3:
                cookie->create_pubkey_blob.blob = create_v3_key(key);
                break;
        default:
                cookie->create_pubkey_blob.blob = create_v2_key(key);
                break;
        }
}

static void
check_signature_in_decrypted_msg(struct ntb_crypto_cookie *cookie)
{
        struct ntb_proto_decrypted_msg msg;
        uint8_t public_key[NTB_ECC_PUBLIC_KEY_SIZE];
        EC_KEY *key;
        uint8_t digest[SHA_DIGEST_LENGTH];
        int verify_result;

        ntb_log("Successfully decrypted a message using the key “%s”",
                cookie->decrypt_msg.chosen_key->label);

        if (!ntb_proto_get_decrypted_msg(cookie->decrypt_msg.result->data,
                                         cookie->decrypt_msg.result->size,
                                         &msg)) {
                ntb_log("The decrypted message is invalid");
                goto invalid;
        }

        SHA1(cookie->decrypt_msg.result->data, msg.signed_data_length, digest);

        /* The keys on the network have the 0x04 prefix stripped so we
         * need to add it back on */
        public_key[0] = 0x04;
        memcpy(public_key + 1,
               msg.sender_signing_key,
               NTB_ECC_PUBLIC_KEY_SIZE - 1);

        key = ntb_ecc_create_key_with_public(cookie->crypto->ecc,
                                             NULL, /* private key */
                                             public_key);

        verify_result = ECDSA_verify(0, /* type, ignored */
                                     digest,
                                     sizeof digest,
                                     msg.sig,
                                     msg.sig_length,
                                     key);

        EC_KEY_free(key);

        if (verify_result != 1) {
                ntb_log("The signature in the decrypted message is invalid");
                goto invalid;
        }

        return;

invalid:
        ntb_key_unref(cookie->decrypt_msg.chosen_key);
        cookie->decrypt_msg.chosen_key = NULL;
        ntb_blob_unref(cookie->decrypt_msg.result);
        cookie->decrypt_msg.result = NULL;
}

static void
handle_decrypt_msg(struct ntb_crypto_cookie *cookie)
{
        struct ntb_crypto *crypto = cookie->crypto;
        struct ntb_buffer buffer;
        struct ntb_key *key;
        ssize_t header_size;
        uint64_t pow_nonce;
        int64_t timestamp;
        uint64_t stream_number;
        const uint8_t *data;
        size_t data_length;
        size_t decryption_start;
        int i;

        header_size = ntb_proto_get_command(cookie->decrypt_msg.blob->data,
                                            cookie->decrypt_msg.blob->size,

                                            NTB_PROTO_ARGUMENT_64,
                                            &pow_nonce,

                                            NTB_PROTO_ARGUMENT_TIMESTAMP,
                                            &timestamp,

                                            NTB_PROTO_ARGUMENT_VAR_INT,
                                            &stream_number,

                                            NTB_PROTO_ARGUMENT_END);

        assert(header_size != -1);

        data = cookie->decrypt_msg.blob->data + header_size;
        data_length = cookie->decrypt_msg.blob->size - header_size;

        ntb_blob_dynamic_init(&buffer, NTB_PROTO_INV_TYPE_MSG);

        decryption_start = buffer.length;

        for (i = 0; i < cookie->decrypt_msg.n_keys; i++) {
                key = cookie->decrypt_msg.keys[i];

                if (ntb_ecc_decrypt(crypto->ecc,
                                    key->encryption_key,
                                    data,
                                    data_length,
                                    &buffer)) {
                        cookie->decrypt_msg.chosen_key = ntb_key_ref(key);
                        cookie->decrypt_msg.result =
                                ntb_blob_dynamic_end(&buffer);
                        check_signature_in_decrypted_msg(cookie);
                        return;
                }

                buffer.length = decryption_start;
        }

        ntb_buffer_destroy(&buffer);
}

static void
idle_cb(struct ntb_main_context_source *source,
        void *user_data)
{
        struct ntb_crypto_cookie *cookie = user_data;
        struct ntb_crypto *crypto = cookie->crypto;
        ntb_crypto_create_key_func create_key_func;
        ntb_crypto_create_pubkey_blob_func create_pubkey_blob_func;
        ntb_crypto_decrypt_msg_func decrypt_msg_func;

        switch (cookie->type) {
        case NTB_CRYPTO_COOKIE_CREATE_KEY:
                create_key_func = cookie->func;
                create_key_func(cookie->create_key.key, cookie->user_data);
                break;
        case NTB_CRYPTO_COOKIE_CREATE_PUBKEY_BLOB:
                create_pubkey_blob_func = cookie->func;
                create_pubkey_blob_func(cookie->create_pubkey_blob.blob,
                                        cookie->user_data);
                break;
        case NTB_CRYPTO_COOKIE_DECRYPT_MSG:
                decrypt_msg_func = cookie->func;
                decrypt_msg_func(cookie->decrypt_msg.chosen_key,
                                 cookie->decrypt_msg.result,
                                 cookie->user_data);
                break;
        }

        pthread_mutex_lock(&crypto->mutex);

        unref_cookie(cookie);

        pthread_mutex_unlock(&crypto->mutex);

        ntb_main_context_remove_source(source);
}

static void *
thread_func(void *user_data)
{
        struct ntb_crypto *crypto = user_data;
        struct ntb_crypto_cookie *cookie;
        enum ntb_crypto_cookie_type type;

        /* Seed the random number generator. I think this will happen
         * anyway but it's not really clear from the docs */
        RAND_poll();

        pthread_mutex_lock(&crypto->mutex);

        while (true) {
                while (!crypto->quit && ntb_list_empty(&crypto->queue))
                        pthread_cond_wait(&crypto->cond, &crypto->mutex);

                if (crypto->quit)
                        break;

                cookie = ntb_container_of(crypto->queue.next, cookie, link);

                /* The cookie would have had a reference for being in
                 * the queue. We'll steal this reference */
                ntb_list_remove(&cookie->link);
                cookie->in_queue = false;

                if (!cookie->cancelled) {
                        type = cookie->type;

                        pthread_mutex_unlock(&crypto->mutex);

                        switch (type) {
                        case NTB_CRYPTO_COOKIE_CREATE_KEY:
                                handle_create_key(cookie);
                                break;
                        case NTB_CRYPTO_COOKIE_CREATE_PUBKEY_BLOB:
                                handle_create_pubkey_blob(cookie);
                                break;
                        case NTB_CRYPTO_COOKIE_DECRYPT_MSG:
                                handle_decrypt_msg(cookie);
                                break;
                        }

                        pthread_mutex_lock(&crypto->mutex);

                        /* The cookie may have been cancelled while we were
                         * processing it without the lock */
                        if (!cookie->cancelled)
                                cookie->idle_source =
                                        ntb_main_context_add_idle(NULL,
                                                                  idle_cb,
                                                                  cookie);
                }

                unref_cookie(cookie);
        }

        pthread_mutex_unlock(&crypto->mutex);

        return NULL;
}

struct ntb_crypto *
ntb_crypto_new(void)
{
        struct ntb_crypto *crypto = ntb_alloc(sizeof *crypto);

        crypto->quit = false;

        ntb_list_init(&crypto->queue);

        ntb_slice_allocator_init(&crypto->cookie_allocator,
                                 sizeof (struct ntb_crypto_cookie),
                                 NTB_ALIGNOF (struct ntb_crypto_cookie));

        pthread_cond_init(&crypto->cond, NULL);
        pthread_mutex_init(&crypto->mutex, NULL);
        crypto->thread = ntb_create_thread(thread_func, crypto);

        crypto->ecc = ntb_ecc_new();

        return crypto;
}

struct ntb_crypto_cookie *
ntb_crypto_create_key(struct ntb_crypto *crypto,
                      const char *label,
                      int leading_zeroes,
                      ntb_crypto_create_key_func callback,
                      void *user_data)
{
        struct ntb_crypto_cookie *cookie;

        pthread_mutex_lock(&crypto->mutex);

        cookie = new_cookie(crypto,
                            NTB_CRYPTO_COOKIE_CREATE_KEY,
                            callback,
                            user_data);
        cookie->create_key.label = ntb_strdup(label);
        cookie->create_key.leading_zeroes = leading_zeroes;
        cookie->create_key.key = NULL;

        pthread_mutex_unlock(&crypto->mutex);

        return cookie;
}

struct ntb_crypto_cookie *
ntb_crypto_create_pubkey_blob(struct ntb_crypto *crypto,
                              struct ntb_key *key,
                              ntb_crypto_create_pubkey_blob_func callback,
                              void *user_data)
{
        struct ntb_crypto_cookie *cookie;

        pthread_mutex_lock(&crypto->mutex);

        cookie = new_cookie(crypto,
                            NTB_CRYPTO_COOKIE_CREATE_PUBKEY_BLOB,
                            callback,
                            user_data);
        cookie->create_pubkey_blob.key = ntb_key_ref(key);
        cookie->create_pubkey_blob.blob = NULL;

        pthread_mutex_unlock(&crypto->mutex);

        return cookie;
}

struct ntb_crypto_cookie *
ntb_crypto_decrypt_msg(struct ntb_crypto *crypto,
                       struct ntb_blob *blob,
                       struct ntb_key * const *keys,
                       int n_keys,
                       ntb_crypto_decrypt_msg_func callback,
                       void *user_data)
{
        struct ntb_crypto_cookie *cookie;
        int i;

        pthread_mutex_lock(&crypto->mutex);

        cookie = new_cookie(crypto,
                            NTB_CRYPTO_COOKIE_DECRYPT_MSG,
                            callback,
                            user_data);
        cookie->decrypt_msg.blob = ntb_blob_ref(blob);
        cookie->decrypt_msg.keys =
                ntb_memdup(keys, n_keys * sizeof (struct ntb_key *));
        cookie->decrypt_msg.n_keys = n_keys;
        cookie->decrypt_msg.result = NULL;
        cookie->decrypt_msg.chosen_key = NULL;

        for (i = 0; i < n_keys; i++)
                ntb_key_ref(keys[i]);

        pthread_mutex_unlock(&crypto->mutex);

        return cookie;
}

void
ntb_crypto_cancel_task(struct ntb_crypto_cookie *cookie)
{
        struct ntb_crypto *crypto = cookie->crypto;

        pthread_mutex_lock(&crypto->mutex);

        /* The queue holds a reference to the cookie */
        if (cookie->in_queue) {
                ntb_list_remove(&cookie->link);
                unref_cookie(cookie);
        }

        cookie->cancelled = true;

        if (cookie->idle_source)
                ntb_main_context_remove_source(cookie->idle_source);

        /* One reference is held by the caller */
        unref_cookie(cookie);

        pthread_mutex_unlock(&crypto->mutex);
}

void
ntb_crypto_free(struct ntb_crypto *crypto)
{
        pthread_mutex_lock(&crypto->mutex);
        crypto->quit = true;
        pthread_cond_signal(&crypto->cond);
        pthread_mutex_unlock(&crypto->mutex);
        pthread_join(crypto->thread, NULL);

        pthread_cond_destroy(&crypto->cond);
        pthread_mutex_destroy(&crypto->mutex);

        ntb_slice_allocator_destroy(&crypto->cookie_allocator);

        ntb_ecc_free(crypto->ecc);

        ntb_free(crypto);
}
