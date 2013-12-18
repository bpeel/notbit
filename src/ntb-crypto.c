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
#include <assert.h>

#include "ntb-crypto.h"
#include "ntb-util.h"
#include "ntb-slice.h"
#include "ntb-list.h"
#include "ntb-main-context.h"
#include "ntb-log.h"
#include "ntb-address.h"
#include "ntb-pub-key-maker.h"

struct ntb_crypto {
        pthread_mutex_t mutex;
        pthread_cond_t cond;
        pthread_t thread;
        bool quit;

        struct ntb_slice_allocator cookie_allocator;

        struct ntb_list queue;

        struct ntb_pub_key_maker *pub_key_maker;
};

enum ntb_crypto_cookie_type {
        NTB_CRYPTO_COOKIE_CREATE_KEY
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
        };
};

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
        /* This should only be called with the lock */

        if (--cookie->ref_count <= 0) {
                switch (cookie->type) {
                case NTB_CRYPTO_COOKIE_CREATE_KEY:
                        if (cookie->create_key.key)
                                ntb_key_unref(cookie->create_key.key);
                        ntb_free(cookie->create_key.label);
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

        result = RAND_bytes(private_key, NTB_KEY_PRIVATE_SIZE);
        assert(result);

        ntb_pub_key_maker_make(crypto->pub_key_maker, private_key, public_key);
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
        uint8_t private_signing_key[NTB_KEY_PRIVATE_SIZE];
        uint8_t pub_signing_key[NTB_KEY_PUBLIC_SIZE + 1];
        uint8_t private_encryption_key[NTB_KEY_PRIVATE_SIZE];
        uint8_t pub_encryption_key[NTB_KEY_PUBLIC_SIZE + 1];
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
                              NTB_KEY_PUBLIC_SIZE + 1);
                SHA512_Update(&sha_ctx,
                              pub_encryption_key,
                              NTB_KEY_PUBLIC_SIZE + 1);
                SHA512_Final(sha_hash, &sha_ctx);

                RIPEMD160(sha_hash, SHA512_DIGEST_LENGTH, ripemd_hash);

                attempts++;
        } while (count_leading_zeroes(ripemd_hash) <
                 cookie->create_key.leading_zeroes);

        ntb_address_encode(4, 1, ripemd_hash, address);

        ntb_log("Key pair generated after %i attempt%s. Address is %s",
                attempts,
                attempts == 1 ? "" : "s",
                address);

        cookie->create_key.key =
                ntb_key_new(cookie->create_key.label,
                            ripemd_hash,
                            private_signing_key,
                            pub_signing_key + 1,
                            private_encryption_key,
                            pub_encryption_key + 1);
}

static void
idle_cb(struct ntb_main_context_source *source,
        void *user_data)
{
        struct ntb_crypto_cookie *cookie = user_data;
        struct ntb_crypto *crypto = cookie->crypto;
        ntb_crypto_create_key_func create_key_func;

        switch (cookie->type) {
        case NTB_CRYPTO_COOKIE_CREATE_KEY:
                create_key_func = cookie->func;
                create_key_func(cookie->create_key.key, cookie->user_data);
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

                if (!cookie->cancelled) {
                        type = cookie->type;

                        pthread_mutex_unlock(&crypto->mutex);

                        switch (type) {
                        case NTB_CRYPTO_COOKIE_CREATE_KEY:
                                handle_create_key(cookie);
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

        crypto->pub_key_maker = ntb_pub_key_maker_new();

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

        ntb_pub_key_maker_free(crypto->pub_key_maker);

        ntb_free(crypto);
}
