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

#include <openssl/sha.h>
#include <assert.h>
#include <string.h>
#include <pthread.h>

#include "ntb-pow.h"
#include "ntb-util.h"
#include "ntb-cpus.h"
#include "ntb-list.h"
#include "ntb-file-error.h"
#include "ntb-main-context.h"

struct ntb_pow {
        int n_threads;
        pthread_t *threads;
        struct ntb_list queue;
        pthread_mutex_t mutex;
        pthread_cond_t cond;
        bool quit;
};

struct ntb_pow_cookie {
        /* This reference count is manipulated with the pow mutex so
         * it doesn't need to be atomic */
        int ref_count;

        struct ntb_pow *pow;

        struct ntb_list link;

        int next_nonce_offset;

        uint8_t hash[SHA512_DIGEST_LENGTH];
        uint64_t target;
        uint64_t nonce;

        ntb_pow_calculate_func func;
        void *user_data;

        bool done;

        struct ntb_main_context_source *idle_source;
};

/* Each thread will only try to check whether another thread has
 * already solved the POW once per this many nonces. Having a lower
 * number will slow down the search because it will lock the mutex and
 * flush caches more often. However a higher number will cause the
 * thread to take longer to notice that another thread has already
 * found the solution */

/* Finding a solution that got to nonce 84450795 on my 4-core CPU took
 * 31.183 seconds. So one core can do 21112698.75 attempts per 31.183
 * seconds, which is 677058 attempts per second. We probably don't
 * want to wait for more than about 10ms for a thread to notice that
 * it should it stop which means we can do up to 6770 attempts before
 * we check. Making this a nice power of two and leaving some room for
 * slower CPUs gives 4096 */

#define NTB_POW_NONCES_PER_CHECK 4096

static void
unref_cookie(struct ntb_pow_cookie *cookie)
{
        /* This should only be called with the lock */

        if (--cookie->ref_count <= 0) {
                /* We don't need to remove the idle source here
                 * because if there is an idle source then that should
                 * be holding a ref and we should never get here. We
                 * couldn't do it anyway because this can be called
                 * from any thread and removing an idle source is not
                 * thread-safe */
                ntb_free(cookie);
        }
}

static void
remove_queued_cookie(struct ntb_pow_cookie *cookie)
{
        /* This should only be called with the lock */

        ntb_list_remove(&cookie->link);
        unref_cookie(cookie);
}

void
ntb_pow_free(struct ntb_pow *pow)
{
        struct ntb_pow_cookie *cookie, *tmp;
        int i;

        pthread_mutex_lock(&pow->mutex);
        pow->quit = true;
        pthread_cond_broadcast(&pow->cond);
        pthread_mutex_unlock(&pow->mutex);

        for (i = 0; i < pow->n_threads; i++)
                pthread_join(pow->threads[i], NULL);

        ntb_list_for_each_safe(cookie, tmp, &pow->queue, link)
                remove_queued_cookie(cookie);

        pthread_mutex_destroy(&pow->mutex);
        pthread_cond_destroy(&pow->cond);

        ntb_free(pow->threads);
        ntb_free(pow);
}

static void
idle_cb(struct ntb_main_context_source *source,
        void *user_data)
{
        struct ntb_pow_cookie *cookie = user_data;
        struct ntb_pow *pow = cookie->pow;
        ntb_pow_calculate_func func;
        void *cb_user_data;
        uint64_t nonce;

        pthread_mutex_lock(&pow->mutex);

        func = cookie->func;
        cb_user_data = cookie->user_data;
        nonce = cookie->nonce;

        ntb_main_context_remove_source(source);
        cookie->idle_source = NULL;

        /* The idle source held a reference */
        unref_cookie(cookie);
        /* Also the initial caller held a reference. It's not allowed
         * to cancel the cookie after the callback is invoked so we
         * can unref it here */
        unref_cookie(cookie);

        pthread_mutex_unlock(&pow->mutex);

        /* We don't really want to hold the lock while the callback is
         * being invoked because it might want to add another
         * calculation during the callback */
        func(nonce, cb_user_data);
}

static void
set_solution(struct ntb_pow_cookie *cookie,
             uint64_t nonce)
{
        struct ntb_pow *pow = cookie->pow;

        pthread_mutex_lock(&pow->mutex);

        /* If the cookie is done then either another thread got here
         * first or it was cancelled. Either way we don't want to do
         * anything */
        if (!cookie->done) {
                cookie->nonce = nonce;
                cookie->done = true;
                cookie->idle_source =
                        ntb_main_context_add_idle(NULL, idle_cb, cookie);
                /* Ref count held by the idle source */
                cookie->ref_count++;
        }

        pthread_mutex_unlock(&pow->mutex);
}

static void
find_nonce(struct ntb_pow_cookie *cookie,
           int nonce_offset)
{
        struct ntb_pow *pow = cookie->pow;
        uint64_t nonce = nonce_offset;
        uint64_t nonce_be;
        uint8_t hash1[SHA512_DIGEST_LENGTH];
        uint8_t hash2[SHA512_DIGEST_LENGTH];
        uint64_t pow_value;
        SHA512_CTX ctx;
        int i;

        /* This should only be called with the lock */

        while (!cookie->done && !pow->quit) {
                pthread_mutex_unlock(&pow->mutex);

                for (i = 0; i < NTB_POW_NONCES_PER_CHECK; i++) {
                        nonce_be = NTB_UINT64_TO_BE(nonce);

                        SHA512_Init(&ctx);
                        SHA512_Update(&ctx, &nonce_be, sizeof nonce_be);
                        SHA512_Update(&ctx, cookie->hash, sizeof cookie->hash);
                        SHA512_Final(hash1, &ctx);

                        SHA512_Init(&ctx);
                        SHA512_Update(&ctx, hash1, sizeof hash1);
                        SHA512_Final(hash2, &ctx);

                        /* The POW value is the first 8 bytes of that
                         * as a big-endian number */
                        memcpy(&pow_value, hash2, sizeof pow_value);
                        pow_value = NTB_UINT64_FROM_BE(pow_value);

                        if (pow_value <= cookie->target) {
                                set_solution(cookie, nonce);
                                break;
                        }

                        nonce += pow->n_threads;
                }

                pthread_mutex_lock(&pow->mutex);
        }
}

static void *
thread_func(void *user_data)
{
        struct ntb_pow *pow = user_data;
        struct ntb_pow_cookie *cookie;
        int nonce_offset;

        pthread_mutex_lock(&pow->mutex);

        while (true) {
                while (!pow->quit && ntb_list_empty(&pow->queue))
                        pthread_cond_wait(&pow->cond, &pow->mutex);

                if (pow->quit)
                        break;

                cookie = ntb_container_of(pow->queue.next, cookie, link);

                cookie->ref_count++;

                nonce_offset = cookie->next_nonce_offset++;

                if (cookie->next_nonce_offset >= pow->n_threads)
                        remove_queued_cookie(cookie);

                find_nonce(cookie, nonce_offset);

                unref_cookie(cookie);
        }

        pthread_mutex_unlock(&pow->mutex);

        return NULL;
}

void
ntb_pow_cancel(struct ntb_pow_cookie *cookie)
{
        struct ntb_pow *pow = cookie->pow;

        pthread_mutex_lock(&pow->mutex);

        /* If the cookie hasn't been seen by all of the threads yet
         * then it is still in queue so we can remove it */
        if (cookie->next_nonce_offset < pow->n_threads)
                remove_queued_cookie(cookie);

        if (cookie->idle_source) {
                /* Having an idle source also holds a reference */
                ntb_main_context_remove_source(cookie->idle_source);
                cookie->idle_source = NULL;
                unref_cookie(cookie);
        }

        cookie->done = true;

        /* This reference is held by the caller */
        unref_cookie(cookie);

        pthread_mutex_unlock(&pow->mutex);
}

struct ntb_pow *
ntb_pow_new(struct ntb_error **error)
{
        struct ntb_pow *pow;
        int thread_ret;
        int n_cpus;

        pow = ntb_alloc(sizeof *pow);

        n_cpus = ntb_cpus_count();

        pthread_mutex_init(&pow->mutex, NULL);
        pthread_cond_init(&pow->cond, NULL);

        ntb_list_init(&pow->queue);
        pow->quit = false;

        pow->threads = ntb_alloc(sizeof (pthread_t) * n_cpus);

        for (pow->n_threads = 0; pow->n_threads < n_cpus; pow->n_threads++) {
                thread_ret = pthread_create(pow->threads + pow->n_threads,
                                            NULL /* attr */,
                                            thread_func,
                                            pow);
                if (thread_ret) {
                        ntb_file_error_set(error,
                                           thread_ret,
                                           "Error creating POW thread: %s",
                                           strerror(thread_ret));
                        ntb_pow_free(pow);
                        return NULL;
                }
        }

        return pow;
}

static uint64_t
calculate_target(size_t length,
                 int payload_extra_bytes,
                 int average_trials_per_byte)
{
        uint64_t divisor, high, low;

        divisor = ((length + (uint64_t) payload_extra_bytes) *
                   average_trials_per_byte);

        /* We need to divide 2⁶⁴ by divisor. We obviously can't do
         * that with a simple division with a 64-bit representation.
         * This tries to do it in a couple of steps */
        high = (UINT64_C(1) << 32) / divisor;
        low = (((UINT64_C(1) << 32) % divisor) << 32) / divisor;

        return (high << 32) | low;
}

struct ntb_pow_cookie *
ntb_pow_calculate(struct ntb_pow *pow,
                  const uint8_t *payload,
                  size_t length,
                  int payload_extra_bytes,
                  int average_trials_per_byte,
                  ntb_pow_calculate_func func,
                  void *user_data)
{
        struct ntb_pow_cookie *cookie;
        uint64_t target;

        cookie = ntb_alloc(sizeof *cookie);

        target = calculate_target(length,
                                  payload_extra_bytes,
                                  average_trials_per_byte);

        pthread_mutex_lock(&pow->mutex);

        /* Once reference is for the caller and one is for being in the queue */
        cookie->ref_count = 2;
        cookie->pow = pow;
        cookie->next_nonce_offset = 0;
        SHA512(payload, length, cookie->hash);
        cookie->target = target;
        cookie->func = func;
        cookie->user_data = user_data;
        cookie->done = false;
        cookie->idle_source = NULL;

        ntb_list_insert(pow->queue.next, &cookie->link);

        pthread_cond_broadcast(&pow->cond);

        pthread_mutex_unlock(&pow->mutex);

        return cookie;
}

bool
ntb_pow_check(const uint8_t *payload,
              size_t length,
              int payload_extra_bytes,
              int average_trials_per_byte)
{
        uint8_t initial_hash[8 + SHA512_DIGEST_LENGTH];
        uint8_t hash1[SHA512_DIGEST_LENGTH];
        uint8_t hash2[SHA512_DIGEST_LENGTH];
        uint64_t pow_value, target;

        assert(length >= 8);

        /* Initial hash is nonce + hash(rest of the data) */
        memcpy(initial_hash, payload, 8);
        SHA512(payload + 8, length - 8, initial_hash + 8);

        /* Get the result hash into hash2 */
        SHA512(initial_hash, sizeof initial_hash, hash1);
        SHA512(hash1, sizeof hash1, hash2);

        /* The POW value is the first 8 bytes of that as a big-endian
         * number */
        memcpy(&pow_value, hash2, sizeof pow_value);
        pow_value = NTB_UINT64_FROM_BE(pow_value);

        target = calculate_target(length - sizeof (uint64_t),
                                  payload_extra_bytes,
                                  average_trials_per_byte);

        return pow_value <= target;
}
