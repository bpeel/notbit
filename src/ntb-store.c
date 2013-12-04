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
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <pthread.h>
#include <stdio.h>
#include <unistd.h>

#include "ntb-store.h"
#include "ntb-util.h"
#include "ntb-buffer.h"
#include "ntb-log.h"
#include "ntb-list.h"
#include "ntb-slice.h"
#include "ntb-proto.h"

struct ntb_error_domain
ntb_store_error;

struct ntb_store {
        struct ntb_buffer filename_buf;
        struct ntb_buffer tmp_buf;
        int directory_len;

        pthread_mutex_t mutex;
        pthread_cond_t cond;
        pthread_t thread;

        struct ntb_list queue;

        /* The slice allocator has to be per-store rather than a
         * global variable so that we can be sure to use it only when
         * the mutex is locked in order to make it thread-safe */
        struct ntb_slice_allocator allocator;

        bool quit;
};

enum ntb_store_task_type {
        NTB_STORE_TASK_TYPE_SAVE_BLOB
};

struct ntb_store_task {
        struct ntb_list link;
        enum ntb_store_task_type type;

        union {
                struct {
                        uint8_t hash[NTB_PROTO_HASH_LENGTH];
                        struct ntb_blob *blob;
                };
        };
};

static void
strip_trailing_slashes(struct ntb_buffer *buffer)
{
        /* Strip all but the first slash */
        while (buffer->length > 1 && buffer->data[buffer->length - 1] == '/')
                buffer->length--;
}

static bool
try_mkdir(const char *name, struct ntb_error **error)
{
        if (mkdir(name, S_IRWXU | S_IRWXG | S_IRWXO) == -1 && errno != EEXIST) {
                ntb_set_error(error,
                              &ntb_store_error,
                              NTB_STORE_ERROR_CREATING_DIRECTORY,
                              "Error creating store directory: %s",
                              strerror(errno));
                return false;
        }

        return true;
}

static bool
make_directory_hierarchy(struct ntb_buffer *buf,
                         struct ntb_error **error)
{
        uint8_t *slash;

        if (buf->length < 1)
                return true;

        slash = buf->data;

        while ((slash = memchr(slash + 1,
                               '/',
                               buf->data + buf->length - slash))) {
                *slash = '\0';

                if (!try_mkdir((const char *) buf->data, error))
                        return false;

                *slash = '/';
        }

        if (buf->data[buf->length - 1] != '/') {
                ntb_buffer_append_c(buf, '\0');
                buf->length--;
                if (!try_mkdir((const char *) buf->data, error))
                        return false;
        }

        return true;
}

static bool
init_store_directory(struct ntb_store *store,
                     const char *store_directory,
                     struct ntb_error **error)
{
        const char *data_home, *home;

        if (store_directory) {
                ntb_buffer_append_string(&store->filename_buf,
                                         store_directory);
                strip_trailing_slashes(&store->filename_buf);
                ntb_buffer_append_string(&store->filename_buf, "/objects/");
        } else if ((data_home = getenv("XDG_DATA_HOME"))) {
                if (data_home[0] != '/') {
                        ntb_set_error(error,
                                      &ntb_store_error,
                                      NTB_STORE_ERROR_INVALID_STORE_DIRECTORY,
                                      "The XDG_DATA_HOME path is not "
                                      "absolute");
                        return false;
                }

                ntb_buffer_append_string(&store->filename_buf,
                                         data_home);
                strip_trailing_slashes(&store->filename_buf);
                ntb_buffer_append_string(&store->filename_buf,
                                         "/notbit/objects/");
        } else if ((home = getenv("HOME"))) {
                if (home[0] != '/') {
                        ntb_set_error(error,
                                      &ntb_store_error,
                                      NTB_STORE_ERROR_INVALID_STORE_DIRECTORY,
                                      "The HOME path is not "
                                      "absolute");
                        return false;
                }

                ntb_buffer_append_string(&store->filename_buf, home);
                strip_trailing_slashes(&store->filename_buf);
                ntb_buffer_append_string(&store->filename_buf,
                                         "/.local/share/notbit/objects/");
        } else {
                ntb_set_error(error,
                              &ntb_store_error,
                              NTB_STORE_ERROR_INVALID_STORE_DIRECTORY,
                              "Neither XDG_DATA_HOME nor HOME is set");
                return false;
        }

        if (!make_directory_hierarchy(&store->filename_buf, error))
                return false;

        store->directory_len = store->filename_buf.length;

        return true;
}

static void
handle_save_blob(struct ntb_store *store,
                 struct ntb_store_task *task)
{
        FILE *file;
        uint32_t type;
        int i;

        store->filename_buf.length = store->directory_len;

        for (i = 0; i < NTB_PROTO_HASH_LENGTH; i++)
                ntb_buffer_append_printf(&store->filename_buf,
                                         "%02x",
                                         task->hash[i]);

        ntb_buffer_append_string(&store->filename_buf, ".tmp");

        file = fopen((char *) store->filename_buf.data, "wb");

        if (file == NULL) {
                ntb_log("Error opening %s: %s",
                        (char *) store->filename_buf.data,
                        strerror(errno));
                return;
        }

        type = NTB_UINT32_TO_BE(task->blob->type);

        if (fwrite(&type, 1, sizeof type, file) != sizeof type ||
            fwrite(task->blob->data, 1, task->blob->size, file) !=
            task->blob->size) {
                ntb_log("Error writing %s: %s",
                        (char *) store->filename_buf.data,
                        strerror(errno));
                fclose(file);
                unlink((char *) store->filename_buf.data);
                return;
        }

        if (fclose(file) == EOF) {
                ntb_log("Error writing %s: %s",
                        (char *) store->filename_buf.data,
                        strerror(errno));
                unlink((char *) store->filename_buf.data);
                return;
        }

        store->tmp_buf.length = 0;
        ntb_buffer_append(&store->tmp_buf,
                          store->filename_buf.data,
                          store->filename_buf.length - 4);
        ntb_buffer_append_c(&store->tmp_buf, '\0');

        if (rename((char *) store->filename_buf.data,
                   (char *) store->tmp_buf.data) == -1) {
                ntb_log("Error renaming %s to %s: %s",
                        (char *) store->filename_buf.data,
                        (char *) store->tmp_buf.data,
                        strerror(errno));
                unlink((char *) store->filename_buf.data);
        }
}

static void
free_task(struct ntb_store *store,
           struct ntb_store_task *task)
{
        /* This must be called with the lock */

        switch (task->type) {
        case NTB_STORE_TASK_TYPE_SAVE_BLOB:
                ntb_blob_unref(task->blob);
                break;
        }

        ntb_slice_free(&store->allocator, task);
}

static void *
store_thread_func(void *user_data)
{
        struct ntb_store *store = user_data;
        struct ntb_store_task *task;

        pthread_mutex_lock(&store->mutex);

        while (true) {
                /* Block until there is something to do */
                while (!store->quit && ntb_list_empty(&store->queue))
                        pthread_cond_wait(&store->cond, &store->mutex);

                if (store->quit && ntb_list_empty(&store->queue))
                        break;

                task = ntb_container_of(store->queue.next, task, link);
                ntb_list_remove(&task->link);

                pthread_mutex_unlock(&store->mutex);

                switch (task->type) {
                case NTB_STORE_TASK_TYPE_SAVE_BLOB:
                        handle_save_blob(store, task);
                        break;
                }

                pthread_mutex_lock(&store->mutex);

                free_task(store, task);
        }

        pthread_mutex_unlock(&store->mutex);

        return NULL;
}

struct ntb_store *
ntb_store_new(const char *store_directory,
              struct ntb_error **error)
{
        struct ntb_store *store = ntb_alloc(sizeof *store);

        ntb_list_init(&store->queue);
        store->quit = false;

        ntb_buffer_init(&store->filename_buf);

        if (!init_store_directory(store, store_directory, error))
                goto error;

        pthread_mutex_init(&store->mutex, NULL /* attrs */);
        pthread_cond_init(&store->cond, NULL /* attrs */);

        if (pthread_create(&store->thread,
                           NULL, /* attr */
                           store_thread_func,
                           store)) {
                pthread_cond_destroy(&store->cond);
                pthread_mutex_destroy(&store->mutex);
                goto error;
        }

        ntb_slice_allocator_init(&store->allocator,
                                 sizeof (struct ntb_store_task),
                                 NTB_ALIGNOF(struct ntb_store_task));
        ntb_buffer_init(&store->tmp_buf);

        return store;

error:
        ntb_buffer_destroy(&store->filename_buf);
        ntb_free(store);
        return NULL;
}

static struct ntb_store_task *
new_task(struct ntb_store *store,
          enum ntb_store_task_type type)
{
        struct ntb_store_task *task;

        /* This should only be called while the mutex is held */

        task = ntb_slice_alloc(&store->allocator);
        task->type = type;
        ntb_list_insert(&store->queue, &task->link);

        pthread_cond_signal(&store->cond);

        return task;
}

void
ntb_store_save_blob(struct ntb_store *store,
                    const uint8_t *hash,
                    struct ntb_blob *blob)
{
        struct ntb_store_task *task;

        pthread_mutex_lock(&store->mutex);

        task = new_task(store, NTB_STORE_TASK_TYPE_SAVE_BLOB);
        memcpy(task->hash, hash, NTB_PROTO_HASH_LENGTH);
        task->blob = ntb_blob_ref(blob);

        pthread_mutex_unlock(&store->mutex);
}

void
ntb_store_free(struct ntb_store *store)
{
        struct ntb_store_task *task, *tmp;

        pthread_mutex_lock(&store->mutex);
        store->quit = true;
        pthread_cond_signal(&store->cond);
        pthread_mutex_unlock(&store->mutex);
        pthread_join(store->thread, NULL);

        ntb_list_for_each_safe(task, tmp, &store->queue, link)
                free_task(store, task);

        ntb_buffer_destroy(&store->tmp_buf);
        ntb_buffer_destroy(&store->filename_buf);

        ntb_slice_allocator_destroy(&store->allocator);

        ntb_free(store);
}
