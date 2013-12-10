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
#include <sys/types.h>
#include <dirent.h>
#include <assert.h>
#include <inttypes.h>

#include "ntb-store.h"
#include "ntb-util.h"
#include "ntb-buffer.h"
#include "ntb-log.h"
#include "ntb-list.h"
#include "ntb-slice.h"
#include "ntb-proto.h"
#include "ntb-main-context.h"
#include "ntb-file-error.h"

struct ntb_error_domain
ntb_store_error;

struct ntb_store {
        struct ntb_buffer filename_buf;
        struct ntb_buffer tmp_buf;
        int directory_len;

        pthread_mutex_t mutex;
        pthread_cond_t cond;
        pthread_t thread;
        bool started;

        struct ntb_list queue;

        /* The slice allocator has to be per-store rather than a
         * global variable so that we can be sure to use it only when
         * the mutex is locked in order to make it thread-safe */
        struct ntb_slice_allocator allocator;

        bool quit;
};

enum ntb_store_task_type {
        NTB_STORE_TASK_TYPE_SAVE_BLOB,
        NTB_STORE_TASK_TYPE_LOAD_BLOB,
        NTB_STORE_TASK_TYPE_SAVE_ADDR_LIST,
        NTB_STORE_TASK_TYPE_DELETE_OBJECT
};

struct ntb_store_task {
        struct ntb_list link;
        enum ntb_store_task_type type;

        union {
                struct {
                        uint8_t hash[NTB_PROTO_HASH_LENGTH];
                        struct ntb_blob *blob;
                } save_blob;

                struct {
                        uint8_t hash[NTB_PROTO_HASH_LENGTH];
                        struct ntb_store_cookie *cookie;
                } load_blob;

                struct {
                        struct ntb_store_addr *addrs;
                        int n_addrs;
                } save_addr_list;

                struct {
                        uint8_t hash[NTB_PROTO_HASH_LENGTH];
                } delete_object;
        };
};

struct ntb_store_cookie {
        struct ntb_store *store;
        struct ntb_blob *blob;
        struct ntb_store_task *task;
        struct ntb_main_context_source *idle_source;
        ntb_store_load_callback func;
        void *user_data;
};

/* The cookies are only allocated and destroyed in the main thread so
 * we don't need to have a per-store allocator */
NTB_SLICE_ALLOCATOR(struct ntb_store_cookie, ntb_store_cookie_allocator);

static struct ntb_store *ntb_store_default = NULL;

static struct ntb_store *
ntb_store_get_default_or_abort(void)
{
        struct ntb_store *store;

        store = ntb_store_get_default();

        if (store == NULL)
                ntb_fatal("default store is missing");

        return store;
}

struct ntb_store *
ntb_store_get_default(void)
{
        return ntb_store_default;
}

void
ntb_store_set_default(struct ntb_store *store)
{
        ntb_store_default = store;
}

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
                ntb_file_error_set(error,
                                   errno,
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
                ntb_buffer_append_string(&store->filename_buf, "/");
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
                                         "/notbit/");
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
                                         "/.local/share/notbit/");
        } else {
                ntb_set_error(error,
                              &ntb_store_error,
                              NTB_STORE_ERROR_INVALID_STORE_DIRECTORY,
                              "Neither XDG_DATA_HOME nor HOME is set");
                return false;
        }

        store->directory_len = store->filename_buf.length;

        ntb_buffer_append_string(&store->filename_buf, "objects");

        if (!make_directory_hierarchy(&store->filename_buf, error))
                return false;

        return true;
}

static void
append_hash(struct ntb_buffer *buffer,
            const uint8_t *hash)
{
        int i;

        for (i = 0; i < NTB_PROTO_HASH_LENGTH; i++)
                ntb_buffer_append_printf(buffer, "%02x", hash[i]);
}

static void
load_blob_idle_cb(struct ntb_main_context_source *source,
                  void *user_data)
{
        struct ntb_store_cookie *cookie = user_data;

        cookie->func(cookie->blob, cookie->user_data);

        if (cookie->blob)
                ntb_blob_unref(cookie->blob);

        ntb_slice_free(&ntb_store_cookie_allocator, cookie);

        ntb_main_context_remove_source(source);
}

static bool
read_all(const char *filename,
         void *data,
         size_t size,
         FILE *stream)
{
        errno = 0;

        if (fread(data, 1, size, stream) != size) {
                if (errno == 0)
                        ntb_log("The object file %s is too short",
                                filename);
                else
                        ntb_log("Error reading %s: %s",
                                filename,
                                strerror(errno));

                return false;
        }

        return true;
}

static struct ntb_blob *
load_blob_from_file(const char *filename,
                    FILE *file)
{
        struct stat statbuf;
        struct ntb_blob *blob;
        uint32_t type;

        if (fstat(fileno(file), &statbuf) == -1) {
                ntb_log("Error getting info for %s", filename);
                return NULL;
        }

        if (statbuf.st_size < sizeof (uint32_t)) {
                ntb_log("Object file %s is too short", filename);
                return NULL;
        }

        if (!read_all(filename, &type, sizeof type, file))
                return NULL;

        blob = ntb_blob_new(NTB_UINT32_FROM_BE(type),
                            NULL /* data */,
                            statbuf.st_size - sizeof (uint32_t));

        if (!read_all(filename, blob->data, blob->size, file)) {
                ntb_blob_unref(blob);
                return NULL;
        }

        return blob;
}

static void
set_hash_filename(struct ntb_store *store,
                  const uint8_t *hash)
{
        store->filename_buf.length = store->directory_len;
        ntb_buffer_append_string(&store->filename_buf, "objects/");
        append_hash(&store->filename_buf, hash);
}

static void
handle_load_blob(struct ntb_store *store,
                 struct ntb_store_task *task)
{
        struct ntb_blob *blob = NULL;
        FILE *file;

        /* As a special case this the lock is still held when this
         * function is called */

        /* If the task was cancelled before we got here then the
         * cookie will have been reset to NULL. In that case we don't
         * need to do anything */
        if (task->load_blob.cookie == NULL)
                return;

        pthread_mutex_unlock(&store->mutex);

        set_hash_filename(store, task->load_blob.hash);

        file = fopen((char *) store->filename_buf.data, "rb");

        if (file == NULL) {
                ntb_log("Error opening %s: %s",
                        (char *) store->filename_buf.data,
                        strerror(errno));
        } else {
                blob = load_blob_from_file((char *) store->filename_buf.data,
                                           file);

                fclose(file);
        }

        pthread_mutex_lock(&store->mutex);

        /* The task could have also been cancelled while we were
         * loading with the mutex unlocked */
        if (task->load_blob.cookie == NULL) {
                if (blob)
                        ntb_blob_unref(blob);
                return;
        }

        task->load_blob.cookie->blob = blob;
        task->load_blob.cookie->idle_source =
                ntb_main_context_add_idle(NULL,
                                          load_blob_idle_cb,
                                          task->load_blob.cookie);
}

static void
handle_save_blob(struct ntb_store *store,
                 struct ntb_store_task *task)
{
        FILE *file;
        uint32_t type;

        set_hash_filename(store, task->save_blob.hash);

        ntb_buffer_append_string(&store->filename_buf, ".tmp");

        file = fopen((char *) store->filename_buf.data, "wb");

        if (file == NULL) {
                ntb_log("Error opening %s: %s",
                        (char *) store->filename_buf.data,
                        strerror(errno));
                return;
        }

        type = NTB_UINT32_TO_BE(task->save_blob.blob->type);

        if (fwrite(&type, 1, sizeof type, file) != sizeof type ||
            fwrite(task->save_blob.blob->data, 1,
                   task->save_blob.blob->size, file) !=
            task->save_blob.blob->size) {
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
handle_delete_object(struct ntb_store *store,
                     struct ntb_store_task *task)
{
        set_hash_filename(store, task->delete_object.hash);

        if (unlink((char *) store->filename_buf.data) == -1) {
                ntb_log("Error deleting %s: %s",
                        (char *) store->filename_buf.data,
                        strerror(errno));
        }
}

static void
handle_save_addr_list(struct ntb_store *store,
                      struct ntb_store_task *task)
{
        struct ntb_store_addr *addrs;
        char *address;
        FILE *out;
        int i;

        ntb_log("Saving addr list");

        store->filename_buf.length = store->directory_len;
        ntb_buffer_append_string(&store->filename_buf,
                                 "addr-list.txt.tmp");

        addrs = task->save_addr_list.addrs;

        out = fopen((char *) store->filename_buf.data, "w");

        if (out == NULL) {
                ntb_log("Error opening %s: %s",
                        (char *) store->filename_buf.data,
                        strerror(errno));
                return;
        }

        for (i = 0; i < task->save_addr_list.n_addrs; i++) {
                address = ntb_netaddress_to_string(&addrs[i].address);
                fprintf(out,
                        "%" PRIi64 ",%" PRIu32 ",%" PRIu64 ",%s\n",
                        addrs[i].timestamp,
                        addrs[i].stream,
                        addrs[i].services,
                        address);
                ntb_free(address);
        }

        if (fclose(out) == EOF) {
                ntb_log("Error writing to %s: %s",
                        (char *) store->filename_buf.data,
                        strerror(errno));
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
        }
}

static void
free_task(struct ntb_store *store,
          struct ntb_store_task *task)
{
        /* This must be called with the lock */

        switch (task->type) {
        case NTB_STORE_TASK_TYPE_SAVE_BLOB:
                ntb_blob_unref(task->save_blob.blob);
                break;
        case NTB_STORE_TASK_TYPE_LOAD_BLOB:
        case NTB_STORE_TASK_TYPE_DELETE_OBJECT:
                break;
        case NTB_STORE_TASK_TYPE_SAVE_ADDR_LIST:
                ntb_free(task->save_addr_list.addrs);
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

                if (task->type == NTB_STORE_TASK_TYPE_LOAD_BLOB) {
                        /* This special case needs to keep the lock
                         * held for part of the task */
                        handle_load_blob(store, task);
                } else {
                        pthread_mutex_unlock(&store->mutex);

                        switch (task->type) {
                        case NTB_STORE_TASK_TYPE_SAVE_BLOB:
                                handle_save_blob(store, task);
                                break;
                        case NTB_STORE_TASK_TYPE_DELETE_OBJECT:
                                handle_delete_object(store, task);
                                break;
                        case NTB_STORE_TASK_TYPE_SAVE_ADDR_LIST:
                                handle_save_addr_list(store, task);
                                break;
                        case NTB_STORE_TASK_TYPE_LOAD_BLOB:
                                assert(false);
                                break;
                        }

                        pthread_mutex_lock(&store->mutex);
                }

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
        store->started = false;

        ntb_buffer_init(&store->filename_buf);

        if (!init_store_directory(store, store_directory, error))
                goto error;

        pthread_mutex_init(&store->mutex, NULL /* attrs */);
        pthread_cond_init(&store->cond, NULL /* attrs */);

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

bool
ntb_store_start(struct ntb_store *store,
                struct ntb_error **error)
{
        int thread_result;

        if (store->started)
                return true;

        thread_result = pthread_create(&store->thread,
                                       NULL, /* attr */
                                       store_thread_func,
                                       store);
        if (thread_result) {
                ntb_file_error_set(error,
                                   thread_result,
                                   "Error starting store thread");
                return false;
        }

        store->started = true;

        return true;
}

static struct ntb_store_task *
new_task(struct ntb_store *store,
          enum ntb_store_task_type type)
{
        struct ntb_store_task *task;

        /* This should only be called while the mutex is held */

        task = ntb_slice_alloc(&store->allocator);
        task->type = type;
        ntb_list_insert(store->queue.prev, &task->link);

        pthread_cond_signal(&store->cond);

        return task;
}

void
ntb_store_save_blob(struct ntb_store *store,
                    const uint8_t *hash,
                    struct ntb_blob *blob)
{
        struct ntb_store_task *task;

        if (store == NULL)
                store = ntb_store_get_default_or_abort();

        pthread_mutex_lock(&store->mutex);

        task = new_task(store, NTB_STORE_TASK_TYPE_SAVE_BLOB);
        memcpy(task->save_blob.hash, hash, NTB_PROTO_HASH_LENGTH);
        task->save_blob.blob = ntb_blob_ref(blob);

        pthread_mutex_unlock(&store->mutex);
}

void
ntb_store_delete_object(struct ntb_store *store,
                        const uint8_t *hash)
{
        struct ntb_store_task *task;

        if (store == NULL)
                store = ntb_store_get_default_or_abort();

        pthread_mutex_lock(&store->mutex);

        task = new_task(store, NTB_STORE_TASK_TYPE_DELETE_OBJECT);
        memcpy(task->delete_object.hash, hash, NTB_PROTO_HASH_LENGTH);

        pthread_mutex_unlock(&store->mutex);
}

void
ntb_store_save_addr_list(struct ntb_store *store,
                         struct ntb_store_addr *addrs,
                         int n_addrs)
{
        struct ntb_store_task *task;

        /* This function takes ownership of the addrs array */

        if (store == NULL)
                store = ntb_store_get_default_or_abort();

        pthread_mutex_lock(&store->mutex);

        task = new_task(store, NTB_STORE_TASK_TYPE_SAVE_ADDR_LIST);

        task->save_addr_list.addrs = addrs;
        task->save_addr_list.n_addrs = n_addrs;

        pthread_mutex_unlock(&store->mutex);
}

static int
hex_digit_value(int ch)
{
        if (ch >= 'a')
                return ch - 'a' + 10;
        if (ch >= 'A')
                return ch - 'A' + 10;

        return ch - '0';
}

static bool
is_hex_digit(int ch)
{
        return ((ch >= 'a' && ch <= 'f') ||
                (ch >= 'A' && ch <= 'F') ||
                (ch >= '0' && ch <= '9'));
}

static void
process_file(struct ntb_store *store,
             const char *filename,
             ntb_store_for_each_blob_func func,
             void *user_data)
{
        uint8_t hash[NTB_PROTO_HASH_LENGTH];
        uint8_t buf[sizeof (uint32_t) + sizeof (uint64_t) * 2];
        uint32_t type;
        int64_t timestamp;
        FILE *file;
        const char *p;
        const uint8_t *buf_ptr;
        uint32_t length;
        int64_t now;
        bool read_ret;
        int i;

        p = filename + store->directory_len + 8;

        for (i = 0; i < NTB_PROTO_HASH_LENGTH; i++) {
                /* Skip files that don't look like a hash */
                if (!is_hex_digit(p[0]) ||
                    !is_hex_digit(p[1]))
                        return;

                hash[i] = ((hex_digit_value(p[0]) << 4) |
                           hex_digit_value(p[1]));
                p += 2;
        }

        /* Delete any temporary files. These could be left around if
         * notbit crashes while writing a file */
        if (!strcmp(p, ".tmp")) {
                if (unlink(filename) == -1)
                        ntb_log("Error deleting %s: %s",
                                filename,
                                strerror(errno));
                return;
        } else if (p[0] != '\0') {
                return;
        }

        file = fopen(filename, "rb");
        if (file == NULL) {
                ntb_log("Error reading %s: %s",
                        filename,
                        strerror(errno));
                return;
        }

        /* All of the files should start with a 32-bit type, the
         * 64-bit nonce and then either a 32-bit or 64-bit timestamp.
         * We only need the type and timestamp so we don't need to
         * read the rest */
        read_ret = read_all(filename, buf, sizeof buf, file);

        fclose(file);

        if (!read_ret)
                return;

        now = ntb_main_context_get_wall_clock(NULL);

        type = ntb_proto_get_32(buf);
        buf_ptr = buf + sizeof (uint32_t) + sizeof (uint64_t);
        length = sizeof (uint64_t);
        ntb_proto_get_timestamp(&buf_ptr, &length, &timestamp);

        if (now - timestamp >= (ntb_proto_get_max_age_for_type(type) +
                                NTB_PROTO_EXTRA_AGE)) {
                if (unlink(filename) == -1)
                        ntb_log("Error deleting %s: %s",
                                filename,
                                strerror(errno));
        } else {
                func(type, hash, timestamp, user_data);
        }
}

void
ntb_store_for_each_blob(struct ntb_store *store,
                        ntb_store_for_each_blob_func func,
                        void *user_data)
{
        DIR *dir;
        struct dirent *dirent;

        if (store == NULL)
                store = ntb_store_get_default_or_abort();

        /* This function runs synchronously but it should only be
         * called once at startup before connecting to any peers so it
         * shouldn't really matter */

        ntb_log("Loading saved object store");

        store->filename_buf.length = store->directory_len;
        ntb_buffer_append_string(&store->filename_buf, "objects");

        dir = opendir((char *) store->filename_buf.data);
        if (dir == NULL) {
                ntb_log("Error listing %s: %s",
                        (char *) store->filename_buf.data,
                        strerror(errno));
                return;
        }

        ntb_buffer_append_c(&store->filename_buf, '/');

        while ((dirent = readdir(dir))) {
                store->filename_buf.length = store->directory_len + 8;
                ntb_buffer_append_string(&store->filename_buf, dirent->d_name);

                process_file(store,
                             (char *) store->filename_buf.data,
                             func,
                             user_data);
        }

        closedir(dir);

        ntb_log("Finished loading object store");
}

static void
process_addr_line(struct ntb_store *store,
                  char *line,
                  ntb_store_for_each_addr_func func,
                  void *user_data)
{
        struct ntb_store_addr addr;
        int address_length;
        char *tail;

        addr.timestamp = strtoll(line, &tail, 10);

        if (tail == line || *tail != ',')
                return;

        line = tail + 1;
        addr.stream = strtoul(line, &tail, 10);

        if (tail == line || *tail != ',')
                return;

        line = tail + 1;
        addr.services = strtoull(line, &tail, 10);

        if (tail == line || *tail != ',')
                return;

        line = tail + 1;
        address_length = strlen(line);

        if (address_length > 0 && line[address_length - 1] == '\n')
                line[--address_length] = '\0';

        if (!ntb_netaddress_from_string(&addr.address, line))
                return;

        func(&addr, user_data);
}

void
ntb_store_for_each_addr(struct ntb_store *store,
                        ntb_store_for_each_addr_func func,
                        void *user_data)
{
        FILE *file;
        char line[1024];

        if (store == NULL)
                store = ntb_store_get_default_or_abort();

        /* This function runs synchronously but it should only be
         * called once at startup before connecting to any peers so it
         * shouldn't really matter */

        ntb_log("Loading saved address list");

        store->filename_buf.length = store->directory_len;
        ntb_buffer_append_string(&store->filename_buf, "addr-list.txt");

        file = fopen((char *) store->filename_buf.data, "r");

        if (file == NULL) {
                if (errno != ENOENT)
                        ntb_log("Error opening %s: %s",
                                (char *) store->filename_buf.data,
                                strerror(errno));
                return;
        }

        while(fgets(line, sizeof line, file))
                process_addr_line(store, line, func, user_data);

        fclose(file);
}

struct ntb_store_cookie *
ntb_store_load_blob(struct ntb_store *store,
                    const uint8_t *hash,
                    ntb_store_load_callback func,
                    void *user_data)
{
        struct ntb_store_task *task;
        struct ntb_store_cookie *cookie;

        if (store == NULL)
                store = ntb_store_get_default_or_abort();

        pthread_mutex_lock(&store->mutex);

        task = new_task(store, NTB_STORE_TASK_TYPE_LOAD_BLOB);
        memcpy(task->load_blob.hash, hash, NTB_PROTO_HASH_LENGTH);

        cookie = ntb_slice_alloc(&ntb_store_cookie_allocator);
        cookie->store = store;
        cookie->blob = NULL;
        cookie->task = task;
        cookie->idle_source = NULL;
        cookie->func = func;
        cookie->user_data = user_data;

        task->load_blob.cookie = cookie;

        pthread_mutex_unlock(&store->mutex);

        return cookie;
}

void
ntb_store_cancel_task(struct ntb_store_cookie *cookie)
{
        struct ntb_store *store = cookie->store;

        pthread_mutex_lock(&store->mutex);

        if (cookie->task)
                cookie->task->load_blob.cookie = NULL;
        if (cookie->idle_source)
                ntb_main_context_remove_source(cookie->idle_source);
        if (cookie->blob)
                ntb_blob_unref(cookie->blob);

        pthread_mutex_unlock(&store->mutex);

        ntb_slice_free(&ntb_store_cookie_allocator, cookie);
}

void
ntb_store_free(struct ntb_store *store)
{
        struct ntb_store_task *task, *tmp;

        if (store->started) {
                pthread_mutex_lock(&store->mutex);
                store->quit = true;
                pthread_cond_signal(&store->cond);
                pthread_mutex_unlock(&store->mutex);
                pthread_join(store->thread, NULL);
        }

        ntb_list_for_each_safe(task, tmp, &store->queue, link)
                free_task(store, task);

        ntb_buffer_destroy(&store->tmp_buf);
        ntb_buffer_destroy(&store->filename_buf);

        ntb_slice_allocator_destroy(&store->allocator);

        ntb_free(store);

        if (ntb_store_default == store)
                ntb_store_default = NULL;
}
