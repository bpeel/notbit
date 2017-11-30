/*
 * Notbit - A Bitmessage client
 * Copyright (C) 2013, 2017  Neil Roberts
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
#include <sys/time.h>
#include <fcntl.h>

#include "ntb-store.h"
#include "ntb-util.h"
#include "ntb-buffer.h"
#include "ntb-log.h"
#include "ntb-list.h"
#include "ntb-slice.h"
#include "ntb-proto.h"
#include "ntb-main-context.h"
#include "ntb-file-error.h"
#include "ntb-base58.h"
#include "ntb-base64.h"
#include "ntb-address.h"
#include "ntb-load-keys.h"
#include "ntb-load-outgoings.h"
#include "ntb-save-message.h"
#include "ntb-mkdir.h"

struct ntb_error_domain
ntb_store_error;

struct ntb_store {
        struct ntb_buffer filename_buf;
        struct ntb_buffer tmp_buf;
        int directory_len;
        struct ntb_buffer maildir_buf;
        int maildir_len;

        pthread_mutex_t mutex;
        pthread_cond_t cond;
        pthread_t thread;
        bool started;

        struct ntb_list queue;

        /* The slice allocator has to be per-store rather than a
         * global variable so that we can be sure to use it only when
         * the mutex is locked in order to make it thread-safe */
        struct ntb_slice_allocator allocator;

        /* Number of messages we have saved. This is just used to help
         * generate a unique name */
        unsigned int num_stored_messages;

        bool quit;
};

enum ntb_store_task_type {
        NTB_STORE_TASK_TYPE_SAVE_BLOB,
        NTB_STORE_TASK_TYPE_LOAD_BLOB,
        NTB_STORE_TASK_TYPE_SAVE_ADDR_LIST,
        NTB_STORE_TASK_TYPE_SAVE_KEYS,
        NTB_STORE_TASK_TYPE_SAVE_OUTGOINGS,
        NTB_STORE_TASK_TYPE_SAVE_MESSAGE,
        NTB_STORE_TASK_TYPE_SAVE_MESSAGE_CONTENT,
        NTB_STORE_TASK_TYPE_LOAD_MESSAGE_CONTENT,
        NTB_STORE_TASK_TYPE_DELETE_MESSAGE_CONTENT,
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
                        struct ntb_key **keys;
                        int n_keys;
                } save_keys;

                struct {
                        struct ntb_blob *blob;
                } save_outgoings;

                struct {
                        int64_t timestamp;
                        struct ntb_key *from_key;
                        char from_address[NTB_ADDRESS_MAX_LENGTH + 1];
                        struct ntb_key *to_key;
                        struct ntb_blob *blob;
                } save_message;

                struct {
                        uint64_t id;
                        struct ntb_blob *blob;
                } save_message_content;

                struct {
                        uint64_t id;
                        struct ntb_store_cookie *cookie;
                } load_message_content;

                struct {
                        uint64_t id;
                } delete_message_content;

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

typedef void (* for_each_blob_internal_func)(const uint8_t *hash,
                                             int64_t expires_time,
                                             const char *filename,
                                             FILE *file,
                                             void *user_data);

/* The cookies are only allocated and destroyed in the main thread so
 * we don't need to have a per-store allocator */
NTB_SLICE_ALLOCATOR(struct ntb_store_cookie, ntb_store_cookie_allocator);

/* ceil(log₅₈(2 ** ((private_key_size + 4 + 1) × 8))) */
/* The added four is for the checksum, and the 1 for the 0x80 prefix */
#define NTB_STORE_MAX_WIF_LENGTH 51

/* ceil(log₅₈(2 ** (NTB_ECC_PUBLIC_KEY_SIZE × 8))) */
/* The added four is for the checksum, and the 1 for the 0x80 prefix */
#define NTB_STORE_MAX_PUBLIC_KEY_LENGTH 89

/* ceil(log₅₈(2 ** (NTB_PROTO_ACKDATA_SIZE × 8))) */
#define NTB_STORE_MAX_ACKDATA_LENGTH 44

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
append_cwd(struct ntb_buffer *buffer)
{
        size_t try_size = 32;

        while (true) {
                ntb_buffer_ensure_size(buffer, buffer->length + try_size);

                if (getcwd((char *) buffer->data + buffer->length,
                           buffer->size - buffer->length)) {
                        buffer->length += strlen((char *) buffer->data +
                                                 buffer->length);
                        return true;
                } else if (errno != ERANGE) {
                        return false;
                }

                try_size *= 2;
        }
}

static void
append_absolute_path(struct ntb_buffer *buffer,
                     const char *path)
{
        if (path[0] != '/' && append_cwd(buffer))
                ntb_buffer_append_c(buffer, '/');

        ntb_buffer_append_string(buffer, path);
        strip_trailing_slashes(buffer);
}

static bool
init_store_directory(struct ntb_store *store,
                     const char *store_directory,
                     struct ntb_error **error)
{
        const char *data_home, *home;

        if (store_directory) {
                append_absolute_path(&store->filename_buf, store_directory);
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

        if (!ntb_mkdir_hierarchy(&store->filename_buf, error))
                return false;

        store->filename_buf.length = store->directory_len;
        ntb_buffer_append_string(&store->filename_buf, "outgoing");
        if (!ntb_mkdir((const char *) store->filename_buf.data, error))
                return false;

        return true;
}

static bool
init_maildir(struct ntb_store *store,
             const char *maildir,
             struct ntb_error **error)
{
        const char *home;

        if (maildir) {
                append_absolute_path(&store->maildir_buf, maildir);
                ntb_buffer_append_c(&store->maildir_buf, '/');
        } else if ((home = getenv("HOME"))) {
                if (home[0] != '/') {
                        ntb_set_error(error,
                                      &ntb_store_error,
                                      NTB_STORE_ERROR_INVALID_MAILDIR,
                                      "The HOME path is not "
                                      "absolute");
                        return false;
                }

                ntb_buffer_append_string(&store->maildir_buf,
                                         home);
                strip_trailing_slashes(&store->maildir_buf);
                ntb_buffer_append_string(&store->maildir_buf,
                                         "/.maildir/");
        } else {
                ntb_set_error(error,
                              &ntb_store_error,
                              NTB_STORE_ERROR_INVALID_MAILDIR,
                              "HOME is not set");
                return false;
        }

        store->maildir_len = store->maildir_buf.length;

        ntb_buffer_append_string(&store->maildir_buf, "new");

        if (!ntb_mkdir_hierarchy(&store->maildir_buf, error))
                return false;

        ntb_buffer_set_length(&store->maildir_buf,
                              store->maildir_buf.length - 3);
        ntb_buffer_append_string(&store->maildir_buf, "tmp");

        if (!ntb_mkdir((const char *) store->maildir_buf.data, error))
                return false;

        ntb_buffer_set_length(&store->maildir_buf,
                              store->maildir_buf.length - 3);
        ntb_buffer_append_string(&store->maildir_buf, "cur");

        if (!ntb_mkdir((const char *) store->maildir_buf.data, error))
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
load_data_idle_cb(struct ntb_main_context_source *source,
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

        if (fstat(fileno(file), &statbuf) == -1) {
                ntb_log("Error getting info for %s", filename);
                return NULL;
        }

        blob = ntb_blob_new(NULL /* data */,
                            statbuf.st_size);

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
                                          load_data_idle_cb,
                                          task->load_blob.cookie);
}

static void
rename_tmp_file(struct ntb_store *store)
{
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
handle_save_blob(struct ntb_store *store,
                 struct ntb_store_task *task)
{
        FILE *file;

        set_hash_filename(store, task->save_blob.hash);

        ntb_buffer_append_string(&store->filename_buf, ".tmp");

        file = fopen((char *) store->filename_buf.data, "wb");

        if (file == NULL) {
                ntb_log("Error opening %s: %s",
                        (char *) store->filename_buf.data,
                        strerror(errno));
                return;
        }

        if (fwrite(task->save_blob.blob->data, 1,
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

        rename_tmp_file(store);
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

        rename_tmp_file(store);
}

static void
encode_wif(const EC_KEY *key,
           char *wif)
{
        const BIGNUM *private_key;
        uint8_t hash1[SHA256_DIGEST_LENGTH];
        uint8_t hash2[SHA256_DIGEST_LENGTH];
        uint8_t address_bytes[NTB_ECC_PRIVATE_KEY_SIZE + 4 + 1];
        size_t wif_length;
        int n_bytes;

        address_bytes[0] = 0x80;

        private_key = EC_KEY_get0_private_key(key);
        n_bytes = BN_num_bytes(private_key);
        BN_bn2bin(private_key,
                  address_bytes + 1 + NTB_ECC_PRIVATE_KEY_SIZE - n_bytes);
        memset(address_bytes + 1, 0, NTB_ECC_PRIVATE_KEY_SIZE - n_bytes);

        SHA256(address_bytes, NTB_ECC_PRIVATE_KEY_SIZE + 1, hash1);
        SHA256(hash1, SHA256_DIGEST_LENGTH, hash2);

        memcpy(address_bytes + NTB_ECC_PRIVATE_KEY_SIZE + 1, hash2, 4);

        wif_length = ntb_base58_encode(address_bytes,
                                       sizeof address_bytes,
                                       wif);
        assert(wif_length <= NTB_STORE_MAX_WIF_LENGTH);

        wif[wif_length] = '\0';
}

static void
encode_public_key(const EC_KEY *key,
                  char *public_key)
{
        uint8_t buf[NTB_ECC_PUBLIC_KEY_SIZE];
        size_t size;

        size = EC_POINT_point2oct(EC_KEY_get0_group(key),
                                  EC_KEY_get0_public_key(key),
                                  POINT_CONVERSION_UNCOMPRESSED,
                                  buf,
                                  sizeof buf,
                                  NULL);
        assert(size == NTB_ECC_PUBLIC_KEY_SIZE);

        size = ntb_base58_encode(buf, sizeof buf, public_key);
        assert(size <= NTB_STORE_MAX_PUBLIC_KEY_LENGTH);

        public_key[size] = '\0';
}

static void
write_key(struct ntb_key *key,
          FILE *out)
{
        char address[NTB_ADDRESS_MAX_LENGTH + 1];
        char signing_key_wif[NTB_STORE_MAX_WIF_LENGTH + 1];
        char encryption_key_wif[NTB_STORE_MAX_WIF_LENGTH + 1];
        char public_signing_key[NTB_STORE_MAX_PUBLIC_KEY_LENGTH + 1];
        char public_encryption_key[NTB_STORE_MAX_PUBLIC_KEY_LENGTH + 1];

        ntb_address_encode(&key->address, address);

        fprintf(out,
                "[%s]\n"
                "label = %s\n"
                "noncetrialsperbyte = %i\n"
                "payloadlengthextrabytes = %i\n",
                address,
                key->label,
                key->pow_per_byte,
                key->pow_extra_bytes);

        if (ntb_key_has_private(key)) {
                encode_wif(key->signing_key, signing_key_wif);
                encode_wif(key->encryption_key, encryption_key_wif);

                fprintf(out,
                        "privsigningkey = %s\n"
                        "privencryptionkey = %s\n"
                        "lastpubkeysendtime = %" PRIi64 "\n"
                        "enabled = %s\n"
                        "decoy = %s\n",
                        signing_key_wif,
                        encryption_key_wif,
                        key->last_pubkey_send_time,
                        key->enabled ? "true" : "false",
                        key->decoy ? "true" : "false");
        } else {
                encode_public_key(key->signing_key, public_signing_key);
                encode_public_key(key->encryption_key, public_encryption_key);

                fprintf(out,
                        "pubsigningkey = %s\n"
                        "pubencryptionkey = %s\n",
                        public_signing_key,
                        public_encryption_key);
        }

        fputc('\n', out);
}

static FILE *
open_sensitive_file(const char *filename)
{
        FILE *file;
        int fd;

        /* open and fdopen is used instead of fopen so that we can
         * make the permissions on the file be at most 600. We don't
         * want sensitive files be world-readable */
        fd = open(filename,
                  O_WRONLY | O_CREAT,
                  S_IRUSR | S_IWUSR);

        if (fd == -1) {
                ntb_log("Error opening %s: %s",
                        filename,
                        strerror(errno));
                return NULL;
        }

        file = fdopen(fd, "w");
        if (file == NULL) {
                ntb_log("Error opening %s: %s",
                        filename,
                        strerror(errno));
                close(fd);
                return NULL;
        }

        return file;
}

static void
handle_save_keys(struct ntb_store *store,
                 struct ntb_store_task *task)
{
        FILE *out;
        int i;

        ntb_log("Saving keys");

        store->filename_buf.length = store->directory_len;
        ntb_buffer_append_string(&store->filename_buf,
                                 "keys.dat.tmp");

        out = open_sensitive_file((char *) store->filename_buf.data);

        if (out == NULL)
                return;

        for (i = 0; i < task->save_keys.n_keys; i++)
                write_key(task->save_keys.keys[i], out);

        if (fclose(out) == EOF) {
                ntb_log("Error writing to %s: %s",
                        (char *) store->filename_buf.data,
                        strerror(errno));
                return;
        }

        rename_tmp_file(store);
}

static void
write_outgoing(const struct ntb_store_outgoing *outgoing,
               FILE *out)
{
        char from_address[NTB_ADDRESS_MAX_LENGTH + 1];
        char to_address[NTB_ADDRESS_MAX_LENGTH + 1];
        char ackdata[NTB_STORE_MAX_ACKDATA_LENGTH + 1];
        ssize_t ackdata_length;

        ntb_address_encode(&outgoing->from_address, from_address);
        ntb_address_encode(&outgoing->to_address, to_address);
        ackdata_length = ntb_base58_encode(outgoing->ackdata,
                                           NTB_PROTO_ACKDATA_SIZE,
                                           ackdata);

        assert(ackdata_length <= NTB_STORE_MAX_ACKDATA_LENGTH);

        ackdata[ackdata_length] = '\0';

        fprintf(out,
                "[message]\n"
                "fromaddress = %s\n"
                "toaddress = %s\n"
                "ackdata = %s\n"
                "contentid = %" PRIu64 "\n"
                "contentencoding = %i\n"
                "lastgetpubkeysendtime = %" PRIi64 "\n"
                "lastmsgsendtime = %" PRIi64 "\n"
                "\n",
                from_address,
                to_address,
                ackdata,
                outgoing->content_id,
                outgoing->content_encoding,
                outgoing->last_getpubkey_send_time,
                outgoing->last_msg_send_time);
}

static void
handle_save_outgoings(struct ntb_store *store,
                      struct ntb_store_task *task)
{
        struct ntb_blob *blob = task->save_outgoings.blob;
        const struct ntb_store_outgoing *outgoings =
                (const struct ntb_store_outgoing *) blob->data;
        FILE *out;
        size_t i;

        ntb_log("Saving outgoing messages");

        store->filename_buf.length = store->directory_len;
        ntb_buffer_append_string(&store->filename_buf,
                                 "outgoing-messages.dat.tmp");

        out = open_sensitive_file((char *) store->filename_buf.data);

        if (out == NULL)
                return;

        for (i = 0; i < blob->size / sizeof *outgoings; i++)
                write_outgoing(outgoings + i, out);

        if (fclose(out) == EOF) {
                ntb_log("Error writing to %s: %s",
                        (char *) store->filename_buf.data,
                        strerror(errno));
                return;
        }

        rename_tmp_file(store);
}

static void
generate_maildir_name(struct ntb_store *store,
                      struct ntb_buffer *buffer)
{
        struct timeval tv;
        int hostname_length = 2;

        gettimeofday(&tv, NULL /* tz */);

        ntb_buffer_append_printf(buffer,
                                 "%li.M%liQ%u.",
                                 (long int) tv.tv_sec,
                                 (long int) tv.tv_usec,
                                 store->num_stored_messages++);

        while (true) {
                ntb_buffer_ensure_size(buffer,
                                       buffer->length + hostname_length);

                if (gethostname((char *) buffer->data + buffer->length,
                                hostname_length) == -1) {
                        if (errno == ENAMETOOLONG)
                                hostname_length *= 2;
                        else
                                buffer->data[buffer->length--] = '\0';
                } else {
                        break;
                }
        }

        while (buffer->data[buffer->length]) {
                if (buffer->data[buffer->length] == '/')
                        buffer->data[buffer->length] = '\057';
                else if (buffer->data[buffer->length] == ':')
                        buffer->data[buffer->length] = '\072';
                buffer->length++;
        }
}

static void
handle_save_message(struct ntb_store *store,
                    struct ntb_store_task *task)
{
        FILE *out;

        ntb_log("Saving message");

        store->maildir_buf.length = store->maildir_len;
        ntb_buffer_append_string(&store->maildir_buf, "tmp/");

        generate_maildir_name(store, &store->maildir_buf);

        out = fopen((char *) store->maildir_buf.data, "w");

        if (out == NULL) {
                ntb_log("Error opening %s: %s",
                        (char *) store->maildir_buf.data,
                        strerror(errno));
                return;
        }

        ntb_save_message(task->save_message.timestamp,
                         task->save_message.from_key,
                         task->save_message.from_address,
                         task->save_message.to_key,
                         task->save_message.blob,
                         out);

        if (fclose(out) == EOF) {
                ntb_log("Error writing to %s: %s",
                        (char *) store->maildir_buf.data,
                        strerror(errno));
                return;
        }

        store->tmp_buf.length = 0;
        ntb_buffer_append(&store->tmp_buf,
                          store->maildir_buf.data,
                          store->maildir_len);
        ntb_buffer_append_string(&store->tmp_buf, "new");
        ntb_buffer_append(&store->tmp_buf,
                          store->maildir_buf.data +
                          store->maildir_len + 3,
                          store->maildir_buf.length -
                          store->maildir_len - 3 + 1);

        if (rename((char *) store->maildir_buf.data,
                   (char *) store->tmp_buf.data) == -1) {
                ntb_log("Error renaming %s to %s: %s",
                        (char *) store->filename_buf.data,
                        (char *) store->tmp_buf.data,
                        strerror(errno));
        }
}

static void
set_message_content_filename(struct ntb_store *store,
                             uint64_t content_id)
{
        store->filename_buf.length = store->directory_len;
        ntb_buffer_append_printf(&store->filename_buf,
                                 "outgoing/%016" PRIx64,
                                 content_id);
}

static void
handle_save_message_content(struct ntb_store *store,
                            struct ntb_store_task *task)
{
        struct ntb_blob *blob = task->save_message_content.blob;
        FILE *file;

        set_message_content_filename(store, task->save_message_content.id);
        ntb_buffer_append_string(&store->filename_buf, ".tmp");

        file = open_sensitive_file((char *) store->filename_buf.data);

        if (file == NULL)
                return;

        if (fwrite(blob->data, 1, blob->size, file) != blob->size) {
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

        rename_tmp_file(store);
}

static struct ntb_blob *
load_message_content_from_file(const char *filename,
                               FILE *file)
{
        struct stat statbuf;
        struct ntb_blob *blob;

        if (fstat(fileno(file), &statbuf) == -1) {
                ntb_log("Error getting info for %s", filename);
                return NULL;
        }

        blob = ntb_blob_new(NULL /* data */,
                            statbuf.st_size);

        if (!read_all(filename, blob->data, blob->size, file)) {
                ntb_blob_unref(blob);
                return NULL;
        }

        return blob;
}

static void
handle_load_message_content(struct ntb_store *store,
                            struct ntb_store_task *task)
{
        struct ntb_blob *blob = NULL;
        const char *filename;
        FILE *file;

        /* As a special case this the lock is still held when this
         * function is called */

        /* If the task was cancelled before we got here then the
         * cookie will have been reset to NULL. In that case we don't
         * need to do anything */
        if (task->load_message_content.cookie == NULL)
                return;

        pthread_mutex_unlock(&store->mutex);

        set_message_content_filename(store, task->load_message_content.id);
        filename = (const char *) store->filename_buf.data;

        file = fopen(filename, "rb");

        if (file == NULL) {
                ntb_log("Error opening %s: %s", filename, strerror(errno));
        } else {
                blob = load_message_content_from_file(filename, file);
                fclose(file);
        }

        pthread_mutex_lock(&store->mutex);

        /* The task could have also been cancelled while we were
         * loading with the mutex unlocked */
        if (task->load_message_content.cookie == NULL) {
                if (blob)
                        ntb_blob_unref(blob);
                return;
        }

        task->load_message_content.cookie->blob = blob;
        task->load_message_content.cookie->idle_source =
                ntb_main_context_add_idle(NULL,
                                          load_data_idle_cb,
                                          task->load_message_content.cookie);
}

static void
handle_delete_message_content(struct ntb_store *store,
                              struct ntb_store_task *task)
{
        set_message_content_filename(store, task->delete_message_content.id);

        if (unlink((char *) store->filename_buf.data) == -1) {
                ntb_log("Error deleting “%s”: %s",
                        (char *) store->filename_buf.data,
                        strerror(errno));
        }
}

static void
free_task(struct ntb_store *store,
          struct ntb_store_task *task)
{
        int i;

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
        case NTB_STORE_TASK_TYPE_SAVE_KEYS:
                for (i = 0; i < task->save_keys.n_keys; i++)
                        ntb_key_unref(task->save_keys.keys[i]);
                ntb_free(task->save_keys.keys);
                break;
        case NTB_STORE_TASK_TYPE_SAVE_OUTGOINGS:
                ntb_blob_unref(task->save_outgoings.blob);
                break;
        case NTB_STORE_TASK_TYPE_SAVE_MESSAGE:
                ntb_blob_unref(task->save_message.blob);
                if (task->save_message.from_key)
                        ntb_key_unref(task->save_message.from_key);
                ntb_key_unref(task->save_message.to_key);
                break;
        case NTB_STORE_TASK_TYPE_SAVE_MESSAGE_CONTENT:
                ntb_blob_unref(task->save_message_content.blob);
                break;
        case NTB_STORE_TASK_TYPE_LOAD_MESSAGE_CONTENT:
                break;
        case NTB_STORE_TASK_TYPE_DELETE_MESSAGE_CONTENT:
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

                task = ntb_container_of(store->queue.next,
                                        struct ntb_store_task,
                                        link);
                ntb_list_remove(&task->link);

                if (task->type == NTB_STORE_TASK_TYPE_LOAD_BLOB) {
                        /* This special case needs to keep the lock
                         * held for part of the task */
                        handle_load_blob(store, task);
                } else if (task->type ==
                           NTB_STORE_TASK_TYPE_LOAD_MESSAGE_CONTENT) {
                        /* This special case needs to keep the lock
                         * held for part of the task */
                        handle_load_message_content(store, task);
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
                        case NTB_STORE_TASK_TYPE_SAVE_KEYS:
                                handle_save_keys(store, task);
                                break;
                        case NTB_STORE_TASK_TYPE_SAVE_OUTGOINGS:
                                handle_save_outgoings(store, task);
                                break;
                        case NTB_STORE_TASK_TYPE_SAVE_MESSAGE:
                                handle_save_message(store, task);
                                break;
                        case NTB_STORE_TASK_TYPE_SAVE_MESSAGE_CONTENT:
                                handle_save_message_content(store, task);
                                break;
                        case NTB_STORE_TASK_TYPE_DELETE_MESSAGE_CONTENT:
                                handle_delete_message_content(store, task);
                                break;
                        case NTB_STORE_TASK_TYPE_LOAD_BLOB:
                        case NTB_STORE_TASK_TYPE_LOAD_MESSAGE_CONTENT:
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
              const char *maildir,
              struct ntb_error **error)
{
        struct ntb_store *store = ntb_alloc(sizeof *store);

        ntb_list_init(&store->queue);
        store->quit = false;
        store->started = false;
        store->num_stored_messages = 0;

        ntb_buffer_init(&store->filename_buf);
        ntb_buffer_init(&store->maildir_buf);

        if (!init_store_directory(store, store_directory, error))
                goto error;

        if (!init_maildir(store, maildir, error))
                goto error;

        pthread_mutex_init(&store->mutex, NULL /* attrs */);
        pthread_cond_init(&store->cond, NULL /* attrs */);

        ntb_slice_allocator_init(&store->allocator,
                                 sizeof (struct ntb_store_task),
                                 NTB_ALIGNOF(struct ntb_store_task));
        ntb_buffer_init(&store->tmp_buf);

        return store;

error:
        ntb_buffer_destroy(&store->maildir_buf);
        ntb_buffer_destroy(&store->filename_buf);
        ntb_free(store);
        return NULL;
}

const char *
ntb_store_get_directory(struct ntb_store *store)
{
        ntb_buffer_set_length(&store->filename_buf, store->directory_len);
        ntb_buffer_append_c(&store->filename_buf, '\0');

        return (const char *) store->filename_buf.data;
}

void
ntb_store_start(struct ntb_store *store)
{
        if (store->started)
                return;

        store->thread = ntb_create_thread(store_thread_func, store);
        store->started = true;
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
ntb_store_save_message(struct ntb_store *store,
                       int64_t timestamp,
                       struct ntb_key *from_key,
                       const char *from_address,
                       struct ntb_key *to_key,
                       struct ntb_blob *blob)
{
        struct ntb_store_task *task;

        if (store == NULL)
                store = ntb_store_get_default_or_abort();

        pthread_mutex_lock(&store->mutex);

        task = new_task(store, NTB_STORE_TASK_TYPE_SAVE_MESSAGE);

        task->save_message.timestamp = timestamp;
        if (from_key)
                task->save_message.from_key = ntb_key_ref(from_key);
        else
                task->save_message.from_key = NULL;
        strcpy(task->save_message.from_address, from_address);
        task->save_message.to_key = ntb_key_ref(to_key);
        task->save_message.blob = ntb_blob_ref(blob);

        pthread_mutex_unlock(&store->mutex);
}

void
ntb_store_save_message_content(struct ntb_store *store,
                               uint64_t content_id,
                               struct ntb_blob *blob)
{
        struct ntb_store_task *task;

        if (store == NULL)
                store = ntb_store_get_default_or_abort();

        pthread_mutex_lock(&store->mutex);

        task = new_task(store, NTB_STORE_TASK_TYPE_SAVE_MESSAGE_CONTENT);

        task->save_message_content.id = content_id;
        task->save_message_content.blob = ntb_blob_ref(blob);

        pthread_mutex_unlock(&store->mutex);
}

struct ntb_store_cookie *
ntb_store_load_message_content(struct ntb_store *store,
                               uint64_t content_id,
                               ntb_store_load_callback func,
                               void *user_data)
{
        struct ntb_store_task *task;
        struct ntb_store_cookie *cookie;

        if (store == NULL)
                store = ntb_store_get_default_or_abort();

        pthread_mutex_lock(&store->mutex);

        task = new_task(store, NTB_STORE_TASK_TYPE_LOAD_MESSAGE_CONTENT);
        task->load_message_content.id = content_id;

        cookie = ntb_slice_alloc(&ntb_store_cookie_allocator);
        cookie->store = store;
        cookie->blob = NULL;
        cookie->task = task;
        cookie->idle_source = NULL;
        cookie->func = func;
        cookie->user_data = user_data;

        task->load_message_content.cookie = cookie;

        pthread_mutex_unlock(&store->mutex);

        return cookie;
}

void
ntb_store_delete_message_content(struct ntb_store *store,
                                 uint64_t content_id)
{
        struct ntb_store_task *task;

        if (store == NULL)
                store = ntb_store_get_default_or_abort();

        pthread_mutex_lock(&store->mutex);

        task = new_task(store, NTB_STORE_TASK_TYPE_DELETE_MESSAGE_CONTENT);

        task->delete_message_content.id = content_id;

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

void
ntb_store_save_keys(struct ntb_store *store,
                    struct ntb_key * const *keys,
                    int n_keys)
{
        struct ntb_store_task *task;
        int i;

        if (store == NULL)
                store = ntb_store_get_default_or_abort();

        pthread_mutex_lock(&store->mutex);

        task = new_task(store, NTB_STORE_TASK_TYPE_SAVE_KEYS);

        task->save_keys.keys = ntb_alloc(sizeof (struct ntb_key *) * n_keys);

        for (i = 0; i < n_keys; i++)
                task->save_keys.keys[i] = ntb_key_ref(keys[i]);

        task->save_keys.n_keys = n_keys;

        pthread_mutex_unlock(&store->mutex);
}

void
ntb_store_save_outgoings(struct ntb_store *store,
                         struct ntb_blob *blob)
{
        struct ntb_store_task *task;

        if (store == NULL)
                store = ntb_store_get_default_or_abort();

        pthread_mutex_lock(&store->mutex);

        task = new_task(store, NTB_STORE_TASK_TYPE_SAVE_OUTGOINGS);

        task->save_outgoings.blob = ntb_blob_ref(blob);

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
             for_each_blob_internal_func func,
             void *user_data)
{
        uint8_t hash[NTB_PROTO_HASH_LENGTH];
        uint8_t buf[sizeof (uint64_t) * 2];
        int64_t expires_time;
        FILE *file;
        const char *p;
        int64_t now;
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

        /* All of the files should start with the 64-bit nonce and
         * then 64-bit expiry time. We only need the expiry time
         * so we don't need to read the rest */
        if (!read_all(filename, buf, sizeof buf, file)) {
                fclose(file);
                return;
        }

        now = ntb_main_context_get_wall_clock(NULL);

        expires_time = ntb_proto_get_64(buf + sizeof (uint64_t));

        if (now >= expires_time + NTB_PROTO_EXTRA_AGE) {
                if (unlink(filename) == -1)
                        ntb_log("Error deleting %s: %s",
                                filename,
                                strerror(errno));
        } else {
                func(hash, expires_time, filename, file, user_data);
        }

        fclose(file);
}

static void
for_each_blob_internal(struct ntb_store *store,
                       for_each_blob_internal_func func,
                       void *user_data)
{
        DIR *dir;
        struct dirent *dirent;

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
}

struct for_each_blob_data {
        ntb_store_for_each_blob_func func;
        void *user_data;
};

static void
for_each_blob_cb(const uint8_t *hash,
                 int64_t expires_time,
                 const char *filename,
                 FILE *file,
                 void *user_data)
{
        struct for_each_blob_data *data = user_data;

        data->func(hash, expires_time, data->user_data);
}

void
ntb_store_for_each_blob(struct ntb_store *store,
                        ntb_store_for_each_blob_func func,
                        void *user_data)
{
        struct for_each_blob_data data;

        if (store == NULL)
                store = ntb_store_get_default_or_abort();

        /* This function runs synchronously but it should only be
         * called once at startup before connecting to any peers so it
         * shouldn't really matter */

        ntb_log("Loading saved object store");

        data.func = func;
        data.user_data = user_data;

        for_each_blob_internal(store, for_each_blob_cb, &data);

        ntb_log("Finished loading object store");
}

struct for_each_pubkey_blob_data {
        ntb_store_for_each_pubkey_blob_func func;
        void *user_data;
};

static void
for_each_pubkey_blob_cb(const uint8_t *hash,
                        int64_t expires_time,
                        const char *filename,
                        FILE *file,
                        void *user_data)
{
        struct for_each_pubkey_blob_data *data = user_data;
        struct stat statbuf;
        struct ntb_blob *blob;
        uint8_t buf[sizeof (uint64_t) * 2 + sizeof (uint32_t)];
        uint32_t type;

        /* Reset the file to the beginning */
        if (fseek(file, 0, SEEK_SET))
                return;

        if (!read_all(filename, buf, sizeof buf, file))
                return;

        type = ntb_proto_get_32(buf + sizeof (uint64_t) * 2);

        if (type != NTB_PROTO_INV_TYPE_PUBKEY)
                return;

        if (fstat(fileno(file), &statbuf) == -1)
                return;

        if (statbuf.st_size < sizeof buf)
                return;

        blob = ntb_blob_new(NULL, /* data */
                            statbuf.st_size);

        memcpy(blob->data, buf, sizeof buf);

        if (read_all(filename,
                     blob->data + sizeof buf,
                     statbuf.st_size - sizeof buf,
                     file))
                data->func(hash, expires_time, blob, data->user_data);

        ntb_blob_unref(blob);
}

void
ntb_store_for_each_pubkey_blob(struct ntb_store *store,
                               ntb_store_for_each_pubkey_blob_func func,
                               void *user_data)
{
        struct for_each_pubkey_blob_data data;

        if (store == NULL)
                store = ntb_store_get_default_or_abort();

        /* This function runs synchronously but it should only be
         * called once at startup before connecting to any peers so it
         * shouldn't really matter */

        ntb_log("Loading pubkey objects");

        data.func = func;
        data.user_data = user_data;

        for_each_blob_internal(store, for_each_pubkey_blob_cb, &data);

        ntb_log("Finished loading pubkey objects");
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

        if (!ntb_netaddress_from_string(&addr.address,
                                        line,
                                        NTB_PROTO_DEFAULT_PORT))
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

void
ntb_store_for_each_key(struct ntb_store *store,
                       ntb_store_for_each_key_func func,
                       void *user_data)
{
        FILE *file;

        if (store == NULL)
                store = ntb_store_get_default_or_abort();

        /* This function runs synchronously but it should only be
         * called once at startup before connecting to any peers so it
         * shouldn't really matter */

        store->filename_buf.length = store->directory_len;
        ntb_buffer_append_string(&store->filename_buf, "keys.dat");

        file = fopen((char *) store->filename_buf.data, "r");

        if (file == NULL) {
                if (errno != ENOENT)
                        ntb_log("Error opening %s: %s",
                                (char *) store->filename_buf.data,
                                strerror(errno));
                return;
        }

        ntb_load_keys(file, (ntb_store_for_each_key_func) func, user_data);

        fclose(file);
}

struct for_each_outgoing_data {
        ntb_store_for_each_outgoing_func func;
        void *user_data;
        struct ntb_buffer used_content_ids;
};

static void
for_each_outgoing_cb(const struct ntb_store_outgoing *outgoing,
                     void *user_data)
{
        struct for_each_outgoing_data *data = user_data;

        data->func(outgoing, data->user_data);

        ntb_buffer_append(&data->used_content_ids,
                          &outgoing->content_id,
                          sizeof outgoing->content_id);
}

static void
maybe_delete_outgoing(struct ntb_store *store,
                      const char *filename,
                      const uint64_t *used_content_ids,
                      size_t n_used_content_ids)
{
        const char *bn = filename + store->directory_len + 9;
        long long int content_id_ll;
        uint64_t content_id;
        char *tail;
        size_t i;

        errno = 0;
        content_id_ll = strtoll(bn, &tail, 16);

        /* Don't delete the file if the name doesn't look like a
         * hexadecimal number */
        if (errno ||
            tail == bn ||
            content_id_ll < 0 ||
            content_id_ll > UINT64_MAX)
                return;

        content_id = content_id_ll;

        if (*tail) {
                /* Don't delete the file unless it is a temporary file
                 * that we probably created */
                if (strcmp(tail, ".tmp"))
                        return;
        } else {
                /* Don't delete the file if it is in use */
                for (i = 0; i < n_used_content_ids; i++)
                        if (used_content_ids[i] == content_id)
                                return;
        }

        if (unlink(filename) == -1)
                ntb_log("Error deleting %s: %s",
                        filename,
                        strerror(errno));
}

static void
delete_unused_outgoings(struct ntb_store *store,
                        const uint64_t *used_content_ids,
                        size_t n_used_content_ids)
{
        DIR *dir;
        struct dirent *dirent;

        store->filename_buf.length = store->directory_len;
        ntb_buffer_append_string(&store->filename_buf, "outgoing");

        dir = opendir((char *) store->filename_buf.data);
        if (dir == NULL) {
                ntb_log("Error listing %s: %s",
                        (char *) store->filename_buf.data,
                        strerror(errno));
                return;
        }

        ntb_buffer_append_c(&store->filename_buf, '/');

        while ((dirent = readdir(dir))) {
                store->filename_buf.length = store->directory_len + 9;
                ntb_buffer_append_string(&store->filename_buf, dirent->d_name);

                maybe_delete_outgoing(store,
                                      (char *) store->filename_buf.data,
                                      used_content_ids,
                                      n_used_content_ids);
        }

        closedir(dir);
}

void
ntb_store_for_each_outgoing(struct ntb_store *store,
                            ntb_store_for_each_outgoing_func func,
                            void *user_data)
{
        struct for_each_outgoing_data data;
        FILE *file;

        if (store == NULL)
                store = ntb_store_get_default_or_abort();

        /* This function runs synchronously but it should only be
         * called once at startup before connecting to any peers so it
         * shouldn't really matter */

        store->filename_buf.length = store->directory_len;
        ntb_buffer_append_string(&store->filename_buf, "outgoing-messages.dat");

        file = fopen((char *) store->filename_buf.data, "r");

        if (file == NULL) {
                if (errno != ENOENT)
                        ntb_log("Error opening %s: %s",
                                (char *) store->filename_buf.data,
                                strerror(errno));
                return;
        }

        data.func = func;
        data.user_data = user_data;
        ntb_buffer_init(&data.used_content_ids);

        ntb_load_outgoings(file, for_each_outgoing_cb, &data);

        delete_unused_outgoings(store,
                                (uint64_t *) data.used_content_ids.data,
                                data.used_content_ids.size / sizeof (uint64_t));

        ntb_buffer_destroy(&data.used_content_ids);

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

        if (cookie->task) {
                switch (cookie->task->type) {
                case NTB_STORE_TASK_TYPE_LOAD_BLOB:
                        cookie->task->load_blob.cookie = NULL;
                        break;
                case NTB_STORE_TASK_TYPE_LOAD_MESSAGE_CONTENT:
                        cookie->task->load_message_content.cookie = NULL;
                        break;
                case NTB_STORE_TASK_TYPE_SAVE_BLOB:
                case NTB_STORE_TASK_TYPE_SAVE_ADDR_LIST:
                case NTB_STORE_TASK_TYPE_SAVE_KEYS:
                case NTB_STORE_TASK_TYPE_SAVE_OUTGOINGS:
                case NTB_STORE_TASK_TYPE_SAVE_MESSAGE:
                case NTB_STORE_TASK_TYPE_SAVE_MESSAGE_CONTENT:
                case NTB_STORE_TASK_TYPE_DELETE_MESSAGE_CONTENT:
                case NTB_STORE_TASK_TYPE_DELETE_OBJECT:
                        assert(false);
                        break;
                }
        }
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

        ntb_buffer_destroy(&store->maildir_buf);
        ntb_buffer_destroy(&store->tmp_buf);
        ntb_buffer_destroy(&store->filename_buf);

        ntb_slice_allocator_destroy(&store->allocator);

        ntb_free(store);

        if (ntb_store_default == store)
                ntb_store_default = NULL;
}
