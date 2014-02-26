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

#include "config.h"

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <inttypes.h>
#include <dirent.h>

#include "ntb-util.h"
#include "ntb-buffer.h"

#define NTB_PROTO_HASH_LENGTH (512 / 8 / 2)

static struct ntb_buffer
filename_buf = NTB_BUFFER_STATIC_INIT;
static int directory_len;

static uint32_t
ntb_proto_get_32(const uint8_t *p)
{
        uint32_t value;

        memcpy(&value, p, sizeof value);

        return NTB_UINT32_FROM_BE(value);
}

static bool
ntb_proto_get_timestamp(const uint8_t **p_ptr,
                        uint32_t *length_ptr,
                        int64_t *result)
{
        /* The timestamp field is transitioning to a 64-bit type.
         * Currently if the first 32-bits are zero it should be
         * treated as a 64-bit value (which will obviously still be
         * less than 32-bits) */

        if (*length_ptr < sizeof (uint32_t))
                return false;

        *result = ntb_proto_get_32(*p_ptr);

        *length_ptr -= sizeof (uint32_t);
        *p_ptr += sizeof (uint32_t);

        if (*result == 0) {
                if (*length_ptr < sizeof (uint32_t))
                        return false;

                *result = ntb_proto_get_32(*p_ptr);

                *length_ptr -= sizeof (uint32_t);
                *p_ptr += sizeof (uint32_t);
        }

        return true;
}

static void
strip_trailing_slashes(struct ntb_buffer *buffer)
{
        /* Strip all but the first slash */
        while (buffer->length > 1 && buffer->data[buffer->length - 1] == '/')
                buffer->length--;
}

static bool
init_store_directory(void)
{
        const char *data_home, *home;

        if ((data_home = getenv("XDG_DATA_HOME"))) {
                if (data_home[0] != '/') {
                        fprintf(stderr,
                                "The XDG_DATA_HOME path is not "
                                "absolute");
                        exit(EXIT_FAILURE);
                }

                ntb_buffer_append_string(&filename_buf,
                                         data_home);
                strip_trailing_slashes(&filename_buf);
                ntb_buffer_append_string(&filename_buf,
                                         "/notbit/");
        } else if ((home = getenv("HOME"))) {
                if (home[0] != '/') {
                        fprintf(stderr,
                                "The HOME path is not "
                                "absolute");
                        exit(EXIT_FAILURE);
                }

                ntb_buffer_append_string(&filename_buf, home);
                strip_trailing_slashes(&filename_buf);
                ntb_buffer_append_string(&filename_buf,
                                         "/.local/share/notbit/");
        } else {
                fprintf(stderr,
                        "Neither XDG_DATA_HOME nor HOME is set");
                exit(EXIT_FAILURE);
        }

        directory_len = filename_buf.length;

        return true;
}

static void
read_all(const char *filename,
         void *data,
         size_t size,
         FILE *stream)
{
        errno = 0;

        if (fread(data, 1, size, stream) != size) {
                if (errno == 0)
                        fprintf(stderr, "%s: file is too short", filename);
                else
                        fprintf(stderr, "%s: %s", filename, strerror(errno));

                exit(EXIT_FAILURE);
        }
}

static bool
is_hex_digit(int ch)
{
        return ((ch >= 'a' && ch <= 'f') ||
                (ch >= 'A' && ch <= 'F') ||
                (ch >= '0' && ch <= '9'));
}

static void
process_file(const char *filename)
{
        uint8_t buf[sizeof (uint32_t) + sizeof (uint64_t) * 2];
        const char *p, *hash;
        const uint8_t *buf_ptr;
        uint32_t length;
        uint32_t type;
        int64_t timestamp;
        FILE *file;
        int i;

        hash = p = filename + directory_len + 8;

        for (i = 0; i < NTB_PROTO_HASH_LENGTH; i++) {
                /* Skip files that don't look like a hash */
                if (!is_hex_digit(p[0]) ||
                    !is_hex_digit(p[1]))
                        return;
                p += 2;
        }

        if (*p != '\0')
                return;

        file = fopen(filename, "rb");

        if (file == NULL) {
                fprintf(stderr, "%s: %s\n", filename, strerror(errno));
                exit(EXIT_FAILURE);
        }

        read_all(filename, buf, sizeof buf, file);

        fclose(file);

        type = ntb_proto_get_32(buf);
        buf_ptr = buf + sizeof (uint32_t) + sizeof (uint64_t);
        length = sizeof (uint64_t);
        ntb_proto_get_timestamp(&buf_ptr, &length, &timestamp);

        printf("%" PRIi64 " %" PRIu32 " %s\n",
               timestamp,
               type,
               hash);
}

int
main(int argc, char **argv)
{
        struct dirent *dirent;
        DIR *dir;

        init_store_directory();

        filename_buf.length = directory_len;
        ntb_buffer_append_string(&filename_buf, "objects");

        dir = opendir((char *) filename_buf.data);
        if (dir == NULL) {
                fprintf(stderr,
                        "%s: %s\n",
                        (char *) filename_buf.data,
                        strerror(errno));
                return EXIT_FAILURE;
        }

        ntb_buffer_append_c(&filename_buf, '/');

        while ((dirent = readdir(dir))) {
                filename_buf.length = directory_len + 8;
                ntb_buffer_append_string(&filename_buf, dirent->d_name);

                process_file((char *) filename_buf.data);
        }

        closedir(dir);

        return EXIT_SUCCESS;
}
