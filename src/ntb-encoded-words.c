/*
 * Notbit - A Bitmessage client
 * Copyright (C) 2014  Neil Roberts
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

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>

#include "ntb-encoded-words.h"
#include "ntb-util.h"
#include "ntb-buffer.h"
#include "ntb-base64.h"
#include "ntb-quoted-printable.h"

struct ntb_encoded_words_data {
        uint8_t *out;
        const uint8_t *in;
        size_t length;
        struct ntb_buffer decode_buf;
};

enum ntb_encoded_words_encoding {
        NTB_ENCODED_WORDS_ENCODING_QUOTED_PRINTABLE,
        NTB_ENCODED_WORDS_ENCODING_BASE64
};

static const uint8_t *
find_string(const uint8_t *haystack,
            size_t haystack_length,
            const char *needle)
{
        size_t needle_length = strlen(needle);

        while (haystack_length >= needle_length) {
                if (!memcmp(haystack, needle, needle_length))
                        return haystack;
                haystack++;
                haystack_length--;
        }

        return NULL;
}

static bool
looking_at(const uint8_t **in,
           size_t *length,
           const char *string)
{
        int string_length = strlen(string);
        int i;

        if (*length < string_length)
                return false;

        for (i = 0; i < string_length; i++)
                if (ntb_ascii_tolower((*in)[i]) != string[i])
                        return false;

        *in += string_length;
        *length -= string_length;

        return true;
}

static bool
process_base64(struct ntb_encoded_words_data *data,
               const uint8_t *in,
               size_t length)
{
        size_t chunk_size;
        struct ntb_base64_data base64_data;
        ssize_t got;

        ntb_base64_decode_start(&base64_data);

        while (length > 0) {
                ntb_buffer_ensure_size(&data->decode_buf,
                                       data->decode_buf.length + 8);

                chunk_size =
                        NTB_BASE64_MAX_INPUT_FOR_SIZE(data->decode_buf.size -
                                                      data->decode_buf.length);
                if (chunk_size > length)
                        chunk_size = length;

                got = ntb_base64_decode(&base64_data,
                                        in,
                                        chunk_size,
                                        data->decode_buf.data +
                                        data->decode_buf.length,
                                        NULL);

                if (got == -1)
                        return false;

                data->decode_buf.length += got;

                in += chunk_size;
                length -= chunk_size;
        }

        ntb_buffer_ensure_size(&data->decode_buf,
                               data->decode_buf.length + 3);

        got = ntb_base64_decode_end(&base64_data,
                                    data->decode_buf.data +
                                    data->decode_buf.length,
                                    NULL);

        if (got == -1)
                return false;

        data->decode_buf.length += got;

        return true;
}

static bool
process_quoted_printable(struct ntb_encoded_words_data *data,
                         const uint8_t *in,
                         size_t length)
{
        size_t chunk_size;
        struct ntb_quoted_printable_data quoted_printable_data;
        ssize_t got;

        ntb_quoted_printable_decode_start(&quoted_printable_data,
                                          true /* underscore_is_space */);

        while (length > 0) {
                ntb_buffer_ensure_size(&data->decode_buf,
                                       data->decode_buf.length + 8);

                chunk_size = MIN(data->decode_buf.size -
                                 data->decode_buf.length,
                                 length);

                got = ntb_quoted_printable_decode(&quoted_printable_data,
                                                  in,
                                                  chunk_size,
                                                  data->decode_buf.data +
                                                  data->decode_buf.length,
                                                  NULL);

                if (got == -1)
                        return false;

                data->decode_buf.length += got;

                in += chunk_size;
                length -= chunk_size;
        }

        return ntb_quoted_printable_decode_end(&quoted_printable_data, NULL);
}

static bool
process_encoded_word(struct ntb_encoded_words_data *data)
{
        enum ntb_encoded_words_encoding encoding;
        const uint8_t *in = data->in;
        size_t length = data->length;
        const uint8_t *ew_end;
        const uint8_t *p;

        if (!looking_at(&in, &length, "us-ascii?") &&
            !looking_at(&in, &length, "utf-8?"))
                return false;

        if (looking_at(&in, &length, "q?"))
                encoding = NTB_ENCODED_WORDS_ENCODING_QUOTED_PRINTABLE;
        else if (looking_at(&in, &length, "b?"))
                encoding = NTB_ENCODED_WORDS_ENCODING_BASE64;
        else
                return false;

        ew_end = find_string(in, length, "?=");

        if (ew_end == NULL)
                return false;

        /* There shouldn't be any space or question mark characters in
         * the encoded data */
        for (p = in; p < ew_end; p++)
                if (*p == ' ' || *p == '?')
                        return false;

        data->decode_buf.length = 0;

        switch (encoding) {
        case NTB_ENCODED_WORDS_ENCODING_QUOTED_PRINTABLE:
                if (!process_quoted_printable(data, in, ew_end - in))
                        return false;
                break;
        case NTB_ENCODED_WORDS_ENCODING_BASE64:
                if (!process_base64(data, in, ew_end - in))
                        return false;
                break;
        }

        memcpy(data->out, data->decode_buf.data, data->decode_buf.length);
        data->out += data->decode_buf.length;

        data->length -= ew_end + 2 - data->in;
        data->in = ew_end + 2;

        return true;
}

size_t
ntb_encoded_words_decode(uint8_t *buffer,
                         size_t length)
{
        struct ntb_encoded_words_data data;
        const uint8_t *ew_start;
        size_t skip_size;
        bool is_space;
        bool had_ew = false;

        data.in = buffer;
        data.out = buffer;
        data.length = length;
        ntb_buffer_init(&data.decode_buf);

        while (true) {
                ew_start = find_string(data.in, data.length, "=?");

                if (ew_start == NULL)
                        break;

                skip_size = ew_start - data.in;

                if (had_ew && skip_size == 1 && ew_start[-1] == ' ') {
                        is_space = true;
                } else {
                        memmove(data.out, data.in, skip_size);
                        data.out += skip_size;
                        is_space = false;
                }

                data.length -= skip_size + 2;
                data.in = ew_start + 2;

                if ((ew_start == buffer || ew_start[-1] == ' ') &&
                    process_encoded_word(&data)) {
                        had_ew = true;
                } else {
                        had_ew = false;
                        if (is_space)
                                *(data.out++) = ' ';
                        memcpy(data.out, "=?", 2);
                        data.out += 2;
                }
        }

        memmove(data.out, data.in, data.length);

        ntb_buffer_destroy(&data.decode_buf);

        return data.out - buffer + data.length;
}

#if 0 /* for testing */

#include <stdio.h>

int
main(int argc, char **argv)
{
        uint8_t *buffer;
        size_t length;
        int i;

        for (i = 1; i < argc; i++) {
                length = strlen(argv[i]);
                buffer = ntb_memdup(argv[i], length);
                length = ntb_encoded_words_decode(buffer, length);
                fwrite(buffer, 1, length, stdout);
                fputc('\n', stdout);
        }

        return EXIT_SUCCESS;
}

#endif /* for testing */
