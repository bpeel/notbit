/*
 * Notbit - A Bitmessage client
 * Copyright (C) 2011, 2014  Neil Roberts
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

#include "ntb-parse-content-type.h"
#include "ntb-buffer.h"

#define HTTP_TYPE_ALPHA 1
#define HTTP_TYPE_CHAR 2
#define HTTP_TYPE_CR 4
#define HTTP_TYPE_CTL 8
#define HTTP_TYPE_DIGIT 16
#define HTTP_TYPE_HEX 32
#define HTTP_TYPE_HT 64
#define HTTP_TYPE_LF 128
#define HTTP_TYPE_LOALPHA 256
#define HTTP_TYPE_LWS 512
#define HTTP_TYPE_OCTET 1024
#define HTTP_TYPE_SEPARATOR 2048
#define HTTP_TYPE_SP 4096
#define HTTP_TYPE_TEXT 8192
#define HTTP_TYPE_TOKEN 16384
#define HTTP_TYPE_UPALPHA 32768

static const uint16_t http_char_table[] = {
        0x040a, 0x040a, 0x040a, 0x040a, 0x040a, 0x040a, 0x040a, 0x040a,
        0x040a, 0x2e4a, 0x268a, 0x040a, 0x040a, 0x260e, 0x040a, 0x040a,
        0x040a, 0x040a, 0x040a, 0x040a, 0x040a, 0x040a, 0x040a, 0x040a,
        0x040a, 0x040a, 0x040a, 0x040a, 0x040a, 0x040a, 0x040a, 0x040a,
        0x3e02, 0x6402, 0x2c02, 0x6402, 0x6402, 0x6402, 0x6402, 0x6402,
        0x2c02, 0x2c02, 0x6402, 0x6402, 0x2c02, 0x6402, 0x6402, 0x2c02,
        0x6432, 0x6432, 0x6432, 0x6432, 0x6432, 0x6432, 0x6432, 0x6432,
        0x6432, 0x6432, 0x2c02, 0x2c02, 0x2c02, 0x2c02, 0x2c02, 0x2c02,
        0x2c02, 0xe523, 0xe523, 0xe523, 0xe523, 0xe523, 0xe523, 0xe503,
        0xe503, 0xe503, 0xe503, 0xe503, 0xe503, 0xe503, 0xe503, 0xe503,
        0xe503, 0xe503, 0xe503, 0xe503, 0xe503, 0xe503, 0xe503, 0xe503,
        0xe503, 0xe503, 0xe503, 0x2c02, 0x2c02, 0x2c02, 0x6402, 0x6402,
        0x6402, 0x6422, 0x6422, 0x6422, 0x6422, 0x6422, 0x6422, 0x6402,
        0x6402, 0x6402, 0x6402, 0x6402, 0x6402, 0x6402, 0x6402, 0x6402,
        0x6402, 0x6402, 0x6402, 0x6402, 0x6402, 0x6402, 0x6402, 0x6402,
        0x6402, 0x6402, 0x6402, 0x2c02, 0x6402, 0x2c02, 0x6402, 0x040a,
        0x2400, 0x2400, 0x2400, 0x2400, 0x2400, 0x2400, 0x2400, 0x2400,
        0x2400, 0x2400, 0x2400, 0x2400, 0x2400, 0x2400, 0x2400, 0x2400,
        0x2400, 0x2400, 0x2400, 0x2400, 0x2400, 0x2400, 0x2400, 0x2400,
        0x2400, 0x2400, 0x2400, 0x2400, 0x2400, 0x2400, 0x2400, 0x2400,
        0x2400, 0x2400, 0x2400, 0x2400, 0x2400, 0x2400, 0x2400, 0x2400,
        0x2400, 0x2400, 0x2400, 0x2400, 0x2400, 0x2400, 0x2400, 0x2400,
        0x2400, 0x2400, 0x2400, 0x2400, 0x2400, 0x2400, 0x2400, 0x2400,
        0x2400, 0x2400, 0x2400, 0x2400, 0x2400, 0x2400, 0x2400, 0x2400,
        0x2400, 0x2400, 0x2400, 0x2400, 0x2400, 0x2400, 0x2400, 0x2400,
        0x2400, 0x2400, 0x2400, 0x2400, 0x2400, 0x2400, 0x2400, 0x2400,
        0x2400, 0x2400, 0x2400, 0x2400, 0x2400, 0x2400, 0x2400, 0x2400,
        0x2400, 0x2400, 0x2400, 0x2400, 0x2400, 0x2400, 0x2400, 0x2400,
        0x2400, 0x2400, 0x2400, 0x2400, 0x2400, 0x2400, 0x2400, 0x2400,
        0x2400, 0x2400, 0x2400, 0x2400, 0x2400, 0x2400, 0x2400, 0x2400,
        0x2400, 0x2400, 0x2400, 0x2400, 0x2400, 0x2400, 0x2400, 0x2400,
        0x2400, 0x2400, 0x2400, 0x2400, 0x2400, 0x2400, 0x2400, 0x2400
};

#define HTTP_IS_TOKEN(ch) (http_char_table[(uint8_t) ch] & HTTP_TYPE_TOKEN)
#define HTTP_IS_LWS(ch) (http_char_table[(uint8_t) ch] & HTTP_TYPE_LWS)
#define HTTP_IS_TEXT(ch) (http_char_table[(uint8_t) ch] & HTTP_TYPE_TEXT)
#define HTTP_IS_CHAR(ch) (http_char_table[(uint8_t) ch] & HTTP_TYPE_CHAR)

bool
ntb_parse_content_type(const char *header_value,
                       ntb_parse_content_type_type_cb type_cb,
                       ntb_parse_content_type_attribute_cb attribute_cb,
                       void *user_data)
{
        struct ntb_buffer buf;
        bool ret = true;
        const char *p = header_value, *end;
        unsigned int value_start;

        ntb_buffer_init(&buf);

        while (HTTP_IS_LWS(*p))
                p++;

        if (!HTTP_IS_TOKEN(*p)) {
                ret = false;
                goto done;
        }

        for (end = p + 1; HTTP_IS_TOKEN(*end); end++);

        ntb_buffer_append(&buf, p, end - p);

        p = end;

        if (*p != '/') {
                ret = false;
                goto done;
        }

        ntb_buffer_append_c(&buf, '/');

        p++;

        if (!HTTP_IS_TOKEN(*p)) {
                ret = false;
                goto done;
        }

        for (end = p + 1; HTTP_IS_TOKEN(*end); end++);

        ntb_buffer_append(&buf, p, end - p);

        p = end;

        ntb_buffer_append_c(&buf, '\0');

        if (!type_cb((const char *) buf.data, user_data)) {
                ret = false;
                goto done;
        }

        while (true) {
                while (HTTP_IS_LWS(*p))
                        p++;
                if (*p == '\0')
                        break;

                if (*p != ';') {
                        ret = false;
                        goto done;
                }

                p++;

                while (HTTP_IS_LWS(*p))
                        p++;

                if (!HTTP_IS_TOKEN(*p)) {
                        ret = false;
                        goto done;
                }

                for (end = p + 1; HTTP_IS_TOKEN(*end); end++);

                buf.length = 0;
                ntb_buffer_append(&buf, p, end - p);
                ntb_buffer_append_c(&buf, '\0');
                value_start = buf.length;

                p = end;

                if (*p != '=') {
                        ret = false;
                        goto done;
                }
                p++;

                if (*p == '"') {
                        p++;
                        while (true)
                                if (*p == '"') {
                                        p++;
                                        break;
                                } else if (*p == '\\') {
                                        if (p[1] == '\0' ||
                                            !HTTP_IS_CHAR(p[1])) {
                                                ret = false;
                                                goto done;
                                        }
                                        ntb_buffer_append_c(&buf, p[1]);
                                        p += 2;
                                } else if (HTTP_IS_TEXT(*p)) {
                                        ntb_buffer_append_c(&buf, *p);
                                        p++;
                                } else {
                                        ret = false;
                                        goto done;
                                }
                } else if (HTTP_IS_TOKEN(*p)) {
                        for (end = p + 1; HTTP_IS_TOKEN(*end); end++) ;

                        ntb_buffer_append(&buf, p, end - p);

                        p = end;
                } else {
                        ret = false;
                        goto done;
                }

                ntb_buffer_append_c(&buf, '\0');

                if (!attribute_cb((const char *) buf.data,
                                  (const char *) buf.data + value_start,
                                  user_data)) {
                        ret = false;
                        goto done;
                }
        }

done:
        ntb_buffer_destroy(&buf);

        return ret;
}
