/*
 * Notbit - A Bitmessage client
 * Copyright (C) 2011, 2014  Neil Roberts
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
