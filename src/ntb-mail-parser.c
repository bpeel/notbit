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

#include <assert.h>

#include "ntb-mail-parser.h"
#include "ntb-buffer.h"
#include "ntb-parse-content-type.h"
#include "ntb-parse-addresses.h"
#include "ntb-base64.h"
#include "ntb-quoted-printable.h"
#include "ntb-encoded-words.h"

struct ntb_error_domain
ntb_mail_parser_error;

enum ntb_mail_parser_state {
        NTB_MAIL_PARSER_HEADER_NAME,
        NTB_MAIL_PARSER_HEADER_VALUE_START,
        NTB_MAIL_PARSER_HEADER_VALUE,
        NTB_MAIL_PARSER_CHECK_EOL,
        NTB_MAIL_PARSER_CHECK_CONTINUATION,
        NTB_MAIL_PARSER_CONTENT
};

enum ntb_mail_parser_header {
        NTB_MAIL_PARSER_SKIP,
        NTB_MAIL_PARSER_TO,
        NTB_MAIL_PARSER_CC,
        NTB_MAIL_PARSER_BCC,
        NTB_MAIL_PARSER_FROM,
        NTB_MAIL_PARSER_SUBJECT,
        NTB_MAIL_PARSER_CONTENT_TYPE,
        NTB_MAIL_PARSER_TRANSFER_ENCODING
};

static struct {
        const char *name;
        enum ntb_mail_parser_header value;
} ntb_mail_parser_headers[] = {
        { "skip", NTB_MAIL_PARSER_SKIP },
        { "to", NTB_MAIL_PARSER_TO },
        { "cc", NTB_MAIL_PARSER_CC },
        { "bcc", NTB_MAIL_PARSER_BCC },
        { "from", NTB_MAIL_PARSER_FROM },
        { "subject", NTB_MAIL_PARSER_SUBJECT },
        { "content-type", NTB_MAIL_PARSER_CONTENT_TYPE },
        { "content-transfer-encoding", NTB_MAIL_PARSER_TRANSFER_ENCODING }
};

enum ntb_mail_parser_encoding {
        NTB_MAIL_PARSER_ENCODING_RAW,
        NTB_MAIL_PARSER_ENCODING_BASE64,
        NTB_MAIL_PARSER_ENCODING_QUOTED_PRINTABLE
};

struct ntb_mail_parser {
        enum ntb_mail_parser_state state;
        enum ntb_mail_parser_header current_header;

        struct ntb_buffer buffer;

        bool had_from;
        bool had_to;
        bool had_cc;
        bool had_bcc;
        bool had_subject;
        bool had_content_type;
        bool had_transfer_encoding;

        ntb_mail_parser_address_cb address_cb;
        ntb_mail_parser_data_cb data_cb;
        void *cb_user_data;

        enum ntb_mail_parser_encoding encoding;

        union {
                struct ntb_base64_data base64_data;
                struct ntb_quoted_printable_data qp_data;
        };
};

struct ntb_mail_parser *
ntb_mail_parser_new(ntb_mail_parser_address_cb address_cb,
                    ntb_mail_parser_data_cb data_cb,
                    void *user_data)
{
        struct ntb_mail_parser *parser = ntb_alloc(sizeof *parser);

        parser->state = NTB_MAIL_PARSER_HEADER_NAME;
        ntb_buffer_init(&parser->buffer);

        parser->had_from = false;
        parser->had_to = false;
        parser->had_cc = false;
        parser->had_bcc = false;
        parser->had_content_type = false;
        parser->had_transfer_encoding = false;
        parser->had_subject = false;

        parser->encoding = NTB_MAIL_PARSER_ENCODING_RAW;

        parser->data_cb = data_cb;
        parser->address_cb = address_cb;
        parser->cb_user_data = user_data;

        return parser;
}

static bool
ascii_islwsp(char ch)
{
        return ch == ' ' || ch == '\t';
}

static bool
ascii_casecmp(const char *a,
              const char *b)
{
        int cmp;

        while (*a && *b) {
                cmp = ntb_ascii_tolower(*a) - ntb_ascii_tolower(*b);

                if (cmp)
                        return cmp;

                a++;
                b++;
        }

        if (*a)
                return 1;
        else if (*b)
                return -1;
        else
                return 0;
}

static bool
is_header(const struct ntb_buffer *buffer,
          const char *name)
{
        char ch;
        size_t i;

        for (i = 0; i < buffer->length; i++) {
                ch = ntb_ascii_tolower(buffer->data[i]);
                if (ch != *name)
                        return false;
                name++;
        }

        return true;
}

static void
set_header(struct ntb_mail_parser *parser)
{
        int i;

        for (i = 0; i < NTB_N_ELEMENTS(ntb_mail_parser_headers); i++) {
                if (is_header(&parser->buffer,
                              ntb_mail_parser_headers[i].name)) {
                        parser->current_header =
                                ntb_mail_parser_headers[i].value;
                        return;
                }
        }

        parser->current_header = NTB_MAIL_PARSER_SKIP;
}

static bool
handle_subject(struct ntb_mail_parser *parser,
               struct ntb_error **error)
{
        if (parser->had_subject) {
                ntb_set_error(error,
                              &ntb_mail_parser_error,
                              NTB_MAIL_PARSER_ERROR_INVALID_HEADER,
                              "Subject header specified twice");
                return false;
        }

        parser->had_subject = true;

        parser->buffer.length = ntb_encoded_words_decode(parser->buffer.data,
                                                         parser->buffer.length);

        return parser->data_cb(NTB_MAIL_PARSER_EVENT_SUBJECT,
                               parser->buffer.data,
                               parser->buffer.length,
                               parser->cb_user_data,
                               error);
}

static bool
destination_address_cb(const struct ntb_address *address,
                       void *user_data,
                       struct ntb_error **error)
{
        struct ntb_mail_parser *parser = user_data;

        return parser->address_cb(NTB_MAIL_PARSER_EVENT_DESTINATION,
                                  address,
                                  parser->cb_user_data,
                                  error);
}

static bool
handle_to(struct ntb_mail_parser *parser,
          struct ntb_error **error)
{
        if (parser->had_to) {
                ntb_set_error(error,
                              &ntb_mail_parser_error,
                              NTB_MAIL_PARSER_ERROR_INVALID_HEADER,
                              "Multiple To headers encountered");
                return false;
        }

        parser->had_to = true;

        return ntb_parse_addresses(&parser->buffer,
                                   destination_address_cb,
                                   parser,
                                   error);
}

static bool
handle_cc(struct ntb_mail_parser *parser,
          struct ntb_error **error)
{
        if (parser->had_cc) {
                ntb_set_error(error,
                              &ntb_mail_parser_error,
                              NTB_MAIL_PARSER_ERROR_INVALID_HEADER,
                              "Multiple Cc headers encountered");
                return false;
        }

        parser->had_cc = true;

        return ntb_parse_addresses(&parser->buffer,
                                   destination_address_cb,
                                   parser,
                                   error);
}

static bool
handle_bcc(struct ntb_mail_parser *parser,
           struct ntb_error **error)
{
        if (parser->had_bcc) {
                ntb_set_error(error,
                              &ntb_mail_parser_error,
                              NTB_MAIL_PARSER_ERROR_INVALID_HEADER,
                              "Multiple Bcc headers encountered");
                return false;
        }

        parser->had_bcc = true;

        return ntb_parse_addresses(&parser->buffer,
                                   destination_address_cb,
                                   parser,
                                   error);
}

static bool
from_address_cb(const struct ntb_address *address,
                void *user_data,
                struct ntb_error **error)
{
        struct ntb_mail_parser *parser = user_data;

        if (parser->had_from) {
                ntb_set_error(error,
                              &ntb_mail_parser_error,
                              NTB_MAIL_PARSER_ERROR_INVALID_HEADER,
                              "Multiple from addresses encountered");
                return false;
        }

        parser->had_from = true;

        return parser->address_cb(NTB_MAIL_PARSER_EVENT_SOURCE,
                                  address,
                                  parser->cb_user_data,
                                  error);
}

static bool
handle_from(struct ntb_mail_parser *parser,
            struct ntb_error **error)
{
        return ntb_parse_addresses(&parser->buffer,
                                   from_address_cb,
                                   parser,
                                   error);
}

struct parse_content_type_data {
        struct ntb_mail_parser *parser;
        struct ntb_error *error;
};

static bool
content_type_type_cb(const char *type,
                     void *user_data)
{
        struct parse_content_type_data *data = user_data;

        if (ascii_casecmp(type, "text/plain")) {
                ntb_set_error(&data->error,
                              &ntb_mail_parser_error,
                              NTB_MAIL_PARSER_ERROR_INVALID_CONTENT_TYPE,
                              "Unsupported content type “%s”",
                              type);
                return false;
        }

        return true;
}

static bool
content_type_attribute_cb(const char *attribute,
                          const char *value,
                          void *user_data)
{
        struct parse_content_type_data *data = user_data;

        if (!ascii_casecmp(attribute, "charset") &&
            ascii_casecmp(value, "utf-8") &&
            ascii_casecmp(value, "us-ascii")) {
                ntb_set_error(&data->error,
                              &ntb_mail_parser_error,
                              NTB_MAIL_PARSER_ERROR_INVALID_CONTENT_TYPE,
                              "Unsupported charset “%s”",
                              value);
                return false;
        }

        return true;
}

static bool
handle_content_type(struct ntb_mail_parser *parser,
                    struct ntb_error **error)
{
        struct parse_content_type_data data;
        const char *header_value;

        if (parser->had_content_type) {
                ntb_set_error(error,
                              &ntb_mail_parser_error,
                              NTB_MAIL_PARSER_ERROR_INVALID_HEADER,
                              "Content-Type header specified twice");
                return false;
        }

        parser->had_content_type = true;

        data.parser = parser;
        data.error = NULL;

        ntb_buffer_append_c(&parser->buffer, '\0');
        header_value = (const char *) parser->buffer.data;

        if (!ntb_parse_content_type(header_value,
                                    content_type_type_cb,
                                    content_type_attribute_cb,
                                    &data)) {
                if (data.error) {
                        ntb_error_propagate(error, data.error);
                } else {
                        ntb_set_error(error,
                                      &ntb_mail_parser_error,
                                      NTB_MAIL_PARSER_ERROR_INVALID_HEADER,
                                      "Invalid Content-Type header "
                                      "encountered");
                }

                return false;
        }

        return true;
}

static bool
handle_transfer_encoding(struct ntb_mail_parser *parser,
                         struct ntb_error **error)
{
        if (parser->had_transfer_encoding) {
                ntb_set_error(error,
                              &ntb_mail_parser_error,
                              NTB_MAIL_PARSER_ERROR_INVALID_HEADER,
                              "Transfer-Encoding header specified twice");
                return false;
        }

        parser->had_transfer_encoding = true;

        if (is_header(&parser->buffer, "base64")) {
                parser->encoding = NTB_MAIL_PARSER_ENCODING_BASE64;
        } else if (is_header(&parser->buffer, "quoted-printable")) {
                parser->encoding = NTB_MAIL_PARSER_ENCODING_QUOTED_PRINTABLE;
        } else if (is_header(&parser->buffer, "7bit") ||
                   is_header(&parser->buffer, "8bit")) {
                parser->encoding = NTB_MAIL_PARSER_ENCODING_RAW;
        } else {
                ntb_set_error(error,
                              &ntb_mail_parser_error,
                              NTB_MAIL_PARSER_ERROR_INVALID_TRANSFER_ENCODING,
                              "Unsupported transfer encoding “%.*s”",
                              (int) parser->buffer.length,
                              (const char *) parser->buffer.data);

                return false;
        }

        return true;
}

static bool
handle_header_end(struct ntb_mail_parser *parser,
                  struct ntb_error **error)
{
        if (parser->buffer.length > 0 &&
            parser->buffer.data[parser->buffer.length - 1] == ' ')
                parser->buffer.length--;

        switch (parser->current_header) {
        case NTB_MAIL_PARSER_TO:
                return handle_to(parser, error);

        case NTB_MAIL_PARSER_CC:
                return handle_cc(parser, error);

        case NTB_MAIL_PARSER_BCC:
                return handle_bcc(parser, error);

        case NTB_MAIL_PARSER_FROM:
                return handle_from(parser, error);

        case NTB_MAIL_PARSER_SUBJECT:
                return handle_subject(parser, error);

        case NTB_MAIL_PARSER_CONTENT_TYPE:
                return handle_content_type(parser, error);

        case NTB_MAIL_PARSER_TRANSFER_ENCODING:
                return handle_transfer_encoding(parser, error);

        case NTB_MAIL_PARSER_SKIP:
                return true;
        }

        assert(false);
}

static bool
handle_headers_end(struct ntb_mail_parser *parser,
                   struct ntb_error **error)
{
        if (!parser->had_from) {
                ntb_set_error(error,
                              &ntb_mail_parser_error,
                              NTB_MAIL_PARSER_ERROR_MISSING_HEADER,
                              "Missing From header");
                return false;
        }

        if (!parser->had_to && !parser->had_cc && !parser->had_bcc) {
                ntb_set_error(error,
                              &ntb_mail_parser_error,
                              NTB_MAIL_PARSER_ERROR_MISSING_HEADER,
                              "Missing To, Cc or Bcc header");
                return false;
        }

        parser->state = NTB_MAIL_PARSER_CONTENT;

        switch (parser->encoding) {
        case NTB_MAIL_PARSER_ENCODING_BASE64:
                ntb_base64_decode_start(&parser->base64_data);
                break;

        case NTB_MAIL_PARSER_ENCODING_QUOTED_PRINTABLE:
                ntb_quoted_printable_decode_start(&parser->qp_data,
                                                  /* underscore_is_space */
                                                  false);
                break;

        case NTB_MAIL_PARSER_ENCODING_RAW:
                break;
        }

        return true;
}

static ssize_t
handle_header_name(struct ntb_mail_parser *parser,
                   const uint8_t *data,
                   size_t length,
                   struct ntb_error **error)
{
        const uint8_t *end;

        for (end = data;
             end - data < length && *end != '\n' && *end != ':';
             end++);

        ntb_buffer_append(&parser->buffer, data, end - data);

        if (end >= data + length)
                return end - data;

        if (*end == '\n') {
                if (parser->buffer.length == 0) {
                        if (!handle_headers_end(parser, error))
                                return -1;
                } else {
                        ntb_set_error(error,
                                      &ntb_mail_parser_error,
                                      NTB_MAIL_PARSER_ERROR_INVALID_HEADER,
                                      "End of line encountered in the "
                                      "middle of a header");
                        return -1;
                }
        } else {
                set_header(parser);
                parser->state = NTB_MAIL_PARSER_HEADER_VALUE_START;
        }

        return end + 1 - data;
}

static ssize_t
handle_header_value_start(struct ntb_mail_parser *parser,
                          const uint8_t *data,
                          size_t length,
                          struct ntb_error **error)
{
        size_t i;

        /* Skip leading spaces */
        for (i = 0; i < length && ascii_islwsp(data[i]); i++);

        if (i < length) {
                parser->state = NTB_MAIL_PARSER_HEADER_VALUE;
                parser->buffer.length = 0;
        }

        return i;
}

static void
add_space(struct ntb_buffer *buffer)
{
        if (buffer->length == 0 ||
            buffer->data[buffer->length - 1] != ' ')
                ntb_buffer_append_c(buffer, ' ');
}

static ssize_t
handle_header_value(struct ntb_mail_parser *parser,
                    const uint8_t *data,
                    size_t length,
                    struct ntb_error **error)
{
        const uint8_t *p;

        for (p = data; p - data < length; p++) {
                if (ascii_islwsp(*p)) {
                        add_space(&parser->buffer);
                } else if (*p == '\0') {
                        ntb_set_error(error,
                                      &ntb_mail_parser_error,
                                      NTB_MAIL_PARSER_ERROR_INVALID_HEADER,
                                      "Null byte encountered in a header");
                        return -1;
                } else if (*p == '\r') {
                        parser->state = NTB_MAIL_PARSER_CHECK_EOL;
                        p++;
                        break;
                } else if (*p == '\n') {
                        parser->state = NTB_MAIL_PARSER_CHECK_CONTINUATION;
                        p++;
                        break;
                } else {
                        ntb_buffer_append_c(&parser->buffer, *p);
                }
        }

        return p - data;
}

static ssize_t
handle_check_eol(struct ntb_mail_parser *parser,
                 const uint8_t *data,
                 size_t length,
                 struct ntb_error **error)
{
        if (*data != '\n') {
                ntb_set_error(error,
                              &ntb_mail_parser_error,
                              NTB_MAIL_PARSER_ERROR_INVALID_HEADER,
                              "\r encountered in headers which was not "
                              "followed by \n");
                return -1;
        }

        parser->state = NTB_MAIL_PARSER_CHECK_CONTINUATION;

        return 1;
}

static ssize_t
handle_check_continuation(struct ntb_mail_parser *parser,
                          const uint8_t *data,
                          size_t length,
                          struct ntb_error **error)
{
        if (ascii_islwsp(*data)) {
                parser->state = NTB_MAIL_PARSER_HEADER_VALUE;
        } else if (!handle_header_end(parser, error)) {
                return -1;
        } else {
                parser->buffer.length = 0;
                parser->state = NTB_MAIL_PARSER_HEADER_NAME;
        }

        return 0;
}

static ssize_t
handle_content_raw(struct ntb_mail_parser *parser,
                   const uint8_t *data,
                   size_t length,
                   struct ntb_error **error)
{
        if (!parser->data_cb(NTB_MAIL_PARSER_EVENT_CONTENT,
                             data,
                             length,
                             parser->cb_user_data,
                             error))
                return -1;

        return length;
}

static ssize_t
handle_content_base64(struct ntb_mail_parser *parser,
                      const uint8_t *data,
                      size_t length_in,
                      struct ntb_error **error)
{
        size_t length = length_in;
        size_t chunk_size;
        ssize_t got;
        uint8_t buf[512];

        while (length > 0) {
                chunk_size = MIN(NTB_BASE64_MAX_INPUT_FOR_SIZE(sizeof buf),
                                 length);

                got = ntb_base64_decode(&parser->base64_data,
                                        data,
                                        chunk_size,
                                        buf,
                                        error);

                if (got == -1)
                        return -1;

                if (!parser->data_cb(NTB_MAIL_PARSER_EVENT_CONTENT,
                                     buf,
                                     got,
                                     parser->cb_user_data,
                                     error))
                        return -1;

                length -= chunk_size;
                data += chunk_size;
        }

        return length_in;
}

static ssize_t
handle_content_quoted_printable(struct ntb_mail_parser *parser,
                                const uint8_t *data,
                                size_t length_in,
                                struct ntb_error **error)
{
        size_t length = length_in;
        size_t chunk_size;
        ssize_t got;
        uint8_t buf[512];

        while (length > 0) {
                chunk_size = MIN(sizeof buf, length);

                got = ntb_quoted_printable_decode(&parser->qp_data,
                                                  data,
                                                  chunk_size,
                                                  buf,
                                                  error);

                if (got == -1)
                        return -1;

                if (!parser->data_cb(NTB_MAIL_PARSER_EVENT_CONTENT,
                                     buf,
                                     got,
                                     parser->cb_user_data,
                                     error))
                        return -1;

                length -= chunk_size;
                data += chunk_size;
        }

        return length_in;
}

static ssize_t
handle_content(struct ntb_mail_parser *parser,
               const uint8_t *data,
               size_t length,
               struct ntb_error **error)
{
        switch (parser->encoding) {
        case NTB_MAIL_PARSER_ENCODING_BASE64:
                return handle_content_base64(parser, data, length, error);

        case NTB_MAIL_PARSER_ENCODING_QUOTED_PRINTABLE:
                return handle_content_quoted_printable(parser,
                                                       data,
                                                       length,
                                                       error);

        case NTB_MAIL_PARSER_ENCODING_RAW:
                return handle_content_raw(parser, data, length, error);
        }

        assert(false);

        return -1;
}

bool
ntb_mail_parser_parse(struct ntb_mail_parser *parser,
                      const uint8_t *data,
                      size_t length,
                      struct ntb_error **error)
{
        ssize_t processed = -1;

        while (length > 0) {
                switch (parser->state) {
                case NTB_MAIL_PARSER_HEADER_NAME:
                        processed = handle_header_name(parser,
                                                       data,
                                                       length,
                                                       error);
                        break;

                case NTB_MAIL_PARSER_HEADER_VALUE_START:
                        processed = handle_header_value_start(parser,
                                                              data,
                                                              length,
                                                              error);
                        break;

                case NTB_MAIL_PARSER_HEADER_VALUE:
                        processed = handle_header_value(parser,
                                                        data,
                                                        length,
                                                        error);
                        break;

                case NTB_MAIL_PARSER_CHECK_EOL:
                        processed = handle_check_eol(parser,
                                                     data,
                                                     length,
                                                     error);
                        break;

                case NTB_MAIL_PARSER_CHECK_CONTINUATION:
                        processed = handle_check_continuation(parser,
                                                              data,
                                                              length,
                                                              error);
                        break;

                case NTB_MAIL_PARSER_CONTENT:
                        processed = handle_content(parser, data, length, error);
                        break;
                }

                if (processed == -1)
                        return false;

                data += processed;
                length -= processed;
        }

        return true;
}

bool
ntb_mail_parser_end(struct ntb_mail_parser *parser,
                    struct ntb_error **error)
{
        ssize_t got;
        uint8_t buf[3];

        if (parser->state != NTB_MAIL_PARSER_CONTENT) {
                ntb_set_error(error,
                              &ntb_mail_parser_error,
                              NTB_MAIL_PARSER_ERROR_INVALID_HEADER,
                              "The mail ended before the end of the "
                              "headers was encountered");
                return false;
        }

        switch (parser->encoding) {
        case NTB_MAIL_PARSER_ENCODING_BASE64:
                got = ntb_base64_decode_end(&parser->base64_data, buf, error);
                if (got == -1)
                        return false;

                if (!parser->data_cb(NTB_MAIL_PARSER_EVENT_CONTENT,
                                     buf,
                                     got,
                                     parser->cb_user_data,
                                     error))
                        return false;

                break;

        case NTB_MAIL_PARSER_ENCODING_QUOTED_PRINTABLE:
                return ntb_quoted_printable_decode_end(&parser->qp_data, error);

        case NTB_MAIL_PARSER_ENCODING_RAW:
                break;
        }

        return true;
}

void
ntb_mail_parser_free(struct ntb_mail_parser *parser)
{
        ntb_buffer_destroy(&parser->buffer);
        ntb_free(parser);
}
