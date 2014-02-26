/*
 * Notbit - A Bitmessage client
 * Copyright (C) 2013, 2014  Neil Roberts
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
#include <errno.h>

#include "ntb-key-value.h"
#include "ntb-buffer.h"
#include "ntb-log.h"
#include "ntb-util.h"

enum ntb_key_value_state {
        NTB_KEY_VALUE_STATE_HEADER_START,
        NTB_KEY_VALUE_STATE_BAD_HEADER_START,
        NTB_KEY_VALUE_STATE_READING_HEADER,
        NTB_KEY_VALUE_STATE_END_HEADER_LINE,
        NTB_KEY_VALUE_STATE_END_HEADER_LINE2,
        NTB_KEY_VALUE_STATE_FIELD_START,
        NTB_KEY_VALUE_STATE_READING_FIELD_NAME,
        NTB_KEY_VALUE_STATE_WAITING_EQUALS,
        NTB_KEY_VALUE_STATE_BAD_FIELD,
        NTB_KEY_VALUE_STATE_WAITING_VALUE_START,
        NTB_KEY_VALUE_STATE_READING_VALUE,
};

struct ntb_key_value_data {
        enum ntb_key_value_state state;

        struct ntb_ecc *ecc;

        ntb_key_value_func func;
        void *user_data;

        struct ntb_buffer key_buffer;
        struct ntb_buffer value_buffer;

        int line_num;
};

static void
ensure_null_buffer(struct ntb_buffer *buffer)
{
        ntb_buffer_ensure_size(buffer, buffer->length + 1);
        buffer->data[buffer->length] = '\0';
}

static void
process_header(struct ntb_key_value_data *data)
{
        ensure_null_buffer(&data->value_buffer);

        data->func(NTB_KEY_VALUE_EVENT_HEADER,
                   data->line_num,
                   NULL, /* key */
                   (const char *) data->value_buffer.data,
                   data->user_data);
}

static void
process_value(struct ntb_key_value_data *data)
{
        ensure_null_buffer(&data->key_buffer);

        while (data->value_buffer.length > 0 &&
               data->value_buffer.data[data->value_buffer.length - 1] == ' ')
                data->value_buffer.length--;

        ensure_null_buffer(&data->value_buffer);

        data->func(NTB_KEY_VALUE_EVENT_PROPERTY,
                   data->line_num,
                   (const char *) data->key_buffer.data,
                   (const char *) data->value_buffer.data,
                   data->user_data);
}

static void
handle_byte(struct ntb_key_value_data *data,
            int ch)
{
        switch (data->state) {
        case NTB_KEY_VALUE_STATE_HEADER_START:
                if (ch == '[') {
                        data->state = NTB_KEY_VALUE_STATE_READING_HEADER;
                        data->value_buffer.length = 0;
                } else if (ch != ' ' && ch != '\n') {
                        ntb_log("Invalid header on line %i",
                                data->line_num);
                        data->state = NTB_KEY_VALUE_STATE_BAD_HEADER_START;
                }
                return;
        case NTB_KEY_VALUE_STATE_BAD_HEADER_START:
                if (ch == '\n')
                        data->state = NTB_KEY_VALUE_STATE_HEADER_START;
                return;
        case NTB_KEY_VALUE_STATE_READING_HEADER:
                if (ch == '\n') {
                        ntb_log("Invalid header on line %i",
                                data->line_num);
                        data->state = NTB_KEY_VALUE_STATE_FIELD_START;
                } else if (ch == ']') {
                        process_header(data);
                        data->state = NTB_KEY_VALUE_STATE_END_HEADER_LINE;
                } else {
                        ntb_buffer_append_c(&data->value_buffer, ch);
                }
                return;
        case NTB_KEY_VALUE_STATE_END_HEADER_LINE:
                if (ch == '\n') {
                        data->state = NTB_KEY_VALUE_STATE_FIELD_START;
                } else if (ch != ' ') {
                        ntb_log("Junk after header on line %i",
                                data->line_num);
                        data->state = NTB_KEY_VALUE_STATE_END_HEADER_LINE2;
                }
                return;
        case NTB_KEY_VALUE_STATE_END_HEADER_LINE2:
                if (ch == '\n')
                        data->state = NTB_KEY_VALUE_STATE_FIELD_START;
                return;
        case NTB_KEY_VALUE_STATE_FIELD_START:
                if (ch == '[') {
                        data->state = NTB_KEY_VALUE_STATE_READING_HEADER;
                        data->value_buffer.length = 0;
                } else if (ch != ' ' && ch != '\n') {
                        ntb_buffer_set_length(&data->key_buffer, 1);
                        data->key_buffer.data[0] = ch;
                        data->state = NTB_KEY_VALUE_STATE_READING_FIELD_NAME;
                }
                return;
        case NTB_KEY_VALUE_STATE_READING_FIELD_NAME:
                if (ch == ' ') {
                        data->state = NTB_KEY_VALUE_STATE_WAITING_EQUALS;
                } else if (ch == '=') {
                        data->state = NTB_KEY_VALUE_STATE_WAITING_VALUE_START;
                } else if (ch == '\n') {
                        ntb_log("Invalid line %i",
                                data->line_num);
                        data->state = NTB_KEY_VALUE_STATE_FIELD_START;
                } else {
                        ntb_buffer_append_c(&data->key_buffer, ch);
                }
                return;
        case NTB_KEY_VALUE_STATE_WAITING_EQUALS:
                if (ch == '=') {
                        data->state = NTB_KEY_VALUE_STATE_WAITING_VALUE_START;
                } else if (ch == '\n') {
                        ntb_log("Invalid line %i",
                                data->line_num);
                        data->state = NTB_KEY_VALUE_STATE_FIELD_START;
                } else if (ch != ' ') {
                        ntb_log("Invalid line %i",
                                data->line_num);
                        data->state = NTB_KEY_VALUE_STATE_BAD_FIELD;
                }
                return;
        case NTB_KEY_VALUE_STATE_WAITING_VALUE_START:
                if (ch == '\n') {
                        ntb_buffer_set_length(&data->value_buffer, 0);
                        process_value(data);
                        data->state = NTB_KEY_VALUE_STATE_FIELD_START;
                } else if (ch != ' ') {
                        ntb_buffer_set_length(&data->value_buffer, 1);
                        data->value_buffer.data[0] = ch;
                        data->state = NTB_KEY_VALUE_STATE_READING_VALUE;
                }
                return;
        case NTB_KEY_VALUE_STATE_READING_VALUE:
                if (ch == '\n') {
                        process_value(data);
                        data->state = NTB_KEY_VALUE_STATE_FIELD_START;
                } else {
                        ntb_buffer_append_c(&data->value_buffer, ch);
                }
                return;
        case NTB_KEY_VALUE_STATE_BAD_FIELD:
                if (ch == '\n')
                        data->state = NTB_KEY_VALUE_STATE_FIELD_START;
                return;
        }

        ntb_fatal("Invalid state reached");
}

void
ntb_key_value_load(FILE *file,
                   ntb_key_value_func func,
                   void *user_data)
{
        struct ntb_key_value_data data;
        int ch;

        data.line_num = 1;
        data.state = NTB_KEY_VALUE_STATE_HEADER_START;

        ntb_buffer_init(&data.key_buffer);
        ntb_buffer_init(&data.value_buffer);

        data.func = func;
        data.user_data = user_data;

        while ((ch = fgetc(file)) != EOF) {
                handle_byte(&data, ch);

                if (ch == '\n')
                        data.line_num++;
        }

        handle_byte(&data, '\n');

        ntb_buffer_destroy(&data.key_buffer);
        ntb_buffer_destroy(&data.value_buffer);
}

bool
ntb_key_value_parse_bool_value(int line_number,
                               const char *value,
                               bool *result)
{
        if (!strcmp(value, "true")) {
                *result = true;
                return true;
        }

        if (!strcmp(value, "false")) {
                *result = false;
                return true;
        }

        ntb_log("Invalid boolean value on line %i", line_number);

        return false;
}

bool
ntb_key_value_parse_int_value(int line_number,
                              const char *value,
                              int64_t max,
                              int64_t *result)
{
        long long int int_value;
        char *tail;

        errno = 0;

        int_value = strtoll(value, &tail, 10);

        if (errno || tail == value || *tail || value < 0) {
                ntb_log("Invalid integer value on line %i", line_number);
                return false;
        }

        if (int_value > max) {
                ntb_log("Value too big on line %i", line_number);
                return false;
        }

        *result = int_value;

        return true;
}
