/*
 * Notbit - A Bitmessage client
 * Copyright (C) 2014  Neil Roberts
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
#include <string.h>
#include <limits.h>
#include <errno.h>

#include "ntb-load-outgoings.h"
#include "ntb-key-value.h"
#include "ntb-buffer.h"
#include "ntb-proto.h"
#include "ntb-log.h"
#include "ntb-util.h"
#include "ntb-base58.h"
#include "ntb-address.h"

struct ntb_load_outgoings_data {
        ntb_load_outgoings_func func;
        void *user_data;

        struct ntb_store_outgoing outgoing;
        bool has_from_address;
        bool has_to_address;
        bool has_ackdata;
        bool has_content_id;
};

static void
reset_data(struct ntb_load_outgoings_data *data)
{
        data->has_from_address = false;
        data->has_to_address = false;
        data->has_ackdata = false;
        data->has_content_id = false;
        data->outgoing.content_encoding = 1;
        data->outgoing.last_getpubkey_send_time = 0;
        data->outgoing.last_msg_send_time = 0;
}

static void
flush_outgoing(struct ntb_load_outgoings_data *data)
{
        if (data->has_from_address &&
            data->has_to_address &&
            data->has_ackdata &&
            data->has_content_id)
                data->func(&data->outgoing, data->user_data);

        reset_data(data);
}

static bool
parse_ackdata(struct ntb_load_outgoings_data *data,
              const char *value,
              uint8_t *ackdata)
{
        ssize_t got;

        got = ntb_base58_decode(value, strlen(value),
                                ackdata,
                                NTB_PROTO_ACKDATA_SIZE);

        if (got == -1)
                return false;

        memmove(ackdata + NTB_PROTO_ACKDATA_SIZE - got, ackdata, got);
        memset(ackdata, 0, NTB_PROTO_ACKDATA_SIZE - got);

        return true;
}

static void
process_property(struct ntb_load_outgoings_data *data,
                 int line_number,
                 const char *key,
                 const char *value)
{
        int64_t int_value;

        if (!strcmp(key, "fromaddress")) {
                if (ntb_address_decode(&data->outgoing.from_address, value))
                        data->has_from_address = true;
                else
                        ntb_log("Invalid address on line %i", line_number);
        } else if (!strcmp(key, "toaddress")) {
                if (ntb_address_decode(&data->outgoing.to_address, value))
                        data->has_to_address = true;
                else
                        ntb_log("Invalid address on line %i", line_number);
        } else if (!strcmp(key, "ackdata")) {
                if (parse_ackdata(data, value, data->outgoing.ackdata))
                        data->has_ackdata = true;
                else
                        ntb_log("Invalid ackdata on line %i", line_number);
        } else if (!strcmp(key, "contentid")) {
                if (ntb_key_value_parse_int_value(line_number,
                                                  value,
                                                  INT_MAX,
                                                  &int_value)) {
                        data->outgoing.content_id = int_value;
                        data->has_content_id = true;
                }
        } else if (!strcmp(key, "contentencoding")) {
                if (ntb_key_value_parse_int_value(line_number,
                                                  value,
                                                  INT_MAX,
                                                  &int_value))
                        data->outgoing.content_encoding = int_value;
        } else if (!strcmp(key, "lastgetpubkeysendtime")) {
                if (ntb_key_value_parse_int_value(line_number,
                                                  value,
                                                  INT64_MAX,
                                                  &int_value))
                        data->outgoing.last_getpubkey_send_time = int_value;
        } else if (!strcmp(key, "lastmsgsendtime")) {
                if (ntb_key_value_parse_int_value(line_number,
                                                  value,
                                                  INT64_MAX,
                                                  &int_value))
                        data->outgoing.last_msg_send_time = int_value;
        }
}

static void
key_value_event_cb(enum ntb_key_value_event event,
                   int line_number,
                   const char *key,
                   const char *value,
                   void *user_data)
{
        struct ntb_load_outgoings_data *data = user_data;

        switch (event) {
        case NTB_KEY_VALUE_EVENT_HEADER:
                flush_outgoing(data);
                break;

        case NTB_KEY_VALUE_EVENT_PROPERTY:
                process_property(data, line_number, key, value);
                break;
        }
}

void
ntb_load_outgoings(FILE *file,
                   ntb_load_outgoings_func func,
                   void *user_data)
{
        struct ntb_load_outgoings_data data;

        ntb_log("Loading outgoing messages");

        data.func = func;
        data.user_data = user_data;

        reset_data(&data);

        ntb_key_value_load(file, key_value_event_cb, &data);

        flush_outgoing(&data);
}
