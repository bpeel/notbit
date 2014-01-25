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

#ifndef NTB_MAIL_PARSER_H
#define NTB_MAIL_PARSER_H

#include <stdint.h>
#include <stdbool.h>

#include "ntb-error.h"
#include "ntb-address.h"

extern struct ntb_error_domain
ntb_mail_parser_error;

enum ntb_mail_parser_error {
        NTB_MAIL_PARSER_ERROR_INVALID_HEADER,
        NTB_MAIL_PARSER_ERROR_INVALID_CONTENT_TYPE,
        NTB_MAIL_PARSER_ERROR_INVALID_TRANSFER_ENCODING,
        NTB_MAIL_PARSER_ERROR_INVALID_ADDRESS,
        NTB_MAIL_PARSER_ERROR_MISSING_HEADER
};

enum ntb_mail_parser_event {
        NTB_MAIL_PARSER_EVENT_SUBJECT,
        NTB_MAIL_PARSER_EVENT_SOURCE,
        NTB_MAIL_PARSER_EVENT_DESTINATION,
        NTB_MAIL_PARSER_EVENT_CONTENT
};

struct ntb_mail_parser;

typedef bool
(* ntb_mail_parser_address_cb)(enum ntb_mail_parser_event event,
                               const struct ntb_address *address,
                               void *user_data,
                               struct ntb_error **error);

typedef bool
(* ntb_mail_parser_data_cb)(enum ntb_mail_parser_event event,
                            const uint8_t *data,
                            size_t length,
                            void *user_data,
                            struct ntb_error **error);

struct ntb_mail_parser *
ntb_mail_parser_new(ntb_mail_parser_address_cb address_cb,
                    ntb_mail_parser_data_cb data_cb,
                    void *user_data);

bool
ntb_mail_parser_parse(struct ntb_mail_parser *parser,
                      const uint8_t *data,
                      size_t length,
                      struct ntb_error **error);

bool
ntb_mail_parser_end(struct ntb_mail_parser *parser,
                    struct ntb_error **error);

void
ntb_mail_parser_free(struct ntb_mail_parser *parser);

#endif /* NTB_MAIL_PARSER_H */
