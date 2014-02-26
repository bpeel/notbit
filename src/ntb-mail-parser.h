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
