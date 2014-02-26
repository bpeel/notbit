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

#ifndef NTB_ERROR_H
#define NTB_ERROR_H

#include <stdarg.h>

#include "ntb-util.h"

/* Exception handling mechanism inspired by glib's GError */

struct ntb_error_domain {
        int stub;
};

struct ntb_error {
        struct ntb_error_domain *domain;
        int code;
        char message[1];
};

void
ntb_set_error_va_list(struct ntb_error **error_out,
                      struct ntb_error_domain *domain,
                      int code,
                      const char *format,
                      va_list ap);

NTB_PRINTF_FORMAT(4, 5) void
ntb_set_error(struct ntb_error **error,
              struct ntb_error_domain *domain,
              int code,
              const char *format,
              ...);

void
ntb_error_free(struct ntb_error *error);

void
ntb_error_clear(struct ntb_error **error);

void
ntb_error_propagate(struct ntb_error **error,
                    struct ntb_error *other);

#endif /* NTB_ERROR_H */
