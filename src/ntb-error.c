/*
 * Notbit - A Bitmessage client
 * Copyright (C) 2013  Neil Roberts
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

#include <stdio.h>
#include <stdarg.h>

#include "ntb-error.h"
#include "ntb-util.h"

static struct ntb_error *
ntb_error_new(int buf_size)
{
        return ntb_alloc(NTB_STRUCT_OFFSET(struct ntb_error, message) +
                         buf_size);
}

void
ntb_set_error_va_list(struct ntb_error **error_out,
                      struct ntb_error_domain *domain,
                      int code,
                      const char *format,
                      va_list ap)
{
        struct ntb_error *error;
        va_list apcopy;
        size_t buf_size, required_size;

        if (error_out == NULL)
                /* Error is being ignored */
                return;

        if (*error_out) {
                ntb_warning("Multiple exceptions occured without "
                            "being handled");
                return;
        }

        buf_size = 64;

        error = ntb_error_new(buf_size);

        va_copy(apcopy, ap);
        required_size = vsnprintf(error->message, buf_size, format, ap);

        if (required_size >= buf_size) {
                ntb_free(error);
                buf_size = required_size + 1;
                error = ntb_error_new(buf_size);
                vsnprintf(error->message, buf_size, format, apcopy);
        }

        va_end(apcopy);

        error->domain = domain;
        error->code = code;
        *error_out = error;
}

void
ntb_set_error(struct ntb_error **error_out,
              struct ntb_error_domain *domain,
              int code,
              const char *format,
              ...)
{
        va_list ap;

        va_start(ap, format);
        ntb_set_error_va_list(error_out, domain, code, format, ap);
        va_end(ap);
}

void
ntb_error_free(struct ntb_error *error)
{
        ntb_free(error);
}

void
ntb_error_clear(struct ntb_error **error)
{
        ntb_error_free(*error);
        *error = NULL;
}

void
ntb_error_propagate(struct ntb_error **error,
                    struct ntb_error *other)
{
        ntb_return_if_fail(other != NULL);

        if (error)
                *error = other;
        else
                ntb_error_free(other);
}
