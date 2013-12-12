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
