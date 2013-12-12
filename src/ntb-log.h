/*
 * Notbit - A Bitmessage client
 * Copyright (C) 2011, 2013  Neil Roberts
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

#ifndef __NTB_LOG_H__
#define __NTB_LOG_H__

#include <stdbool.h>

#include "ntb-util.h"
#include "ntb-log.h"
#include "ntb-error.h"

bool
ntb_log_available(void);

NTB_PRINTF_FORMAT(1, 2) void
ntb_log(const char *format, ...);

bool
ntb_log_set_file(const char *filename,
                 struct ntb_error **error);

void
ntb_log_start(void);

void
ntb_log_close(void);

#endif /* __NTB_LOG_H__ */
