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

#ifndef NTB_FILE_ERROR_H
#define NTB_FILE_ERROR_H

#include "ntb-error.h"

extern struct ntb_error_domain
ntb_file_error;

enum ntb_file_error {
  NTB_FILE_ERROR_EXIST,
  NTB_FILE_ERROR_ISDIR,
  NTB_FILE_ERROR_ACCES,
  NTB_FILE_ERROR_NAMETOOLONG,
  NTB_FILE_ERROR_NOENT,
  NTB_FILE_ERROR_NOTDIR,
  NTB_FILE_ERROR_AGAIN,
  NTB_FILE_ERROR_INTR,
  NTB_FILE_ERROR_PERM,
  NTB_FILE_ERROR_PFNOSUPPORT,
  NTB_FILE_ERROR_AFNOSUPPORT,

  NTB_FILE_ERROR_OTHER
};

enum ntb_file_error
ntb_file_error_from_errno(int errnum);

NTB_PRINTF_FORMAT(3, 4) void
ntb_file_error_set(struct ntb_error **error,
                   int errnum,
                   const char *format,
                   ...);

#endif /* NTB_FILE_ERROR_H */
