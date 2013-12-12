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

#include <errno.h>

#include "ntb-file-error.h"

struct ntb_error_domain
ntb_file_error;

enum ntb_file_error
ntb_file_error_from_errno(int errnum)
{
        switch (errnum) {
        case EEXIST:
                return NTB_FILE_ERROR_EXIST;
        case EISDIR:
                return NTB_FILE_ERROR_ISDIR;
        case EACCES:
                return NTB_FILE_ERROR_ACCES;
        case ENAMETOOLONG:
                return NTB_FILE_ERROR_NAMETOOLONG;
        case ENOENT:
                return NTB_FILE_ERROR_NOENT;
        case ENOTDIR:
                return NTB_FILE_ERROR_NOTDIR;
        case EAGAIN:
#if EAGAIN != EWOULDBLOCK
        case EWOULDBLOCK:
#endif
                return NTB_FILE_ERROR_AGAIN;
        case EINTR:
                return NTB_FILE_ERROR_INTR;
        case EPERM:
                return NTB_FILE_ERROR_PERM;
        case EPFNOSUPPORT:
                return NTB_FILE_ERROR_PFNOSUPPORT;
        case EAFNOSUPPORT:
                return NTB_FILE_ERROR_AFNOSUPPORT;
        }

        return NTB_FILE_ERROR_OTHER;
}

NTB_PRINTF_FORMAT(3, 4) void
ntb_file_error_set(struct ntb_error **error,
                   int errnum,
                   const char *format,
                   ...)
{
        va_list ap;

        va_start(ap, format);
        ntb_set_error_va_list(error,
                              &ntb_file_error,
                              ntb_file_error_from_errno(errnum),
                              format,
                              ap);
        va_end(ap);
}
