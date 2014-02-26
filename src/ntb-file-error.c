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
