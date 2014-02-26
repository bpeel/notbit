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
