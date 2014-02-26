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

#include "config.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "ntb-daemon.h"
#include "ntb-sendmail.h"
#include "ntb-keygen.h"

int
main(int argc, char **argv)
{
        const char *bn;

        for (bn = argv[0] + strlen(argv[0]);
             bn > argv[0] && bn[-1] != '/';
             bn--);

        if (!strcmp(bn, "notbit-sendmail")) {
                return ntb_sendmail(argc, argv);
        } else if (!strcmp(bn, "notbit-keygen")) {
                return ntb_keygen(argc, argv);
        } else if (!strcmp(bn, "notbit")) {
                return ntb_daemon(argc, argv);
        } else {
                fprintf(stderr, "Unknown executable name “%s”\n", argv[0]);
                return EXIT_FAILURE;
        }
}
