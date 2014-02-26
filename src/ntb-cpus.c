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

#include <stdio.h>
#include <stdbool.h>

#include "ntb-cpus.h"
#include "ntb-util.h"

static int
get_n_cpus_from_file(FILE *file)
{
        char search_string[] = "processor";
        const int search_string_length = sizeof search_string - 1;
        int n_cpus = 0;
        int state = 0; /* state 0 is the beginning of a line */
        int ch;

        while (true) {
                ch = fgetc(file);

                if (ch == EOF)
                        return MAX(n_cpus, 1);

                if (ch == '\n') {
                        state = 0; /* we're now at the beginning of a line */
                } else if (state == search_string_length) {
                        if (ch == ':') {
                                n_cpus++;
                                state = -1; /* skip the rest of the line */
                        } else if (ch != ' ' && ch != '\t') {
                                state = -1; /* skip the rest of the line */
                        }
                } else if (state != -1) {
                        if (ch == search_string[state])
                                state++;
                        else
                                state = -1; /* skip the rest of the line */
                }
        }
}

int
ntb_cpus_count(void)
{
        FILE *file;
        static int n_cpus = 0;

        /* Use the cached value if we've already calculated it */
        if (n_cpus)
                return n_cpus;

        file = fopen("/proc/cpuinfo", "r");
        if (file == NULL) {
                n_cpus = 1;
        } else {
                n_cpus = get_n_cpus_from_file(file);
                fclose(file);
        }

        return n_cpus;
}
