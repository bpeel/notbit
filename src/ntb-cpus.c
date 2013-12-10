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
