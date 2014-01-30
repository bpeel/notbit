/*
 * Notbit - A Bitmessage client
 * Copyright (C) 2014  Neil Roberts
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
