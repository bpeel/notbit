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

#include <sys/stat.h>
#include <errno.h>
#include <string.h>

#include "ntb-mkdir.h"
#include "ntb-buffer.h"
#include "ntb-file-error.h"

bool
ntb_mkdir(const char *name,
          struct ntb_error **error)
{
        if (mkdir(name, S_IRWXU | S_IRWXG | S_IRWXO) == -1 && errno != EEXIST) {
                ntb_file_error_set(error,
                                   errno,
                                   "Error creating directory %s: %s",
                                   name,
                                   strerror(errno));
                return false;
        }

        return true;
}

bool
ntb_mkdir_hierarchy(struct ntb_buffer *buf,
                    struct ntb_error **error)
{
        uint8_t *slash;
        bool res;

        if (buf->length < 1)
                return true;

        slash = buf->data;

        while ((slash = memchr(slash + 1,
                               '/',
                               buf->data + buf->length - slash))) {
                *slash = '\0';

                res = ntb_mkdir((const char *) buf->data, error);

                *slash = '/';

                if (!res)
                        return false;
        }

        if (buf->data[buf->length - 1] != '/') {
                ntb_buffer_append_c(buf, '\0');
                buf->length--;
                if (!ntb_mkdir((const char *) buf->data, error))
                        return false;
        }

        return true;
}
