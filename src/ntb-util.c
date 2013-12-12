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
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include "ntb-util.h"

void
ntb_fatal(const char *format, ...)
{
        va_list ap;

        va_start(ap, format);
        vfprintf(stderr, format, ap);
        va_end(ap);

        fputc('\n', stderr);

        fflush(stderr);

        abort();
}

void
ntb_warning(const char *format, ...)
{
        va_list ap;

        va_start(ap, format);
        vfprintf(stderr, format, ap);
        va_end(ap);

        fputc('\n', stderr);
}

void *
ntb_alloc(size_t size)
{
        void *result = malloc(size);

        if (result == NULL)
                ntb_fatal("Memory exhausted");

        return result;
}

void *
ntb_realloc(void *ptr, size_t size)
{
        if (ptr == NULL)
                return ntb_alloc(size);

        ptr = realloc(ptr, size);

        if (ptr == NULL)
                ntb_fatal("Memory exhausted");

        return ptr;
}

void
ntb_free(void *ptr)
{
        if (ptr)
                free(ptr);
}

char *
ntb_strdup(const char *str)
{
        return ntb_memdup(str, strlen(str) + 1);
}

void *
ntb_memdup(const void *data, size_t size)
{
        void *ret;

        ret = ntb_alloc(size);
        memcpy(ret, data, size);

        return ret;
}

char *
ntb_strconcat(const char *string1, ...)
{
        size_t string1_length;
        size_t total_length;
        size_t str_length;
        va_list ap, apcopy;
        const char *str;
        char *result, *p;

        if (string1 == NULL)
                return ntb_strdup("");

        total_length = string1_length = strlen(string1);

        va_start(ap, string1);
        va_copy(apcopy, ap);

        while ((str = va_arg(ap, const char *)))
                total_length += strlen(str);

        va_end(ap);

        result = ntb_alloc(total_length + 1);
        memcpy(result, string1, string1_length);
        p = result + string1_length;

        while ((str = va_arg(apcopy, const char *))) {
                str_length = strlen(str);
                memcpy(p, str, str_length);
                p += str_length;
        }
        *p = '\0';

        va_end(apcopy);

        return result;
}

int
ntb_close(int fd)
{
        int ret;

        do {
                ret = close(fd);
        } while (ret == -1 && errno == EINTR);

        return ret;
}

pthread_t
ntb_create_thread(void *(* thread_func)(void *),
                  void *user_data)
{
        pthread_t thread;
        int result;

        result = pthread_create(&thread,
                                NULL, /* attr */
                                thread_func,
                                user_data);

        if (result)
                ntb_fatal("Error creating thread: %s",
                          strerror(result));

        return thread;
}
