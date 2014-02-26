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
