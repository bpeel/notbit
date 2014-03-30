/*
 * Notbit - A Bitmessage client
 * Copyright (C) 2011, 2013  Neil Roberts
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

#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <pthread.h>
#include <stdbool.h>
#include <signal.h>

#include "ntb-log.h"
#include "ntb-buffer.h"
#include "ntb-file-error.h"

static FILE *ntb_log_file = NULL;
static struct ntb_buffer ntb_log_buffer = NTB_BUFFER_STATIC_INIT;
static pthread_t ntb_log_thread;
static bool ntb_log_has_thread = false;
static pthread_mutex_t ntb_log_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t ntb_log_cond = PTHREAD_COND_INITIALIZER;
static bool ntb_log_finished = false;

struct ntb_error_domain
ntb_log_error;

bool
ntb_log_available(void)
{
        return ntb_log_file != NULL;
}

void
ntb_log(const char *format, ...)
{
        va_list ap;
        time_t now;
        struct tm *tm;

        if (!ntb_log_available())
                return;

        pthread_mutex_lock(&ntb_log_mutex);

        time(&now);
        tm = gmtime(&now);

        ntb_buffer_append_printf(&ntb_log_buffer,
                                 "[%4d-%02d-%02dT%02d:%02d:%02dZ] ",
                                 tm->tm_year + 1900,
                                 tm->tm_mon + 1,
                                 tm->tm_mday,
                                 tm->tm_hour,
                                 tm->tm_min,
                                 tm->tm_sec);

        va_start(ap, format);
        ntb_buffer_append_vprintf(&ntb_log_buffer, format, ap);
        va_end(ap);

        ntb_buffer_append_c(&ntb_log_buffer, '\n');

        pthread_cond_signal(&ntb_log_cond);

        pthread_mutex_unlock(&ntb_log_mutex);
}

static void
block_sigint(void)
{
        sigset_t sigset;

        sigemptyset(&sigset);
        sigaddset(&sigset, SIGINT);
        sigaddset(&sigset, SIGTERM);

        if (pthread_sigmask(SIG_BLOCK, &sigset, NULL) == -1)
                ntb_warning("pthread_sigmask failed: %s", strerror(errno));
}

static void *
ntb_log_thread_func(void *data)
{
        struct ntb_buffer alternate_buffer;
        struct ntb_buffer tmp;
        bool had_error = false;

        block_sigint();

        ntb_buffer_init(&alternate_buffer);

        pthread_mutex_lock(&ntb_log_mutex);

        while (!ntb_log_finished || ntb_log_buffer.length > 0) {
                size_t wrote;

                /* Wait until there's something to do */
                while (!ntb_log_finished && ntb_log_buffer.length == 0)
                        pthread_cond_wait(&ntb_log_cond, &ntb_log_mutex);

                if (had_error) {
                        /* Just ignore the data */
                        ntb_buffer_set_length(&ntb_log_buffer, 0);
                } else {
                        /* Swap the log buffer for an empty alternate
                           buffer so we can write from the normal
                           one */
                        tmp = ntb_log_buffer;
                        ntb_log_buffer = alternate_buffer;
                        alternate_buffer = tmp;

                        /* Release the mutex while we do a blocking write */
                        pthread_mutex_unlock(&ntb_log_mutex);

                        wrote = fwrite(alternate_buffer.data, 1 /* size */ ,
                                       alternate_buffer.length, ntb_log_file);

                        /* If there was an error then we'll just start
                           ignoring data until we're told to quit */
                        if (wrote != alternate_buffer.length)
                                had_error = true;
                        else
                                fflush(ntb_log_file);

                        ntb_buffer_set_length(&alternate_buffer, 0);

                        pthread_mutex_lock(&ntb_log_mutex);
                }
        }

        pthread_mutex_unlock(&ntb_log_mutex);

        ntb_buffer_destroy(&alternate_buffer);

        return NULL;
}

bool
ntb_log_set_file(const char *filename, struct ntb_error **error)
{
        FILE *file;

        file = fopen(filename, "a");

        if (file == NULL) {
                ntb_file_error_set(error,
                                   errno,
                                   "%s: %s",
                                   filename,
                                   strerror(errno));
                return false;
        }

        ntb_log_close();

        ntb_log_file = file;
        ntb_log_finished = false;

        return true;
}

void
ntb_log_start(void)
{
        if (!ntb_log_available() || ntb_log_has_thread)
                return;

        ntb_log_thread = ntb_create_thread(ntb_log_thread_func,
                                           NULL /* thread func arg */);
        ntb_log_has_thread = true;
}

void
ntb_log_close(void)
{
        if (ntb_log_has_thread) {
                pthread_mutex_lock(&ntb_log_mutex);
                ntb_log_finished = true;
                pthread_cond_signal(&ntb_log_cond);
                pthread_mutex_unlock(&ntb_log_mutex);

                pthread_join(ntb_log_thread, NULL);

                ntb_log_has_thread = false;
        }

        ntb_buffer_destroy(&ntb_log_buffer);
        ntb_buffer_init(&ntb_log_buffer);

        if (ntb_log_file) {
                fclose(ntb_log_file);
                ntb_log_file = NULL;
        }
}
