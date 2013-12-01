/*
 * Notbit - A Bitmessage client
 * Copyright (C) 2011, 2013  Neil Roberts
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
        tm = localtime(&now);

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
                while (!ntb_log_finished && &ntb_log_buffer.length == 0)
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
                ntb_set_error(error,
                              &ntb_log_error,
                              NTB_LOG_ERROR_FILE,
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

bool
ntb_log_start(struct ntb_error **error)
{
        int result;

        if (!ntb_log_available() || ntb_log_has_thread)
                return true;

        result = pthread_create(&ntb_log_thread,
                                NULL, /* attr */
                                ntb_log_thread_func,
                                NULL /* thread func arg */);
        if (result) {
                ntb_set_error(error,
                              &ntb_log_error,
                              NTB_LOG_ERROR_THREAD,
                              "Error starting log thread: %s",
                              strerror(result));
                return false;
        }

        ntb_log_has_thread = true;

        return true;
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
