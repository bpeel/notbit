/*
 * Notbit - A Bitmessage client
 * Copyright (C) 2013, 2014  Neil Roberts
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

#include <stdint.h>
#include <string.h>
#include <assert.h>

#include "ntb-save-message.h"
#include "ntb-base64.h"

static bool
need_encoded_words(const uint8_t *subject,
                   size_t subject_length)
{
        size_t i;

        if (subject_length > 76 - 9)
                return true;

        for (i = 0; i < subject_length; i++)
                if (subject[i] >= 128 || subject[i] < ' ')
                        return true;

        if (subject_length > 0) {
                for (i = 0; i < subject_length - 1; i++) {
                        if (subject[i] == '=' && subject[i + 1] == '?')
                                return true;
                }
        }

        return false;
}

static void
write_encoded_words(const uint8_t *subject,
                    size_t subject_length,
                    FILE *out)
{
        /* Maximum line length allowed is 76 and the first line will
         * contain ‘Subject: ’ so we want to account for that. Base64
         * grows the size by a quarter. Each line contains the extra
         * characters ‘=?UTF-8?B?’ and ‘?=’ */
        const size_t max_encoded_length = 76 - 9 - 10 - 2;
        const size_t max_chunk_length = max_encoded_length / 4 * 3;
        char buf[(max_chunk_length * 4 + 2) / 3];
        size_t encoded_size;
        size_t chunk_size;

        while (true) {
                chunk_size = MIN(max_chunk_length, subject_length);

                encoded_size = ntb_base64_encode(subject, chunk_size, buf);

                assert(encoded_size <= sizeof buf);

                fputs("=?UTF-8?B?", out);
                fwrite(buf, 1, encoded_size, out);
                fputs("?=", out);

                subject += chunk_size;
                subject_length -= chunk_size;

                if (subject_length <= 0)
                        break;

                fputs("\n ", out);
        }
}

static void
write_subject(const uint8_t *subject,
              size_t subject_length,
              FILE *out)
{
        if (need_encoded_words(subject, subject_length))
                write_encoded_words(subject, subject_length, out);
        else
                fwrite(subject, 1, subject_length, out);
}

void
ntb_save_message(time_t timestamp,
                 const char *from_address,
                 const char *to_address,
                 struct ntb_blob *blob,
                 FILE *out)
{
        struct ntb_proto_decrypted_msg msg;
        const uint8_t *eol;
        static const char *day_names[] = {
                "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"
        };
        static const char *month_names[] = {
                "Jan", "Feb", "Mar", "Apr", "May", "Jun",
                "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
        };
        struct tm tm;

        localtime_r(&timestamp, &tm);

        fprintf(out,
                "From: %s@bitmessage\n"
                "To: %s@bitmessage\n"
                "Date: %s, %i %s %i %02i:%02i:%02i %c%02li%02li\n"
                "Content-Type: text/plain; charset=UTF-8\n"
                "Content-Transfer-Encoding: 8bit\n",
                from_address,
                to_address,
                day_names[tm.tm_wday],
                tm.tm_mday,
                month_names[tm.tm_mon],
                tm.tm_year + 1900,
                tm.tm_hour,
                tm.tm_min,
                tm.tm_sec,
                tm.tm_gmtoff < 0 ? '-' : '+',
                labs(tm.tm_gmtoff) / 3600,
                labs(tm.tm_gmtoff) % 3600 / 60);

        ntb_proto_get_decrypted_msg(blob->data, blob->size, &msg);

        if (msg.encoding == 2 &&
            msg.message_length >= 9 &&
            !memcmp(msg.message, "Subject:", 8) &&
            (eol = memchr(msg.message, '\n', msg.message_length))) {
                fputs("Subject: ", out);
                write_subject(msg.message + 8, eol - msg.message - 8, out);
                fputc('\n', out);

                msg.message_length -= eol - msg.message + 1;
                msg.message = eol + 1;

                if (msg.message_length >= 5 &&
                    !memcmp(msg.message, "Body:", 5)) {
                        msg.message += 5;
                        msg.message_length -= 5;
                }
        }

        fputc('\n', out);
        fwrite(msg.message, 1, msg.message_length, out);
}
