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

#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

#include "ntb-keygen.h"
#include "ntb-util.h"
#include "ntb-ipc-client.h"
#include "ntb-ipc-proto.h"
#include "ntb-buffer.h"
#include "ntb-proto.h"

static struct ntb_error_domain
arguments_error;

enum ntb_arguments_error {
        NTB_ARGUMENTS_ERROR_INVALID,
        NTB_ARGUMENTS_ERROR_UNKNOWN
};

static int option_version = 0;
static int option_stream = 1;
static int option_zeroes = 0;
static const char *option_label = "";

static const char options[] = "-hzZ:v:s:l:";

static void
usage(void)
{
        printf("notbit-keygen - Adds a new private key to a running notbit "
               "instance\n"
               "usage: notbit-keygen [options]...\n"
               " -h                    Show this help message\n"
               " -z                    Spend a bit of extra time to generate\n"
               "                       a shorter address.\n"
               " -l <label>            Specify a label for the address.\n"
               " -s <stream>           Specify which stream version to use.\n"
               " -v <version>          Specify which key version to generate.\n"
               "                       Defaults to the latest version.\n"
               " -Z <zeroes>           Specify an exact number of zeroes to\n"
               "                       require at the start of the address.\n");
        exit(EXIT_FAILURE);
}

static bool
process_arguments(int argc,
                  char **argv,
                  struct ntb_error **error)
{
        int opt;

        opterr = false;

        while ((opt = getopt(argc, argv, options)) != -1) {
                switch (opt) {
                case ':':
                case '?':
                        ntb_set_error(error,
                                      &arguments_error,
                                      NTB_ARGUMENTS_ERROR_INVALID,
                                      "invalid option '%c'",
                                      optopt);
                        return false;

                case '\1':
                        ntb_set_error(error,
                                      &arguments_error,
                                      NTB_ARGUMENTS_ERROR_UNKNOWN,
                                      "unexpected argument \"%s\"",
                                      optarg);
                        return false;

                case 'z':
                        option_zeroes = 2;
                        break;

                case 'Z':
                        option_zeroes = atoi(optarg);
                        break;

                case 'v':
                        option_version = atoi(optarg);
                        break;

                case 's':
                        option_stream = atoi(optarg);
                        break;

                case 'l':
                        option_label = optarg;
                        break;

                case 'h':
                        usage();
                        break;
                }
        }

        if (optind < argc) {
                ntb_set_error(error,
                              &arguments_error,
                              NTB_ARGUMENTS_ERROR_UNKNOWN,
                              "unexpected argument \"%s\"",
                              argv[optind]);
                return false;
        }

        return true;
}

static bool
send_keygen_command(int sock,
                    uint64_t version,
                    uint64_t stream,
                    uint8_t zeroes,
                    const char *label,
                    struct ntb_error **error)
{
        struct ntb_buffer buf;
        bool res;

        ntb_buffer_init(&buf);

        ntb_ipc_proto_begin_command(&buf, "keygen", 0 /* request_id */);
        ntb_proto_add_var_int(&buf, version);
        ntb_proto_add_var_int(&buf, stream);
        ntb_proto_add_8(&buf, zeroes);
        ntb_proto_add_var_str(&buf, label);
        ntb_ipc_proto_end_command(&buf, 0 /* command_start */);

        res = ntb_ipc_client_send_command(sock,
                                          buf.data,
                                          buf.length,
                                          NULL,
                                          0, /* n_fds */
                                          error);

        ntb_buffer_destroy(&buf);

        return res;
}

static bool
handle_response(const uint8_t *data,
                uint32_t data_length)
{
        struct ntb_proto_var_str address_str;
        uint64_t version;
        uint64_t stream;
        ssize_t header_size;

        header_size = ntb_proto_get_command(data,
                                            data_length,

                                            NTB_PROTO_ARGUMENT_VAR_INT,
                                            &version,

                                            NTB_PROTO_ARGUMENT_VAR_INT,
                                            &stream,

                                            NTB_PROTO_ARGUMENT_END);

        if (header_size == -1)
                goto error;

        if (data_length < header_size + 20)
                goto error;

        data += header_size + 20;
        data_length -= header_size + 20;

        if (!ntb_proto_get_var_str(&data, &data_length, &address_str))
                goto error;

        fwrite(address_str.data, 1, address_str.length, stdout);
        fputc('\n', stdout);

        return true;

error:
        fprintf(stderr, "The IPC response is invalid\n");
        return false;
}

int
ntb_keygen(int argc, char **argv)
{
        struct ntb_error *error = NULL;
        struct ntb_buffer response_buf;
        int ret = EXIT_SUCCESS;
        int sock;

        if (!process_arguments(argc, argv, &error)) {
                fprintf(stderr, "%s\n", error->message);
                return EXIT_FAILURE;
        }

        sock = ntb_ipc_client_connect(&error);

        if (sock == -1) {
                fprintf(stderr, "%s\n", error->message);
                ntb_error_free(error);
                return EXIT_FAILURE;
        }

        if (send_keygen_command(sock,
                                option_version,
                                option_stream,
                                option_zeroes,
                                option_label,
                                &error)) {
                ntb_buffer_init(&response_buf);
                if (ntb_ipc_client_get_response(sock,
                                                &response_buf,
                                                &error,
                                                0 /* request_id */)) {
                        if (!handle_response(response_buf.data,
                                             response_buf.length))
                                ret = EXIT_FAILURE;
                } else {
                        fprintf(stderr, "%s\n", error->message);
                        ntb_error_free(error);
                        ret = EXIT_FAILURE;
                }
                ntb_buffer_destroy(&response_buf);
        } else {
                fprintf(stderr, "%s\n", error->message);
                ntb_error_free(error);
                ret = EXIT_FAILURE;
        }

        close(sock);

        return ret;
}