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

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <pwd.h>
#include <grp.h>
#include <sys/types.h>

#include "ntb-daemon.h"
#include "ntb-main-context.h"
#include "ntb-log.h"
#include "ntb-network.h"
#include "ntb-store.h"
#include "ntb-proto.h"
#include "ntb-file-error.h"
#include "ntb-keyring.h"
#include "ntb-ipc.h"

static struct ntb_error_domain
arguments_error;

enum ntb_arguments_error {
        NTB_ARGUMENTS_ERROR_INVALID,
        NTB_ARGUMENTS_ERROR_UNKNOWN
};

struct address {
        /* Only one of these will be set depending on whether the user
         * specified a full address or just a port */
        const char *address;
        const char *port;

        struct address *next;
};

static struct address *option_listen_addresses = NULL;
static struct address *option_peer_addresses = NULL;
static char *option_log_file = NULL;
static bool option_daemonize = false;
static char *option_user = NULL;
static char *option_group = NULL;
static char *option_store_directory = NULL;
static char *option_maildir = NULL;
static bool option_only_explicit_addresses = false;

static const char options[] = "-a:l:du:g:D:p:eP:hm:";

static void
add_address(struct address **list,
            const char *address)
{
        struct address *listen_address;

        listen_address = ntb_alloc(sizeof (struct address));
        listen_address->address = address;
        listen_address->port = NULL;
        listen_address->next = *list;
        *list = listen_address;
}

static void
add_port(struct address **list,
         const char *port_string)
{
        struct address *listen_address;

        listen_address = ntb_alloc(sizeof (struct address));
        listen_address->address = NULL;
        listen_address->port = port_string;
        listen_address->next = *list;
        *list = listen_address;
}

static void
free_addresses(struct address *list)
{
        struct address *address, *next;

        for (address = list;
             address;
             address = next) {
                next = address->next;
                ntb_free(address);
        }
}

static void
usage(void)
{
        printf("Notbit - a Bitmessage → maildir daemon\n"
               "usage: notbit [options]...\n"
               " -h                    Show this help message\n"
               " -p <port>             Specifies a port to listen on.\n"
               "                       Equivalent to -a [::]:port.\n"
               " -a <address[:port]>   Add an address to listen on. Can be\n"
               "                       specified multiple times. Defaults to\n"
               "                       [::] to listen on port "
               NTB_STRINGIFY(NTB_PROTO_DEFAULT_PORT) "\n"
               " -P <address[:port]>   Add to the list of initial peers that\n"
               "                       might be connected to.\n"
               " -e                    Only connect to peers specified by "
               ""                      "-P\n"
               " -l <file>             Specify the pathname for the log file\n"
               "                       Defaults to stdout.\n"
               " -d                    Fork and detach from terminal after\n"
               "                       creating listen socket. (Daemonize)\n"
               " -u <user>             Specify a user to run as. Used to drop\n"
               "                       privileges.\n"
               " -g <group>            Specify a group to run as.\n"
               " -D <datadir>          Specify an alternate location for the\n"
               "                       object store. Defaults to $XDG_DATA_HOME"
               ""                      "/notbit\n"
               " -m <maildir>          Specify the maildir to save messages "
               "to.\n"
               "                       Defaults to $HOME/.maildir\n");
        exit(EXIT_FAILURE);
}

static bool
process_arguments(int argc, char **argv, struct ntb_error **error)
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
                        goto error;

                case '\1':
                        ntb_set_error(error,
                                      &arguments_error,
                                      NTB_ARGUMENTS_ERROR_UNKNOWN,
                                      "unexpected argument \"%s\"",
                                      optarg);
                        goto error;

                case 'a':
                        add_address(&option_listen_addresses, optarg);
                        break;

                case 'p':
                        add_port(&option_listen_addresses, optarg);
                        break;

                case 'P':
                        add_address(&option_peer_addresses, optarg);
                        break;

                case 'l':
                        option_log_file = optarg;
                        break;

                case 'd':
                        option_daemonize = true;
                        break;

                case 'u':
                        option_user = optarg;
                        break;

                case 'g':
                        option_group = optarg;
                        break;

                case 'D':
                        option_store_directory = optarg;
                        break;

                case 'e':
                        option_only_explicit_addresses = true;
                        break;

                case 'm':
                        option_maildir = optarg;
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
                goto error;
        }

        if (option_listen_addresses == NULL)
                add_port(&option_listen_addresses,
                         NTB_STRINGIFY(NTB_PROTO_DEFAULT_PORT));

        return true;

error:
        free_addresses(option_peer_addresses);
        option_peer_addresses = NULL;
        free_addresses(option_listen_addresses);
        option_listen_addresses = NULL;
        return false;
}

static void
daemonize(void)
{
        pid_t pid, sid;

        pid = fork();

        if (pid < 0) {
                ntb_warning("fork failed: %s", strerror(errno));
                exit(EXIT_FAILURE);
        }
        if (pid > 0)
                /* Parent process, we can just quit */
                exit(EXIT_SUCCESS);

        /* Reset the file mask (not really sure why we do this..) */
        umask(0);

        /* Create a new SID for the child process */
        sid = setsid();
        if (sid < 0) {
                ntb_warning("setsid failed: %s", strerror(errno));
                exit(EXIT_FAILURE);
        }

        /* Change the working directory so we're resilient against it being
           removed */
        if (chdir("/") < 0) {
                ntb_warning("chdir failed: %s", strerror(errno));
                exit(EXIT_FAILURE);
        }

        /* Redirect standard files to /dev/null */
        freopen("/dev/null", "r", stdin);
        freopen("/dev/null", "w", stdout);
        freopen("/dev/null", "w", stderr);
}

static void
set_user(const char *user_name)
{
        struct passwd *user_info;

        user_info = getpwnam(user_name);

        if (user_info == NULL) {
                fprintf(stderr, "Unknown user \"%s\"\n", user_name);
                exit(EXIT_FAILURE);
        }

        if (setuid(user_info->pw_uid) == -1) {
                fprintf(stderr, "Error setting user privileges: %s\n",
                        strerror(errno));
                exit(EXIT_FAILURE);
        }
}

static void
set_group(const char *group_name)
{
        struct group *group_info;

        group_info = getgrnam(group_name);

        if (group_info == NULL) {
                fprintf(stderr, "Unknown group \"%s\"\n", group_name);
                exit(EXIT_FAILURE);
        }

        if (setgid(group_info->gr_gid) == -1) {
                fprintf(stderr, "Error setting group privileges: %s\n",
                        strerror(errno));
                exit(EXIT_FAILURE);
        }
}

static void
quit_cb(struct ntb_main_context_source *source,
        void *user_data)
{
        bool *quit = user_data;
        *quit = true;
}

static bool
add_listen_address_to_network(struct ntb_network *nw,
                              struct address *address,
                              struct ntb_error **error)
{
        struct ntb_error *local_error = NULL;
        char *full_address;
        bool res;

        if (address->address)
                return ntb_network_add_listen_address(nw,
                                                      address->address,
                                                      error);

        /* If just the port is specified then we'll first try
         * listening on an IPv6 address. Listening on IPv6 should
         * accept IPv4 connections as well. However some servers have
         * IPv6 disabled so if it doesn't work we'll fall back to
         * IPv4 */
        full_address = ntb_strconcat("[::]:", address->port, NULL);
        res = ntb_network_add_listen_address(nw, full_address, &local_error);
        ntb_free(full_address);

        if (res)
                return true;

        if (local_error->domain == &ntb_file_error &&
            (local_error->code == NTB_FILE_ERROR_PFNOSUPPORT ||
             local_error->code == NTB_FILE_ERROR_AFNOSUPPORT)) {
                ntb_error_free(local_error);
        } else {
                ntb_error_propagate(error, local_error);
                return false;
        }

        full_address = ntb_strconcat("0.0.0.0:", address->port, NULL);
        res = ntb_network_add_listen_address(nw, full_address, error);
        ntb_free(full_address);

        return res;
}

static bool
add_addresses(struct ntb_network *nw,
              struct ntb_error **error)
{
        struct address *address;

        for (address = option_listen_addresses;
             address;
             address = address->next) {
                if (!add_listen_address_to_network(nw,
                                                   address,
                                                   error))
                        return false;
        }

        for (address = option_peer_addresses;
             address;
             address = address->next) {
                if (!ntb_network_add_peer_address(nw,
                                                  address->address,
                                                  error))
                        return false;
        }

        if (option_only_explicit_addresses)
                ntb_network_set_only_use_explicit_addresses(nw, true);

        return true;
}

static bool
set_log_file(struct ntb_store *store,
             struct ntb_error **error)
{
        struct ntb_buffer buffer;
        bool res;

        if (option_log_file) {
                return ntb_log_set_file(option_log_file, error);
        } else if (option_daemonize) {
                ntb_buffer_init(&buffer);
                ntb_buffer_append_string(&buffer,
                                         ntb_store_get_directory(store));
                if (buffer.length > 0 && buffer.data[buffer.length - 1] != '/')
                        ntb_buffer_append_c(&buffer, '/');
                ntb_buffer_append_string(&buffer, "notbit.log");

                res = ntb_log_set_file((const char *) buffer.data, error);

                ntb_buffer_destroy(&buffer);

                return res;
        } else {
                return ntb_log_set_file("/dev/stdout", error);
        }
}

static void
run_main_loop(struct ntb_network *nw,
              struct ntb_keyring *keyring,
              struct ntb_store *store)
{
        struct ntb_main_context_source *quit_source;
        bool quit = false;

        if (option_group)
                set_group(option_group);
        if (option_user)
                set_user(option_user);

        if (option_daemonize)
                daemonize();

        ntb_keyring_start(keyring);
        ntb_log_start();

        ntb_network_load_store(nw);
        ntb_keyring_load_store(keyring);

        ntb_store_start(store);

        quit_source = ntb_main_context_add_quit(NULL, quit_cb, &quit);

        do
                ntb_main_context_poll(NULL);
        while(!quit);

        ntb_log("Exiting...");

        ntb_main_context_remove_source(quit_source);
}

static int
run_network(void)
{
        struct ntb_store *store = NULL;
        struct ntb_network *nw;
        struct ntb_keyring *keyring;
        struct ntb_ipc *ipc;
        int ret = EXIT_SUCCESS;
        struct ntb_error *error = NULL;

        nw = ntb_network_new();

        if (!add_addresses(nw, &error)) {
                fprintf(stderr, "%s\n", error->message);
                ntb_error_clear(&error);
                ret = EXIT_FAILURE;
        } else {
                store = ntb_store_new(option_store_directory,
                                      option_maildir,
                                      &error);

                if (store == NULL) {
                        fprintf(stderr, "%s\n", error->message);
                        ntb_error_clear(&error);
                        ret = EXIT_FAILURE;
                } else {
                        ntb_store_set_default(store);

                        if (!set_log_file(store, &error)) {
                                fprintf(stderr, "%s\n", error->message);
                                ntb_error_clear(&error);
                                ret = EXIT_FAILURE;
                        } else {
                                keyring = ntb_keyring_new(nw);
                                ipc = ntb_ipc_new(keyring, &error);

                                if (ipc == NULL) {
                                        fprintf(stderr, "%s\n", error->message);
                                        ntb_error_clear(&error);
                                        ret = EXIT_FAILURE;
                                } else {
                                        run_main_loop(nw, keyring, store);
                                        ntb_ipc_free(ipc);
                                }

                                ntb_keyring_free(keyring);

                                ntb_log_close();
                        }
                }
        }

        ntb_network_free(nw);

        /* We need to free the store after freeing the network so that
         * if the network queues anything in the store just before it
         * is freed then we will be sure to complete the task before
         * exiting */
        if (store)
                ntb_store_free(store);

        return ret;
}

int
ntb_daemon(int argc, char **argv)
{
        struct ntb_main_context *mc;
        struct ntb_error *error = NULL;
        int ret = EXIT_SUCCESS;

        if (!process_arguments(argc, argv, &error)) {
                fprintf(stderr, "%s\n", error->message);
                return EXIT_FAILURE;
        }

        mc = ntb_main_context_get_default(&error);

        if (mc == NULL) {
                fprintf(stderr, "%s\n", error->message);
                return EXIT_FAILURE;
        }

        ret = run_network();

        ntb_main_context_free(mc);

        free_addresses(option_peer_addresses);
        free_addresses(option_listen_addresses);

        return ret;
}
