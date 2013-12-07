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

#include "ntb-main-context.h"
#include "ntb-log.h"
#include "ntb-network.h"
#include "ntb-store.h"
#include "ntb-proto.h"

static struct ntb_error_domain
arguments_error;

enum ntb_arguments_error {
        NTB_ARGUMENTS_ERROR_INVALID,
        NTB_ARGUMENTS_ERROR_UNKNOWN
};

struct address {
        const char *address;
        struct address *next;
};

static struct address *option_listen_addresses = NULL;
static struct address *option_peer_addresses = NULL;
static char *option_log_file = "/dev/stdout";
static bool option_daemonize = false;
static char *option_user = NULL;
static char *option_group = NULL;
static char *option_store_directory = NULL;
static bool option_only_explicit_addresses = false;

static const char options[] = "-a:l:du:g:D:p:eh";

static void
add_address(struct address **list,
            const char *address)
{
        struct address *listen_address;

        listen_address = ntb_alloc(sizeof (struct address));
        listen_address->address = address;
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
        printf("Notbit - a Bitmessage ↔ maildir daemon\n"
               "usage: notbit [options]...\n"
               " -h                    Show this help message\n"
               " -a <address[:port]>   Add an address to listen on. Can be\n"
               "                       specified multiple times. Defaults to\n"
               "                       [::1] to listen on port "
               NTB_STRINGIFY(NTB_PROTO_DEFAULT_PORT) "\n"
               " -p <address[:port]>   Add to the list of initial peers that\n"
               "                       might be connected to.\n"
               " -e                    Only connect to peers specified by "
               ""                      "-p\n"
               " -l <file>             Specify the pathname for the log file\n"
               "                       Defaults to stdout.\n"
               " -d                    Fork and detach from terminal after\n"
               "                       creating listen socket. (Daemonize)\n"
               " -u <user>             Specify a user to run as. Used to drop\n"
               "                       privileges.\n"
               " -g <group>            Specify a group to run as.\n"
               " -D <datadir>          Specify an alternate location for the\n"
               "                       object store. Defaults to $XDG_DATA_HOME"
               ""                      "/notbit\n");
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
                add_address(&option_listen_addresses, "[::]");

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
add_addresses(struct ntb_network *nw,
              struct ntb_error **error)
{
        struct address *address;

        for (address = option_listen_addresses;
             address;
             address = address->next) {
                if (!ntb_network_add_listen_address(nw,
                                                    address->address,
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

static int
run_network(void)
{
        struct ntb_store *store;
        struct ntb_network *nw;
        int ret = EXIT_SUCCESS;
        struct ntb_error *error = NULL;
        struct ntb_main_context_source *quit_source;
        bool quit = false;

        nw = ntb_network_new();

        if (!add_addresses(nw, &error)) {
                fprintf(stderr, "%s\n", error->message);
                ntb_error_clear(&error);
                ret = EXIT_FAILURE;
        } else {
                if (option_group)
                        set_group(option_group);
                if (option_user)
                        set_user(option_user);

                store = ntb_store_new(option_store_directory, &error);

                if (store == NULL) {
                        fprintf(stderr, "%s\n", error->message);
                        ntb_error_clear(&error);
                        ret = EXIT_FAILURE;
                } else {
                        ntb_store_set_default(store);

                        if (option_daemonize)
                                daemonize();

                        if (!ntb_store_start(store, &error)) {
                                /* This probably shouldn't happen. By
                                   the time we get here may have
                                   daemonized so we can't really print
                                   anything but let's do it anyway. */
                                ntb_warning("%s\n", error->message);
                                ntb_error_clear(&error);
                        } else if (!ntb_log_start(&error)) {
                                /* This probably shouldn't happen. By the time
                                   we get here may have daemonized so we can't
                                   really print anything but let's do it
                                   anyway. */
                                ntb_warning("Error starting log file: %s\n",
                                            error->message);
                                ntb_error_clear(&error);
                        } else {
                                ntb_network_load_store(nw);

                                quit_source = ntb_main_context_add_quit(NULL,
                                                                        quit_cb,
                                                                        &quit);

                                do
                                        ntb_main_context_poll(NULL);
                                while(!quit);

                                ntb_log("Exiting...");

                                ntb_main_context_remove_source(quit_source);
                        }

                        ntb_store_free(store);
                }
        }

        ntb_network_free(nw);

        return ret;
}

int
main(int argc, char **argv)
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

        if (option_log_file && !ntb_log_set_file(option_log_file, &error)) {
                fprintf(stderr, "Error setting log file: %s\n", error->message);
                ntb_error_clear(&error);
                ret = EXIT_FAILURE;
        } else {
                ret = run_network();

                ntb_log_close();
        }

        ntb_main_context_free(mc);

        free_addresses(option_peer_addresses);
        free_addresses(option_listen_addresses);

        return ret;
}
