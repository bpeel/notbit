/*
 * Notbit - A Bitmessage client
 * Copyright (C) 2014  Neil Roberts
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

#include <assert.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include "ntb-buffer.h"
#include "ntb-ipc-client.h"
#include "ntb-ipc-sockaddr.h"
#include "ntb-list.h"
#include "ntb-log.h"
#include "ntb-netaddress.h"
#include "ntb-smtp.h"
#include "ntb-util.h"

/* Force the user to use localhost, because there is no support 
   for encryption or authentication. */
#define SMTP_ADDR "127.0.0.1"

enum smtp_command {
        SMTP_COMMAND_HELO,
        SMTP_COMMAND_MAIL,
        SMTP_COMMAND_RCPT,
        SMTP_COMMAND_DATA,
        SMTP_COMMAND_QUIT,
        SMTP_COMMAND_RSET,
        SMTP_COMMAND_NOOP
};

enum smtp_state {
        SMTP_RECV_FROM,
        SMTP_RECV_TO,
        SMTP_RECV_DATA,
        SMTP_WAIT_FOR_COMMAND
};

struct mail {
        struct ntb_buffer from;
        struct ntb_list to;
        struct ntb_buffer text;
        enum smtp_state smtp_state;
};

struct to {
        struct ntb_buffer addr;
        struct ntb_list link;
};

struct ntb_smtp_context {
        bool exit;
        int socket;
        pthread_t thread;
        /* Guard for exit */
        pthread_mutex_t lock;
};

static void 
clear_struct_mail(struct mail *mail) 
{
        struct to *tmp, *to;
        ntb_list_for_each_safe(to, tmp, &mail->to, link) {
                ntb_list_remove(&to->link);
                ntb_buffer_destroy(&to->addr);
                ntb_free(to);
        }
        ntb_buffer_set_length(&mail->from, 0);
        ntb_buffer_set_length(&mail->text, 0);
        mail->smtp_state = SMTP_WAIT_FOR_COMMAND;
}

static void
free_struct_mail(struct mail *mail) 
{
        struct to *tmp, *to;
        ntb_list_for_each_safe(to, tmp, &mail->to, link) {
                ntb_list_remove(&to->link);
                ntb_buffer_destroy(&to->addr);
                ntb_free(to);
        }
        ntb_buffer_destroy(&mail->from);
        ntb_buffer_destroy(&mail->text);
}

static void 
init_struct_mail(struct mail *mail) 
{
        ntb_buffer_init(&mail->from);
        ntb_list_init(&mail->to);
        ntb_buffer_init(&mail->text);
        mail->smtp_state = SMTP_WAIT_FOR_COMMAND;
}

static void 
send_str(int sock, const char *data) 
{
        send(sock, data, strlen(data), 0);
}

static void 
shift_left(char *buf, int offset) 
{
        int i;
        const int size_to_move = strlen(buf) - offset;
        for (i=0;i<=size_to_move;i++) {
                buf[i] = buf[i+offset];
        }
}

static bool 
process_smtp_command(char *buf, enum smtp_command *smtp_command) 
{
        if (!strncmp(buf, "HELO", 4)) {
                *smtp_command = SMTP_COMMAND_HELO;
                return true;
        }

        if (!strncmp(buf, "MAIL FROM:", 10)) {
                *smtp_command = SMTP_COMMAND_MAIL;
                shift_left(buf, 10);
                return true;
        }

        if (!strncmp(buf, "RCPT TO:", 8)) {
                *smtp_command = SMTP_COMMAND_RCPT;
                shift_left(buf, 8);
                return true;
        }

        if (!strncmp(buf, "DATA", 4)) {
                *smtp_command = SMTP_COMMAND_DATA;
                return true;
        }

        if (!strncmp(buf, "RSET", 4)) {
                *smtp_command = SMTP_COMMAND_RSET;
                return true;
        }

        if (!strncmp(buf, "NOOP", 4)) {
                *smtp_command = SMTP_COMMAND_NOOP;
                return true;
        }

        if (!strncmp(buf, "QUIT", 4)) {
                *smtp_command = SMTP_COMMAND_QUIT;
                return true;
        }

        return false;
}

static void
convert_line_ends(char *data) 
{
        char *tmp = ntb_alloc(strlen(data)+1);
        int i;
        int offset = 0;
        for (i=0;i<strlen(data);i++) {
                if (!strncmp(&data[i], "\r\n", 2)) {
                        offset++;
                } else {
                        tmp[i-offset] = data[i];
                }
        }
        tmp[i-offset] = '\0';
        memcpy(data, tmp, strlen(tmp)+1);
        ntb_free(tmp);
}

static void
add_bcc_to_text(struct mail *mail)
{
        struct to *to;
        struct ntb_buffer buffer;
        bool found_bcc = false;

        ntb_buffer_init(&buffer);
        ntb_buffer_append(&buffer, "BCC: ", 5);

        ntb_list_for_each(to, &mail->to, link) {
                if (!strstr((char *)mail->text.data, (char *)to->addr.data)) {
                        found_bcc = true;
                        ntb_buffer_append(&buffer, 
                                          to->addr.data, 
                                          to->addr.length-1);
                        ntb_buffer_append(&buffer, 
                                          ", ", 
                                          2);
                }
        }

        if (!found_bcc) {
                ntb_buffer_destroy(&buffer);
                return;
        }

        ntb_buffer_set_length(&buffer, buffer.length-2);
        ntb_buffer_append_c(&buffer, '\n');
        ntb_buffer_append(&buffer, mail->text.data, mail->text.length);
        ntb_buffer_set_length(&mail->text, 0);
        ntb_buffer_append(&mail->text, buffer.data, buffer.length);
        ntb_buffer_destroy(&buffer);
}        

static bool 
process_mail(struct mail *mail, char **error_str) 
{
        struct ntb_buffer response_buf;
        struct ntb_error *error = NULL;
        struct sockaddr *sockaddr = NULL;
        socklen_t sockaddr_len;
        const char *sockaddr_path;
        int sock_command = -1;
        int sock_data = -1;
        int sock_tmp = -1;
        bool state = true;

        const uint8_t email_command[] =
                "email\0\0\0\0\0\0\0" /* command name */
                "\0\0\0\0" /* request id */
                "\0\0\0\0"; /* payload length */

        *error_str = NULL;

        convert_line_ends((char *)mail->text.data);
        add_bcc_to_text(mail);

        ntb_ipc_sockaddr_create(&sockaddr, &sockaddr_len, "smtp");
        sockaddr_path = ((struct sockaddr_un *) sockaddr)->sun_path;
        /* The directory should have already been created by ntb_ipc_new() */

        sock_data = socket(PF_LOCAL, SOCK_STREAM, 0);
        if (sock_data == -1) {
                ntb_log("Can't create socket");
                state = false;
                goto end;
        }

        if (unlink(sockaddr_path) == -1 && errno != ENOENT) {
                ntb_log("Error deleting IPC socket %s: %s",
                        sockaddr_path,
                        strerror(errno));
                state = false;
                goto end;
        }

        if (bind(sock_data, sockaddr, sockaddr_len) == -1) {
                ntb_log("Can't bind socket %s", sockaddr_path);
                state = false;
                goto end;
        }

        if (listen(sock_data, 1) == -1) {
                ntb_log("Can't listen on socket %s", sockaddr_path);
                state = false;
                goto end;
        }

        sock_command = ntb_ipc_client_connect(&error);

        if (sock_command == -1) {
                ntb_log("%s\n", error->message);
                ntb_error_free(error);
                state = false;
                goto end;
        }

        sock_tmp = socket(PF_LOCAL, SOCK_STREAM, 0);
        if (sock_tmp == -1) {
                ntb_log("Can't create socket");
                state = false;
                goto end;
        }

        if (connect(sock_tmp, sockaddr, sockaddr_len) == -1) {
                ntb_log("Can't connect socket");
                state = false;
                goto end;
        }

        if (ntb_ipc_client_send_command(sock_command,
                                        email_command,
                                        sizeof email_command - 1,
                                        &sock_tmp,
                                        1, /* n_fds */
                                        &error)) {

                sock_tmp = accept(sock_data, NULL, NULL);
                send_str(sock_tmp, (char *)mail->text.data);
                ntb_close(sock_tmp);
                ntb_close(sock_data);

                ntb_buffer_init(&response_buf);
                if (!ntb_ipc_client_get_response(sock_command,
                                                 &response_buf,
                                                 &error,
                                                 0 /* request_id */)) {
                        ntb_log("%s\n", error->message);
                        *error_str = ntb_strdup(error->message);
                        ntb_error_free(error);
                        state = false;
                }
                ntb_buffer_destroy(&response_buf);
        } else {
                ntb_log("%s\n", error->message);
                *error_str = ntb_strdup(error->message);
                ntb_error_free(error);
                state = false;
        }

end:
        if (sock_data != -1) ntb_close(sock_data);
        if (sock_tmp != -1) ntb_close(sock_tmp);
        if (sock_command != -1) ntb_close(sock_command);
        unlink(sockaddr_path);
        ntb_free(sockaddr);

        return state;
}

static int 
recv_data(int sock, struct mail *mail) 
{
        static struct to *tmp_to;
        int recv_len;
        const int buf_len = 80;
        char buf[81];
        char *error_str;
        bool smtp_command_finished;
        enum smtp_command smtp_command;

        recv_len = recv(sock, buf, buf_len, 0);
        if (recv_len == 0 || recv_len == -1) return false;

        buf[recv_len] = '\0';
        if (!strncmp(&buf[strlen(buf)-2], "\r\n", 2) && 
            mail->smtp_state != SMTP_RECV_DATA) {
                smtp_command_finished = true;
                buf[strlen(buf)-2] = '\0';
        } else {
                smtp_command_finished = false;
        }

        if (mail->smtp_state == SMTP_WAIT_FOR_COMMAND) {
                if (!process_smtp_command(buf, &smtp_command)) {
                        send_str(sock, "502 Command unknown\r\n");
                        return true;
                }

                switch (smtp_command) {
                        case SMTP_COMMAND_HELO:
                                send_str(sock, "250 OK\r\n");
                                return true;
                                break;
                        case SMTP_COMMAND_MAIL:
                                if (mail->from.length) {
                                        send_str(sock, "503\r\n");
                                        return false;
                                }
                                mail->smtp_state = SMTP_RECV_FROM;
                                break;
                        case SMTP_COMMAND_RCPT:
                                mail->smtp_state = SMTP_RECV_TO;
                                if (!tmp_to) {
                                        tmp_to = ntb_alloc(sizeof(*tmp_to));
                                        ntb_buffer_init(&tmp_to->addr);
                                } else {
                                        ntb_buffer_set_length(&tmp_to->addr, 0);
                                }
                                break;
                        case SMTP_COMMAND_DATA:
                                if (!mail->from.length ||
                                    ntb_list_empty(&mail->to)) {
                                        send_str(sock, "503\r\n");
                                        return false;
                                }
                                send_str(sock, "354 End data with .\r\n");
                                mail->smtp_state = SMTP_RECV_DATA;
                                break;
                        case SMTP_COMMAND_RSET:
                                send_str(sock, "250 OK\r\n");
                                clear_struct_mail(mail);
                                return true;
                                break;
                        case SMTP_COMMAND_NOOP:
                                send_str(sock, "250 OK\r\n");
                                return true;
                                break;
                        case SMTP_COMMAND_QUIT:
                                send_str(sock, "221 Bye\r\n");
                                return false;
                                break;
                }
        }

        switch (mail->smtp_state) {
                case SMTP_RECV_DATA:
                        ntb_buffer_append(&mail->text, buf, strlen(buf));

                        if (!strncmp((char *)&mail->text.data[mail->text.length-5],
                                     "\r\n.\r\n",
                                     5)) {
                                mail->text.data[mail->text.length-3] = '\0';    
                                if (process_mail(mail, &error_str)) {
                                        send_str(sock, "250 OK\r\n");
                                } else {
                                        send_str(sock, "553 ");
                                        if (error_str) 
                                                send_str(sock, error_str);
                                        send_str(sock, "\r\n");
                                        ntb_free(error_str);
                                }
                                clear_struct_mail(mail);
                        }
                        return true;
                        break;
                case SMTP_RECV_FROM:
                        ntb_buffer_append(&mail->from, buf, strlen(buf));

                        if (smtp_command_finished) {
                                ntb_buffer_append_c(&mail->from, '\0');
                                send_str(sock, "250 OK\r\n");
                                mail->smtp_state = SMTP_WAIT_FOR_COMMAND;
                        }
                        return true;
                        break;
                case SMTP_RECV_TO:
                        ntb_buffer_append(&tmp_to->addr, buf, strlen(buf));

                        if (smtp_command_finished) {
                                ntb_buffer_append_c(&tmp_to->addr, '\0');
                                send_str(sock, "250 OK\r\n");
                                ntb_list_insert(&mail->to, &tmp_to->link);
                                tmp_to = NULL;
                                mail->smtp_state = SMTP_WAIT_FOR_COMMAND;
                        }
                        return true;
                        break;
                case SMTP_WAIT_FOR_COMMAND:
                        assert(false);
        }
        assert(false);
}

static void*
smtp_main_loop(void *data) 
{
        struct ntb_smtp_context *ctx = data;
        struct mail mail;
        struct timeval wait_time;
        int sock;
        fd_set sock_set;

        init_struct_mail(&mail);

        ntb_log("Starting SMTP server...");
        while (true) {
                pthread_mutex_lock(&ctx->lock);
                if (ctx->exit) {
                        ntb_log("Closing SMTP server...");
                        pthread_mutex_unlock(&ctx->lock);
                        break;
                }
                pthread_mutex_unlock(&ctx->lock);

                FD_ZERO(&sock_set);
                FD_SET(ctx->socket, &sock_set);
                wait_time.tv_sec = 1;
                wait_time.tv_usec = 0;

                if (select(ctx->socket+1, 
                           &sock_set, 
                           NULL, 
                           NULL, 
                           &wait_time) == -1) 
                        break;

                if (!FD_ISSET(ctx->socket, &sock_set)) 
                        continue;

                sock = accept(ctx->socket, NULL, NULL);
                if (sock < 0) {
                        ntb_close(sock);
                        continue;
                } else {        
                        send_str(sock, "220 ");
                        send_str(sock, SMTP_ADDR);
                        send_str(sock, " SMTP\r\n");
                }

                while (recv_data(sock, &mail)); 
                ntb_close(sock);
                clear_struct_mail(&mail);
        }
        free_struct_mail(&mail);
        return NULL;
}

struct ntb_smtp_context* 
ntb_smtp_start(int port) {
        const int true_value = true;
        struct ntb_netaddress address;
        struct ntb_netaddress_native native_address;
        struct ntb_smtp_context *ctx = ntb_alloc(sizeof(*ctx));

        ctx->exit = false;
        pthread_mutex_init(&ctx->lock, NULL);

        if (!ntb_netaddress_from_string(&address, SMTP_ADDR, port)) {
                ntb_log("Invalid port for SMTP server: %d!", port);
                return NULL;
        }
        ntb_netaddress_to_native(&address, &native_address); 

        ctx->socket = socket(native_address.sockaddr.sa_family == AF_INET6 ?
                             PF_INET6 : PF_INET, 
                             SOCK_STREAM, 
                             0);
        if (ctx->socket < 0) {
                ntb_log("Can't open socket for SMTP server.");
                return NULL;
        }

        setsockopt(ctx->socket,
                   SOL_SOCKET, 
                   SO_REUSEADDR,
                   &true_value, 
                   sizeof true_value);

        if (bind(ctx->socket, 
                 &native_address.sockaddr, 
                 native_address.length) < 0) {
                ntb_log("Can't bind socket for SMTP server.");
                return NULL;
        }

        if (listen(ctx->socket, 5) < 0) {
                ntb_log("Can't listen on socket for SMTP server.");
                return NULL;
        } 
        
        ctx->thread = ntb_create_thread(smtp_main_loop, ctx);
        return ctx;
}

void ntb_smtp_stop(struct ntb_smtp_context *ctx) 
{
        pthread_mutex_lock(&ctx->lock);
        ctx->exit = true;
        pthread_mutex_unlock(&ctx->lock);
        pthread_join(ctx->thread, NULL);
        ntb_close(ctx->socket);
        ntb_free(ctx);
        return;
}

