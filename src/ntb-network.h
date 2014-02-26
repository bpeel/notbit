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

#ifndef NTB_NETWORK_H
#define NTB_NETWORK_H

#include <stdbool.h>

#include "ntb-error.h"
#include "ntb-signal.h"
#include "ntb-blob.h"

extern struct ntb_error_domain
ntb_network_error;

enum ntb_network_error {
        NTB_NETWORK_ERROR_INVALID_ADDRESS
};

enum ntb_network_add_object_flags {
        NTB_NETWORK_SKIP_VALIDATION = (1 << 0),
        NTB_NETWORK_DELAY = (1 << 1)
};

enum ntb_network_object_location {
        NTB_NETWORK_OBJECT_LOCATION_NOWHERE,
        NTB_NETWORK_OBJECT_LOCATION_STORE,
        NTB_NETWORK_OBJECT_LOCATION_MEMORY
};

struct ntb_network;

struct ntb_network *
ntb_network_new(void);

void
ntb_network_add_object_from_data(struct ntb_network *nw,
                                 enum ntb_proto_inv_type type,
                                 const uint8_t *object_data,
                                 size_t object_data_length,
                                 enum ntb_network_add_object_flags flags,
                                 const char *source_note);

void
ntb_network_add_blob(struct ntb_network *nw,
                     struct ntb_blob *blob,
                     enum ntb_network_add_object_flags flags,
                     const char *source_note);

void
ntb_network_load_store(struct ntb_network *nw);

bool
ntb_network_add_listen_address(struct ntb_network *nw,
                               const char *address,
                               struct ntb_error **error);

bool
ntb_network_add_peer_address(struct ntb_network *nw,
                             const char *address,
                             struct ntb_error **error);

struct ntb_signal *
ntb_network_get_new_object_signal(struct ntb_network *nw);

void
ntb_network_set_only_use_explicit_addresses(struct ntb_network *nw,
                                            bool value);

enum ntb_network_object_location
ntb_network_get_object(struct ntb_network *nw,
                       const uint8_t *hash,
                       struct ntb_blob **blob);

void
ntb_network_free(struct ntb_network *nw);

#endif /* NTB_NETWORK_H */
