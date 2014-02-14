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
#include <stdbool.h>
#include <openssl/ripemd.h>
#include <openssl/bn.h>
#include <string.h>
#include <limits.h>
#include <errno.h>

#include "ntb-load-keys.h"
#include "ntb-key-value.h"
#include "ntb-buffer.h"
#include "ntb-proto.h"
#include "ntb-ecc.h"
#include "ntb-log.h"
#include "ntb-util.h"
#include "ntb-base58.h"
#include "ntb-address.h"

struct ntb_load_keys_data {
        struct ntb_ecc *ecc;

        ntb_load_keys_func func;
        void *user_data;

        struct ntb_buffer label;
        struct ntb_buffer address;

        int nonce_trials_per_byte;
        int payload_length_extra_bytes;
        int64_t last_pubkey_send_time;
        bool enabled;
        bool decoy;
        bool has_private_signing_key;
        bool has_private_encryption_key;
        bool has_public_signing_key;
        bool has_public_encryption_key;

        uint8_t private_signing_key[NTB_ECC_PRIVATE_KEY_SIZE];
        uint8_t private_encryption_key[NTB_ECC_PRIVATE_KEY_SIZE];
        uint8_t public_signing_key[NTB_ECC_PUBLIC_KEY_SIZE];
        uint8_t public_encryption_key[NTB_ECC_PUBLIC_KEY_SIZE];
};

static void
reset_data(struct ntb_load_keys_data *data)
{
        data->label.length = 0;
        data->address.length = 0;
        data->nonce_trials_per_byte = NTB_PROTO_MIN_NONCE_TRIALS_PER_BYTE;
        data->payload_length_extra_bytes = NTB_PROTO_MIN_EXTRA_BYTES;
        data->last_pubkey_send_time = 0;
        data->enabled = true;
        data->decoy = false;

        data->has_private_signing_key = false;
        data->has_private_encryption_key = false;
        data->has_public_signing_key = false;
        data->has_public_encryption_key = false;
}

static void
flush_key(struct ntb_load_keys_data *data)
{
        struct ntb_key *key;
        struct ntb_address address;
        bool has_private_keys;

        has_private_keys = (data->has_private_signing_key &&
                            data->has_private_encryption_key);

        if (!has_private_keys &&
            (!data->has_public_signing_key ||
             !data->has_public_encryption_key)) {
                reset_data(data);
                return;
        }

        if (!ntb_address_decode(&address,
                                (const char *) data->address.data)) {
                ntb_log("Address is invalid “%s”",
                        (const char *) data->address.data);
                address.version = 4;
                address.stream = 1;
        }

        if (has_private_keys) {
                key = ntb_key_new(data->ecc,
                                  (const char *) data->label.data,
                                  address.version,
                                  address.stream,
                                  data->private_signing_key,
                                  data->private_encryption_key);
        } else {
                key = ntb_key_new_with_public(data->ecc,
                                              (const char *) data->label.data,
                                              &address,
                                              NULL, /* private signing key */
                                              data->public_signing_key,
                                              NULL, /* private encryption key */
                                              data->public_encryption_key);
        }

        if (memcmp(key->address.ripe, address.ripe, RIPEMD160_DIGEST_LENGTH)) {
                ntb_log("Calculated address for %s does not match",
                        (const char *) data->address.data);
        }

        key->nonce_trials_per_byte = data->nonce_trials_per_byte;
        key->payload_length_extra_bytes =
                data->payload_length_extra_bytes;
        key->last_pubkey_send_time = data->last_pubkey_send_time;
        key->enabled = data->enabled;
        key->decoy = data->decoy;

        data->func(key, data->user_data);

        ntb_key_unref(key);

        reset_data(data);
}

static bool
parse_wif(struct ntb_load_keys_data *data,
          int line_number,
          const char *value,
          uint8_t *result)
{
        uint8_t key_buf[1 + NTB_ECC_PRIVATE_KEY_SIZE + 4];
        uint8_t hash1[SHA256_DIGEST_LENGTH];
        uint8_t hash2[SHA256_DIGEST_LENGTH];
        ssize_t key_length;

        key_length = ntb_base58_decode(value,
                                       strlen(value),
                                       key_buf,
                                       sizeof key_buf);

        if (key_length == -1) {
                ntb_log("Invalid private key on line %i",
                        line_number);
                return false;
        }

        memmove(key_buf + sizeof key_buf - key_length, key_buf, key_length);
        memset(key_buf, 0, sizeof key_buf - key_length);

        if (key_buf[0] != 0x80) {
                ntb_log("Private key on line %i does not have the right prefix",
                        line_number);
                return false;
        }

        SHA256(key_buf, NTB_ECC_PRIVATE_KEY_SIZE + 1, hash1);
        SHA256(hash1, SHA256_DIGEST_LENGTH, hash2);

        if (memcmp(key_buf + 1 + NTB_ECC_PRIVATE_KEY_SIZE, hash2, 4)) {
                ntb_log("Checksum does not match for private key on line %i",
                        line_number);
                return false;
        }

        memcpy(result, key_buf + 1, NTB_ECC_PRIVATE_KEY_SIZE);

        return true;
}

static bool
parse_public_key(struct ntb_load_keys_data *data,
                 int line_number,
                 const char *value,
                 uint8_t *result)
{
        ssize_t key_length;

        key_length = ntb_base58_decode(value,
                                       strlen(value),
                                       result,
                                       NTB_ECC_PUBLIC_KEY_SIZE);

        if (key_length != NTB_ECC_PUBLIC_KEY_SIZE) {
                ntb_log("Invalid public key on line %i",
                        line_number);
                return false;
        }

        if (result[0] != 0x04) {
                ntb_log("Public key on line %i does not have the right prefix",
                        line_number);
                return false;
        }

        return true;
}

static void
process_property(struct ntb_load_keys_data *data,
                 int line_number,
                 const char *key,
                 const char *value)
{
        int64_t int_value;
        bool bool_value;

        if (!strcmp(key, "label")) {
                ntb_buffer_set_length(&data->label, 0);
                ntb_buffer_append_string(&data->label, value);
        } else if (!strcmp(key, "enabled")) {
                if (ntb_key_value_parse_bool_value(line_number,
                                                   value,
                                                   &bool_value))
                        data->enabled = bool_value;
        } else if (!strcmp(key, "decoy")) {
                if (ntb_key_value_parse_bool_value(line_number,
                                                   value,
                                                   &bool_value))
                        data->decoy = bool_value;
        } else if (!strcmp(key, "noncetrialsperbyte")) {
                if (ntb_key_value_parse_int_value(line_number,
                                                  value,
                                                  INT_MAX,
                                                  &int_value))
                        data->nonce_trials_per_byte = int_value;
        } else if (!strcmp(key, "payloadlengthextrabytes")) {
                if (ntb_key_value_parse_int_value(line_number,
                                                  value,
                                                  INT_MAX,
                                                  &int_value))
                        data->payload_length_extra_bytes = int_value;
        } else if (!strcmp(key, "privsigningkey")) {
                if (parse_wif(data,
                              line_number,
                              value,
                              data->private_signing_key))
                        data->has_private_signing_key = true;
        } else if (!strcmp(key, "privencryptionkey")) {
                if (parse_wif(data,
                              line_number,
                              value,
                              data->private_encryption_key))
                        data->has_private_encryption_key = true;
        } else if (!strcmp(key, "pubsigningkey")) {
                if (parse_public_key(data,
                                     line_number,
                                     value,
                                     data->public_signing_key))
                        data->has_public_signing_key = true;
        } else if (!strcmp(key, "pubencryptionkey")) {
                if (parse_public_key(data,
                                     line_number,
                                     value,
                                     data->public_encryption_key))
                        data->has_public_encryption_key = true;
        } else if (!strcmp(key, "lastpubkeysendtime")) {
                if (ntb_key_value_parse_int_value(line_number,
                                                  value,
                                                  INT64_MAX,
                                                  &int_value))
                        data->last_pubkey_send_time = int_value;
        }
}

static void
key_value_event_cb(enum ntb_key_value_event event,
                   int line_number,
                   const char *key,
                   const char *value,
                   void *user_data)
{
        struct ntb_load_keys_data *data = user_data;

        switch (event) {
        case NTB_KEY_VALUE_EVENT_HEADER:
                flush_key(data);
                data->address.length = 0;
                ntb_buffer_append_string(&data->address, value);
                break;

        case NTB_KEY_VALUE_EVENT_PROPERTY:
                process_property(data, line_number, key, value);
                break;
        }
}

void
ntb_load_keys(FILE *file,
              ntb_load_keys_func func,
              void *user_data)
{
        struct ntb_load_keys_data data;

        ntb_log("Loading keys");

        data.ecc = ntb_ecc_new();

        ntb_buffer_init(&data.label);
        ntb_buffer_init(&data.address);

        data.func = func;
        data.user_data = user_data;

        reset_data(&data);

        ntb_key_value_load(file, key_value_event_cb, &data);

        flush_key(&data);

        ntb_buffer_destroy(&data.label);
        ntb_buffer_destroy(&data.address);

        ntb_ecc_free(data.ecc);
}
