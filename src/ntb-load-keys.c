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

#include <stdint.h>
#include <stdbool.h>
#include <openssl/ripemd.h>
#include <openssl/bn.h>
#include <string.h>
#include <limits.h>
#include <errno.h>

#include "ntb-load-keys.h"
#include "ntb-buffer.h"
#include "ntb-proto.h"
#include "ntb-pub-key-maker.h"
#include "ntb-log.h"
#include "ntb-util.h"
#include "ntb-base58.h"
#include "ntb-address.h"

enum ntb_load_keys_state {
        NTB_LOAD_KEYS_STATE_HEADER_START,
        NTB_LOAD_KEYS_STATE_BAD_HEADER_START,
        NTB_LOAD_KEYS_STATE_READING_HEADER,
        NTB_LOAD_KEYS_STATE_END_HEADER_LINE,
        NTB_LOAD_KEYS_STATE_END_HEADER_LINE2,
        NTB_LOAD_KEYS_STATE_FIELD_START,
        NTB_LOAD_KEYS_STATE_READING_FIELD_NAME,
        NTB_LOAD_KEYS_STATE_WAITING_EQUALS,
        NTB_LOAD_KEYS_STATE_BAD_FIELD,
        NTB_LOAD_KEYS_STATE_WAITING_VALUE_START,
        NTB_LOAD_KEYS_STATE_READING_VALUE,
};

enum ntb_load_keys_field {
        NTB_LOAD_KEYS_FIELD_LABEL,
        NTB_LOAD_KEYS_FIELD_ENABLED,
        NTB_LOAD_KEYS_FIELD_DECOY,
        NTB_LOAD_KEYS_FIELD_NONCE_TRIALS_PER_BYTE,
        NTB_LOAD_KEYS_FIELD_PAYLOAD_LENGTH_EXTRA_BYTES,
        NTB_LOAD_KEYS_FIELD_PRIV_SIGNING_KEY,
        NTB_LOAD_KEYS_FIELD_PRIV_ENCRYPTION_KEY,
        NTB_LOAD_KEYS_FIELD_LAST_PUBKEY_SEND_TIME
};

struct ntb_load_keys_data {
        enum ntb_load_keys_state state;
        enum ntb_load_keys_field field;

        struct ntb_pub_key_maker *pub_key_maker;

        ntb_load_keys_func func;
        void *user_data;

        struct ntb_buffer label;
        struct ntb_buffer address;
        struct ntb_buffer tmp_buf;

        int line_num;

        int nonce_trials_per_byte;
        int payload_length_extra_bytes;
        int64_t last_pubkey_send_time;
        bool enabled;
        bool decoy;
        bool has_private_signing_key;
        bool has_private_encryption_key;

        uint8_t private_signing_key[NTB_KEY_PRIVATE_SIZE];
        uint8_t private_encryption_key[NTB_KEY_PRIVATE_SIZE];
};

static void
flush_key(struct ntb_load_keys_data *data)
{
        struct ntb_key *key;
        uint8_t address[RIPEMD160_DIGEST_LENGTH];
        uint8_t header_address[RIPEMD160_DIGEST_LENGTH];
        uint8_t sha_hash[SHA512_DIGEST_LENGTH];
        uint8_t public_signing_key[NTB_KEY_PUBLIC_SIZE + 1];
        uint8_t public_encryption_key[NTB_KEY_PUBLIC_SIZE + 1];
        int version, stream;
        SHA512_CTX sha_ctx;

        if (!data->has_private_signing_key ||
            !data->has_private_encryption_key)
                return;

        ntb_buffer_ensure_size(&data->address, data->address.length + 1);
        data->address.data[data->address.length] = '\0';

        if (!ntb_address_decode((const char *) data->address.data,
                                &version,
                                &stream,
                                header_address)) {
                ntb_log("Address is invalid “%s”",
                        (const char *) data->address.data);
                version = 4;
                stream = 1;
        }

        ntb_buffer_ensure_size(&data->label, data->label.length + 1);
        data->label.data[data->label.length] = '\0';

        ntb_pub_key_maker_make(data->pub_key_maker,
                               data->private_signing_key,
                               public_signing_key);
        ntb_pub_key_maker_make(data->pub_key_maker,
                               data->private_encryption_key,
                               public_encryption_key);

        SHA512_Init(&sha_ctx);
        SHA512_Update(&sha_ctx,
                      public_signing_key,
                      NTB_KEY_PUBLIC_SIZE + 1);
        SHA512_Update(&sha_ctx,
                      public_encryption_key,
                      NTB_KEY_PUBLIC_SIZE + 1);
        SHA512_Final(sha_hash, &sha_ctx);

        RIPEMD160(sha_hash, SHA512_DIGEST_LENGTH, address);

        if (memcmp(address, header_address, RIPEMD160_DIGEST_LENGTH)) {
                ntb_log("Calculated address for %s does not match",
                        (const char *) data->address.data);
        }

        key = ntb_key_new((const char *) data->label.data,
                          address,
                          version,
                          stream,
                          data->private_signing_key,
                          public_signing_key + 1,
                          data->private_encryption_key,
                          public_encryption_key + 1);

        key->nonce_trials_per_byte = data->nonce_trials_per_byte;
        key->payload_length_extra_bytes =
                data->payload_length_extra_bytes;
        key->last_pubkey_send_time = data->last_pubkey_send_time;
        key->enabled = data->enabled;
        key->decoy = data->decoy;

        data->func(key, data->user_data);

        ntb_key_unref(key);
}

static void
reset_data(struct ntb_load_keys_data *data)
{
        data->state = NTB_LOAD_KEYS_STATE_HEADER_START;
        data->label.length = 0;
        data->tmp_buf.length = 0;
        data->address.length = 0;
        data->nonce_trials_per_byte = NTB_PROTO_MIN_NONCE_TRIALS_PER_BYTE;
        data->payload_length_extra_bytes = NTB_PROTO_MIN_EXTRA_BYTES;
        data->last_pubkey_send_time = 0;
        data->enabled = true;
        data->decoy = false;

        data->has_private_signing_key = false;
        data->has_private_encryption_key = false;
}

static bool
parse_bool_value(struct ntb_load_keys_data *data,
                 bool *result)
{
        if (!strcmp((const char *) data->tmp_buf.data, "true")) {
                *result = true;
                return true;
        }

        if (!strcmp((const char *) data->tmp_buf.data, "false")) {
                *result = false;
                return true;
        }

        ntb_log("Invalid boolean value on line %i", data->line_num);

        return false;
}

static bool
parse_int_value(struct ntb_load_keys_data *data,
                int64_t max,
                int64_t *result)
{
        long long int value;
        char *tail;

        errno = 0;

        value = strtoll((const char *) data->tmp_buf.data, &tail, 10);

        if (errno ||
            tail == (const char *) data->tmp_buf.data ||
            *tail ||
            value < 0) {
                ntb_log("Invalid integer value on line %i in keys.dat",
                        data->line_num);
                return false;
        }

        if (value > max) {
                ntb_log("Value too big on line %i in keys.dat",
                        data->line_num);
                return false;
        }

        *result = value;

        return true;
}

static bool
parse_key(struct ntb_load_keys_data *data,
          uint8_t *result)
{
        uint8_t key_buf[1 + NTB_KEY_PRIVATE_SIZE + 4];
        uint8_t hash1[SHA256_DIGEST_LENGTH];
        uint8_t hash2[SHA256_DIGEST_LENGTH];
        ssize_t key_length;

        key_length = ntb_base58_decode((const char *) data->tmp_buf.data,
                                       data->tmp_buf.length,
                                       key_buf,
                                       sizeof key_buf);

        if (key_length == -1) {
                ntb_log("Invalid private key on line %i",
                        data->line_num);
                return false;
        }

        memmove(key_buf + sizeof key_buf - key_length, key_buf, key_length);
        memset(key_buf, 0, sizeof key_buf - key_length);

        if (key_buf[0] != 0x80) {
                ntb_log("Private key on line %i does not have the right prefix",
                        data->line_num);
                return false;
        }

        SHA256(key_buf, NTB_KEY_PRIVATE_SIZE + 1, hash1);
        SHA256(hash1, SHA256_DIGEST_LENGTH, hash2);

        if (memcmp(key_buf + 1 + NTB_KEY_PRIVATE_SIZE, hash2, 4)) {
                ntb_log("Checksum does not match for private key on line %i",
                        data->line_num);
                return false;
        }

        memcpy(result, key_buf + 1, NTB_KEY_PRIVATE_SIZE);

        return true;
}

static void
process_value(struct ntb_load_keys_data *data)
{
        int64_t int_value;
        bool bool_value;

        while (data->tmp_buf.length > 0 &&
               data->tmp_buf.data[data->tmp_buf.length - 1] == ' ')
                data->tmp_buf.length--;

        ntb_buffer_ensure_size(&data->tmp_buf, data->tmp_buf.length + 1);
        data->tmp_buf.data[data->tmp_buf.length] = '\0';

        switch (data->field) {
        case NTB_LOAD_KEYS_FIELD_LABEL:
                ntb_buffer_set_length(&data->label, 0);
                ntb_buffer_append(&data->label,
                                  data->tmp_buf.data,
                                  data->tmp_buf.length);
                return;

        case NTB_LOAD_KEYS_FIELD_ENABLED:
                if (parse_bool_value(data, &bool_value))
                        data->enabled = bool_value;
                return;
        case NTB_LOAD_KEYS_FIELD_DECOY:
                if (parse_bool_value(data, &bool_value))
                        data->decoy = bool_value;
                return;
        case NTB_LOAD_KEYS_FIELD_NONCE_TRIALS_PER_BYTE:
                if (parse_int_value(data, INT_MAX, &int_value))
                        data->nonce_trials_per_byte = int_value;
                return;
        case NTB_LOAD_KEYS_FIELD_PAYLOAD_LENGTH_EXTRA_BYTES:
                if (parse_int_value(data, INT_MAX, &int_value))
                        data->payload_length_extra_bytes = int_value;
                return;
        case NTB_LOAD_KEYS_FIELD_PRIV_SIGNING_KEY:
                if (parse_key(data, data->private_signing_key))
                        data->has_private_signing_key = true;
                return;
        case NTB_LOAD_KEYS_FIELD_PRIV_ENCRYPTION_KEY:
                if (parse_key(data, data->private_encryption_key))
                        data->has_private_encryption_key = true;
                return;
        case NTB_LOAD_KEYS_FIELD_LAST_PUBKEY_SEND_TIME:
                if (parse_int_value(data, INT64_MAX, &int_value))
                        data->last_pubkey_send_time = int_value;
                return;
        }

        ntb_fatal("Invalid field reached");
}

static void
set_state_from_field_name(struct ntb_load_keys_data *data)
{
        const char *field_name;

        ntb_buffer_append_c(&data->tmp_buf, '\0');

        field_name = (const char *) data->tmp_buf.data;

        data->state = NTB_LOAD_KEYS_STATE_WAITING_VALUE_START;

        if (!strcmp(field_name, "label"))
                data->field = NTB_LOAD_KEYS_FIELD_LABEL;
        else if (!strcmp(field_name, "enabled"))
                data->field = NTB_LOAD_KEYS_FIELD_ENABLED;
        else if (!strcmp(field_name, "decoy"))
                data->field = NTB_LOAD_KEYS_FIELD_DECOY;
        else if (!strcmp(field_name, "noncetrialsperbyte"))
                data->field = NTB_LOAD_KEYS_FIELD_NONCE_TRIALS_PER_BYTE;
        else if (!strcmp(field_name, "payloadlengthextrabytes"))
                data->field = NTB_LOAD_KEYS_FIELD_PAYLOAD_LENGTH_EXTRA_BYTES;
        else if (!strcmp(field_name, "privsigningkey"))
                data->field = NTB_LOAD_KEYS_FIELD_PRIV_SIGNING_KEY;
        else if (!strcmp(field_name, "privencryptionkey"))
                data->field = NTB_LOAD_KEYS_FIELD_PRIV_ENCRYPTION_KEY;
        else if (!strcmp(field_name, "lastpubkeysendtime"))
                data->field = NTB_LOAD_KEYS_FIELD_LAST_PUBKEY_SEND_TIME;
        else
                data->state = NTB_LOAD_KEYS_STATE_BAD_FIELD;

        data->tmp_buf.length = 0;
}

static void
handle_byte(struct ntb_load_keys_data *data,
            int ch)
{
        switch (data->state) {
        case NTB_LOAD_KEYS_STATE_HEADER_START:
                if (ch == '[') {
                        data->state = NTB_LOAD_KEYS_STATE_READING_HEADER;
                        data->address.length = 0;
                } else if (ch != ' ' && ch != '\n') {
                        ntb_log("Invalid header on line %i in keys.dat",
                                data->line_num);
                        data->state = NTB_LOAD_KEYS_STATE_BAD_HEADER_START;
                }
                return;
        case NTB_LOAD_KEYS_STATE_BAD_HEADER_START:
                if (ch == '\n')
                        data->state = NTB_LOAD_KEYS_STATE_HEADER_START;
                return;
        case NTB_LOAD_KEYS_STATE_READING_HEADER:
                if (ch == '\n') {
                        ntb_log("Invalid header on line %i in keys.dat",
                                data->line_num);
                        data->state = NTB_LOAD_KEYS_STATE_FIELD_START;
                } else if (ch == ']') {
                        data->state = NTB_LOAD_KEYS_STATE_END_HEADER_LINE;
                } else {
                        ntb_buffer_append_c(&data->address, ch);
                }
                return;
        case NTB_LOAD_KEYS_STATE_END_HEADER_LINE:
                if (ch == '\n') {
                        data->state = NTB_LOAD_KEYS_STATE_FIELD_START;
                } else if (ch != ' ') {
                        ntb_log("Junk after header on line %i in keys.data",
                                data->line_num);
                        data->state = NTB_LOAD_KEYS_STATE_END_HEADER_LINE2;
                }
                return;
        case NTB_LOAD_KEYS_STATE_END_HEADER_LINE2:
                if (ch == '\n')
                        data->state = NTB_LOAD_KEYS_STATE_FIELD_START;
                return;
        case NTB_LOAD_KEYS_STATE_FIELD_START:
                if (ch == '[') {
                        flush_key(data);
                        data->state = NTB_LOAD_KEYS_STATE_READING_HEADER;
                        data->address.length = 0;
                } else if (ch != ' ' && ch != '\n') {
                        ntb_buffer_set_length(&data->tmp_buf, 1);
                        data->tmp_buf.data[0] = ch;
                        data->state = NTB_LOAD_KEYS_STATE_READING_FIELD_NAME;
                }
                return;
        case NTB_LOAD_KEYS_STATE_READING_FIELD_NAME:
                if (ch == ' ') {
                        data->state = NTB_LOAD_KEYS_STATE_WAITING_EQUALS;
                } else if (ch == '=') {
                        set_state_from_field_name(data);
                } else if (ch == '\n') {
                        ntb_log("Invalid line %i in keys.dat",
                                data->line_num);
                        data->state = NTB_LOAD_KEYS_STATE_FIELD_START;
                } else {
                        ntb_buffer_append_c(&data->tmp_buf, ch);
                }
                return;
        case NTB_LOAD_KEYS_STATE_WAITING_EQUALS:
                if (ch == '=') {
                        set_state_from_field_name(data);
                } else if (ch == '\n') {
                        ntb_log("Invalid line %i in keys.dat",
                                data->line_num);
                        data->state = NTB_LOAD_KEYS_STATE_FIELD_START;
                } else if (ch != ' ') {
                        ntb_log("Invalid line %i in keys.dat",
                                data->line_num);
                        data->state = NTB_LOAD_KEYS_STATE_BAD_FIELD;
                }
                return;
        case NTB_LOAD_KEYS_STATE_WAITING_VALUE_START:
                if (ch == '\n') {
                        process_value(data);
                        data->state = NTB_LOAD_KEYS_STATE_FIELD_START;
                } else if (ch != ' ') {
                        ntb_buffer_set_length(&data->tmp_buf, 1);
                        data->tmp_buf.data[0] = ch;
                        data->state = NTB_LOAD_KEYS_STATE_READING_VALUE;
                }
                return;
        case NTB_LOAD_KEYS_STATE_READING_VALUE:
                if (ch == '\n') {
                        process_value(data);
                        data->state = NTB_LOAD_KEYS_STATE_FIELD_START;
                } else {
                        ntb_buffer_append_c(&data->tmp_buf, ch);
                }
                return;
        case NTB_LOAD_KEYS_STATE_BAD_FIELD:
                if (ch == '\n')
                        data->state = NTB_LOAD_KEYS_STATE_FIELD_START;
                return;
        }

        ntb_fatal("Invalid state reached");
}

void
ntb_load_keys(FILE *file,
              ntb_load_keys_func func,
              void *user_data)
{
        struct ntb_load_keys_data data;
        int ch;

        ntb_log("Loading private keys");

        data.line_num = 1;

        data.pub_key_maker = ntb_pub_key_maker_new();

        ntb_buffer_init(&data.label);
        ntb_buffer_init(&data.tmp_buf);
        ntb_buffer_init(&data.address);

        data.func = func;
        data.user_data = user_data;

        reset_data(&data);

        while ((ch = fgetc(file)) != EOF) {
                handle_byte(&data, ch);

                if (ch == '\n')
                        data.line_num++;
        }

        handle_byte(&data, '\n');

        flush_key(&data);

        ntb_buffer_destroy(&data.label);
        ntb_buffer_destroy(&data.tmp_buf);
        ntb_buffer_destroy(&data.address);

        ntb_pub_key_maker_free(data.pub_key_maker);

        ntb_log("Finished loading private keys");
}
