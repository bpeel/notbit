/*
 * Notbit - A Bitmessage client
 * Copyright (C) 2013, 2017  Neil Roberts
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

#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <stdarg.h>
#include <assert.h>

#include "ntb-proto.h"
#include "ntb-util.h"
#include "ntb-ecc.h"

const uint8_t
ntb_proto_magic[4] = { 0xe9, 0xbe, 0xb4, 0xd9 };

void
ntb_proto_double_hash(const void *data,
                      int length,
                      uint8_t *hash)
{
        uint8_t hash1[SHA512_DIGEST_LENGTH];
        uint8_t hash2[SHA512_DIGEST_LENGTH];

        SHA512(data, length, hash1);
        SHA512(hash1, SHA512_DIGEST_LENGTH, hash2);

        memcpy(hash, hash2, NTB_PROTO_HASH_LENGTH);
}

void
ntb_proto_address_hash(const void *data,
                       int length,
                       uint8_t *hash)
{
        uint8_t hash1[SHA512_DIGEST_LENGTH];

        SHA512(data, length, hash1);
        RIPEMD160(hash1, SHA512_DIGEST_LENGTH, hash);
}

bool
ntb_proto_check_command_string(const uint8_t *command_string)
{
        const uint8_t *command_end;
        int i;

        /* The command must end with a zero */
        command_end = memchr(command_string, 0, 12);

        if (command_end == NULL)
                return false;

        /* The rest of the command must be zeroes */
        for (i = command_end - command_string + 1; i < 12; i++)
                if (command_string[i] != '\0')
                        return false;

        return true;
}

uint16_t
ntb_proto_get_16(const uint8_t *p)
{
        uint16_t value;

        memcpy(&value, p, sizeof value);

        return NTB_UINT16_FROM_BE(value);
}

uint32_t
ntb_proto_get_32(const uint8_t *p)
{
        uint32_t value;

        memcpy(&value, p, sizeof value);

        return NTB_UINT32_FROM_BE(value);
}

uint64_t
ntb_proto_get_64(const uint8_t *p)
{
        uint64_t value;

        memcpy(&value, p, sizeof value);

        return NTB_UINT64_FROM_BE(value);
}

bool
ntb_proto_get_var_int(const uint8_t **p_ptr,
                      uint32_t *length_ptr,
                      uint64_t *result)
{
        const uint8_t *p = *p_ptr;
        int length = *length_ptr;

        if (length < 0) {
                return false;
        } else if (*p < 0xfd) {
                if (length < 1)
                        return false;
                *result = p[0];
                *length_ptr -= 1;
                *p_ptr += 1;
                return true;
        } else if (*p == 0xfd) {
                if (length < 3)
                        return false;
                *result = ntb_proto_get_16(p + 1);
                *length_ptr -= 3;
                *p_ptr += 3;
                return true;
        } else if (*p == 0xfe) {
                if (length < 5)
                        return false;
                *result = ntb_proto_get_32(p + 1);
                *length_ptr -= 5;
                *p_ptr += 5;
                return true;
        } else {
                if (length < 9)
                        return false;
                *result = ntb_proto_get_64(p + 1);
                *length_ptr -= 9;
                *p_ptr += 9;
                return true;
        }
}

bool
ntb_proto_get_var_str(const uint8_t **p_ptr,
                      uint32_t *length_ptr,
                      struct ntb_proto_var_str *result)
{
        if (!ntb_proto_get_var_int(p_ptr, length_ptr, &result->length))
                return false;

        if (*length_ptr < result->length)
                return false;

        result->data = (const char *) *p_ptr;
        *length_ptr -= result->length;
        *p_ptr += result->length;

        return true;
}

bool
ntb_proto_get_var_int_list(const uint8_t **p_ptr,
                           uint32_t *length_ptr,
                           struct ntb_proto_var_int_list *result)
{
        uint64_t value;
        uint64_t i;

        if (!ntb_proto_get_var_int(p_ptr, length_ptr, &result->n_ints))
                return false;

        result->values = *p_ptr;

        for (i = 0; i < result->n_ints; i++)
                if (!ntb_proto_get_var_int(p_ptr, length_ptr, &value))
                        return false;

        return true;
}

ssize_t
ntb_proto_get_command_va_list(const uint8_t *data_start,
                              uint32_t length,
                              va_list ap)
{
        const uint8_t *data = data_start;
        enum ntb_proto_argument arg;
        struct ntb_netaddress *netaddress;
        struct ntb_proto_var_str *var_str;
        struct ntb_proto_var_int_list *var_int_list;

        while (true) {
                arg = va_arg(ap, enum ntb_proto_argument);

                switch (arg) {
                case NTB_PROTO_ARGUMENT_8:
                        if (length < sizeof (uint8_t))
                                return -1;
                        *va_arg(ap, uint8_t *) = ntb_proto_get_8(data);
                        data += sizeof (uint8_t);
                        length -= sizeof (uint8_t);
                        break;
                case NTB_PROTO_ARGUMENT_16:
                        if (length < sizeof (uint16_t))
                                return -1;
                        *va_arg(ap, uint16_t *) = ntb_proto_get_16(data);
                        data += sizeof (uint16_t);
                        length -= sizeof (uint16_t);
                        break;
                case NTB_PROTO_ARGUMENT_32:
                        if (length < sizeof (uint32_t))
                                return -1;
                        *va_arg(ap, uint32_t *) = ntb_proto_get_32(data);
                        data += sizeof (uint32_t);
                        length -= sizeof (uint32_t);
                        break;
                case NTB_PROTO_ARGUMENT_64:
                        if (length < sizeof (uint64_t))
                                return -1;
                        *va_arg(ap, uint64_t *) = ntb_proto_get_64(data);
                        data += sizeof (uint64_t);
                        length -= sizeof (uint64_t);
                        break;
                case NTB_PROTO_ARGUMENT_BOOL:
                        if (length < sizeof (uint8_t))
                                return -1;
                        *va_arg(ap, bool *) = !!ntb_proto_get_8(data);
                        data += sizeof (uint8_t);
                        length -= sizeof (uint8_t);
                        break;
                case NTB_PROTO_ARGUMENT_VAR_INT:
                        if (!ntb_proto_get_var_int(&data,
                                                   &length,
                                                   va_arg(ap, uint64_t *)))
                                return -1;
                        break;
                case NTB_PROTO_ARGUMENT_NETADDRESS:
                        if (length < 16 + sizeof (uint16_t))
                                return -1;
                        netaddress = va_arg(ap, struct ntb_netaddress *);
                        memcpy(netaddress->host, data, 16);
                        netaddress->port = ntb_proto_get_16(data + 16);
                        data += sizeof (uint16_t) + 16;
                        length -= sizeof (uint16_t) + 16;
                        break;
                case NTB_PROTO_ARGUMENT_VAR_STR:
                        var_str = va_arg(ap, struct ntb_proto_var_str *);
                        if (!ntb_proto_get_var_str(&data,
                                                   &length,
                                                   var_str))
                                return -1;
                        break;
                case NTB_PROTO_ARGUMENT_VAR_INT_LIST:
                        var_int_list =
                                va_arg(ap, struct ntb_proto_var_int_list *);
                        if (!ntb_proto_get_var_int_list(&data,
                                                        &length,
                                                        var_int_list))
                                return -1;
                        break;
                case NTB_PROTO_ARGUMENT_END:
                        return data - data_start;
                }
        }
}

ssize_t
ntb_proto_get_command(const uint8_t *data,
                      uint32_t length,
                      ...)
{
        ssize_t result;
        va_list ap;

        va_start(ap, length);
        result = ntb_proto_get_command_va_list(data, length, ap);
        va_end(ap);

        return result;
}

bool
ntb_proto_get_decrypted_msg(const uint8_t *data,
                            uint32_t data_length,
                            struct ntb_proto_decrypted_msg *msg)
{
        const uint8_t *data_start = data;
        ssize_t header_size;

        header_size = ntb_proto_get_command(data,
                                            data_length,

                                            NTB_PROTO_ARGUMENT_VAR_INT,
                                            &msg->sender_address_version,

                                            NTB_PROTO_ARGUMENT_VAR_INT,
                                            &msg->sender_stream_number,

                                            NTB_PROTO_ARGUMENT_32,
                                            &msg->sender_behaviors,

                                            NTB_PROTO_ARGUMENT_END);

        if (header_size == -1)
                return false;

        data += header_size;
        data_length -= header_size;

        if (data_length < (NTB_ECC_PUBLIC_KEY_SIZE - 1) * 2)
                return false;

        msg->sender_signing_key = data;
        msg->sender_encryption_key = data + NTB_ECC_PUBLIC_KEY_SIZE - 1;

        data += (NTB_ECC_PUBLIC_KEY_SIZE - 1) * 2;
        data_length -= (NTB_ECC_PUBLIC_KEY_SIZE - 1) * 2;

        if (msg->sender_address_version >= 3) {
                header_size = ntb_proto_get_command(data,
                                                    data_length,

                                                    NTB_PROTO_ARGUMENT_VAR_INT,
                                                    &msg->pow_per_byte,

                                                    NTB_PROTO_ARGUMENT_VAR_INT,
                                                    &msg->pow_extra_bytes,

                                                    NTB_PROTO_ARGUMENT_END);

                if (header_size == -1)
                        return false;

                data += header_size;
                data_length -= header_size;
        } else {
                msg->pow_per_byte = NTB_PROTO_MIN_POW_PER_BYTE;
                msg->pow_extra_bytes = NTB_PROTO_MIN_POW_EXTRA_BYTES;
        }

        if (data_length < RIPEMD160_DIGEST_LENGTH)
                return false;

        msg->destination_ripe = data;

        data += RIPEMD160_DIGEST_LENGTH;
        data_length -= RIPEMD160_DIGEST_LENGTH;

        header_size = ntb_proto_get_command(data,
                                            data_length,

                                            NTB_PROTO_ARGUMENT_VAR_INT,
                                            &msg->encoding,

                                            NTB_PROTO_ARGUMENT_VAR_INT,
                                            &msg->message_length,

                                            NTB_PROTO_ARGUMENT_END);

        if (header_size == -1)
                return false;

        data += header_size;
        data_length -= header_size;

        if (data_length < msg->message_length)
                return false;

        msg->message = data;

        data += msg->message_length;
        data_length -= msg->message_length;

        if (!ntb_proto_get_var_int(&data, &data_length, &msg->ack_length))
                return false;

        if (data_length < msg->ack_length)
                return false;

        msg->ack = data;

        data += msg->ack_length;
        data_length -= msg->ack_length;

        msg->signed_data_length = data - data_start;

        if (!ntb_proto_get_var_int(&data, &data_length, &msg->sig_length))
                return false;

        msg->sig = data;

        if (data_length != msg->sig_length)
                return false;

        return true;
}

static bool
process_v2_pubkey_parts(const uint8_t *data,
                        uint32_t message_length,
                        struct ntb_proto_pubkey *pubkey)
{
        if (message_length < 64 * 2 + 4)
                return false;

        pubkey->behaviours = ntb_proto_get_32(data);
        pubkey->public_signing_key = data + 4;
        pubkey->public_encryption_key = data + 4 + 64;

        pubkey->pow_per_byte = NTB_PROTO_MIN_POW_PER_BYTE;
        pubkey->pow_extra_bytes = NTB_PROTO_MIN_POW_EXTRA_BYTES;

        return true;
}

static bool
process_v3_pubkey_parts(const uint8_t *data,
                        uint32_t message_length,
                        struct ntb_proto_pubkey *pubkey)
{
        ssize_t header_length;

        if (message_length < 4 + 64 * 2)
                return false;

        pubkey->behaviours = ntb_proto_get_32(data);
        pubkey->public_signing_key = data + 4;
        pubkey->public_encryption_key = data + 4 + 64;

        data += 4 + 64 * 2;
        message_length -= 4 + 64 * 2;

        header_length =
                ntb_proto_get_command(data,
                                      message_length,

                                      NTB_PROTO_ARGUMENT_VAR_INT,
                                      &pubkey->pow_per_byte,

                                      NTB_PROTO_ARGUMENT_VAR_INT,
                                      &pubkey->pow_extra_bytes,

                                      NTB_PROTO_ARGUMENT_END);

        if (header_length == -1)
                return false;

        data += header_length;
        message_length -= header_length;

        pubkey->signed_data_length = data - pubkey->signed_data;

        if (!ntb_proto_get_var_int(&data,
                                   &message_length,
                                   &pubkey->signature_length))
                return false;

        if (message_length != pubkey->signature_length)
                return false;

        pubkey->signature = data;

        return true;
}

static bool
process_v4_pubkey_parts(const uint8_t *data,
                        uint32_t message_length,
                        struct ntb_proto_pubkey *pubkey)
{
        if (message_length < 32)
                return false;

        pubkey->tag = data;
        pubkey->encrypted_data = data + 32;
        pubkey->encrypted_data_length = message_length - 32;

        return true;
}

bool
ntb_proto_get_pubkey(bool decrypted,
                     const uint8_t *data_start,
                     uint32_t message_length,
                     struct ntb_proto_pubkey *pubkey)
{
        const uint8_t *data = data_start;
        ssize_t header_length;

        memset(pubkey, 0, sizeof *pubkey);

        header_length = ntb_proto_get_object_header(data,
                                                    message_length,
                                                    &pubkey->header);

        if (header_length == -1 ||
            pubkey->header.type != NTB_PROTO_INV_TYPE_PUBKEY)
                return false;

        data += header_length;
        message_length -= header_length;

        switch (pubkey->header.version) {
        case 2:
                return process_v2_pubkey_parts(data,
                                               message_length,
                                               pubkey);
        case 4:
                if (decrypted) {
                        pubkey->tag = data;
                        data += 32;
                        message_length -= 32;
                } else {
                        return process_v4_pubkey_parts(data,
                                                       message_length,
                                                       pubkey);
                }
                /* flow through */
        case 3:
                pubkey->signed_data = data_start + sizeof (uint64_t);

                return process_v3_pubkey_parts(data,
                                               message_length,
                                               pubkey);

        default:
                return false;
        }
}

ssize_t
ntb_proto_get_object_header(const uint8_t *data,
                            uint32_t length,
                            struct ntb_proto_object_header *header)
{
        return ntb_proto_get_command(data,
                                     length,

                                     NTB_PROTO_ARGUMENT_64,
                                     &header->nonce,

                                     NTB_PROTO_ARGUMENT_64,
                                     &header->expires_time,

                                     NTB_PROTO_ARGUMENT_32,
                                     &header->type,

                                     NTB_PROTO_ARGUMENT_VAR_INT,
                                     &header->version,

                                     NTB_PROTO_ARGUMENT_VAR_INT,
                                     &header->stream,

                                     NTB_PROTO_ARGUMENT_END);
}

void
ntb_proto_add_var_int(struct ntb_buffer *buf,
                      uint64_t value)
{
        if (value < 0xfd) {
                ntb_proto_add_8(buf, value);
        } else if (value <= 0xffff) {
                ntb_proto_add_8(buf, 0xfd);
                ntb_proto_add_16(buf, value);
        } else if (value <= 0xffffffff) {
                ntb_proto_add_8(buf, 0xfe);
                ntb_proto_add_32(buf, value);
        } else {
                ntb_proto_add_8(buf, 0xff);
                ntb_proto_add_64(buf, value);
        }
}

void
ntb_proto_add_netaddress(struct ntb_buffer *buf,
                         const struct ntb_netaddress *address)
{
        ntb_buffer_append(buf, address->host, sizeof address->host);
        ntb_proto_add_16(buf, address->port);
}

void
ntb_proto_add_var_str(struct ntb_buffer *buf,
                      const char *str)
{
        uint8_t len = strlen(str);
        ntb_buffer_append(buf, &len, 1);
        ntb_buffer_append(buf, (const uint8_t *) str, len);
}

void
ntb_proto_add_public_key(struct ntb_buffer *buf,
                         const EC_KEY *key)
{
        size_t oct_size;

        ntb_buffer_ensure_size(buf, buf->length + NTB_ECC_PUBLIC_KEY_SIZE);

        oct_size = EC_POINT_point2oct(EC_KEY_get0_group(key),
                                      EC_KEY_get0_public_key(key),
                                      POINT_CONVERSION_UNCOMPRESSED,
                                      buf->data + buf->length,
                                      NTB_ECC_PUBLIC_KEY_SIZE,
                                      NULL);
        assert(oct_size == NTB_ECC_PUBLIC_KEY_SIZE);

        /* Remove the 0x04 prefix */
        memmove(buf->data + buf->length,
                buf->data + buf->length + 1,
                NTB_ECC_PUBLIC_KEY_SIZE - 1);

        buf->length += NTB_ECC_PUBLIC_KEY_SIZE - 1;
}

void
ntb_proto_begin_command(struct ntb_buffer *buf,
                        const char *command)
{
        int command_length;
        uint8_t *header;

        ntb_buffer_ensure_size(buf,
                               buf->length +
                               NTB_PROTO_HEADER_SIZE);
        header = buf->data + buf->length;

        memcpy(header, ntb_proto_magic, sizeof ntb_proto_magic);
        command_length = strlen(command);
        memcpy(header + 4, command, command_length);
        memset(header + 4 + command_length, 0, 12 - command_length);

        buf->length += NTB_PROTO_HEADER_SIZE;
}

void
ntb_proto_end_command(struct ntb_buffer *buf,
                      size_t command_start)
{
        uint32_t payload_length, payload_length_be;
        uint8_t hash[SHA512_DIGEST_LENGTH];
        uint8_t *header;

        header = buf->data + command_start;
        payload_length = buf->length - command_start - NTB_PROTO_HEADER_SIZE;
        payload_length_be = NTB_UINT32_TO_BE(payload_length);

        memcpy(header + 16, &payload_length_be, sizeof payload_length_be);

        SHA512(header + NTB_PROTO_HEADER_SIZE, payload_length, hash);
        memcpy(header + 20, hash, 4);
}

void
ntb_proto_add_command_va_list(struct ntb_buffer *buf,
                              const char *command,
                              va_list ap)
{
        size_t command_start;
        enum ntb_proto_argument arg;
        const struct ntb_netaddress *netaddress;

        command_start = buf->length;

        ntb_proto_begin_command(buf, command);

        while (true) {
                arg = va_arg(ap, enum ntb_proto_argument);

                switch (arg) {
                case NTB_PROTO_ARGUMENT_8:
                        ntb_proto_add_8(buf, va_arg(ap, int));
                        break;
                case NTB_PROTO_ARGUMENT_16:
                        ntb_proto_add_16(buf, va_arg(ap, int));
                        break;
                case NTB_PROTO_ARGUMENT_32:
                        ntb_proto_add_32(buf, va_arg(ap, uint32_t));
                        break;
                case NTB_PROTO_ARGUMENT_64:
                        ntb_proto_add_64(buf, va_arg(ap, uint64_t));
                        break;
                case NTB_PROTO_ARGUMENT_BOOL:
                        ntb_proto_add_bool(buf, va_arg(ap, int));
                        break;
                case NTB_PROTO_ARGUMENT_VAR_INT:
                        ntb_proto_add_var_int(buf, va_arg(ap, uint64_t));
                        break;
                case NTB_PROTO_ARGUMENT_NETADDRESS:
                        netaddress = va_arg(ap, const struct ntb_netaddress *);
                        ntb_proto_add_netaddress(buf, netaddress);
                        break;
                case NTB_PROTO_ARGUMENT_VAR_STR:
                        ntb_proto_add_var_str(buf, va_arg(ap, const char *));
                        break;
                case NTB_PROTO_ARGUMENT_VAR_INT_LIST:
                        assert(false);
                        break;
                case NTB_PROTO_ARGUMENT_END:
                        goto done;
                }
        }

done:
        ntb_proto_end_command(buf, command_start);
}

void
ntb_proto_add_command(struct ntb_buffer *buf,
                      const char *command,
                      ...)
{
        va_list ap;

        va_start(ap, command);
        ntb_proto_add_command_va_list(buf, command, ap);
        va_end(ap);
}
