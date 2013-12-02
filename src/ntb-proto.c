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

#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <stdarg.h>
#include <assert.h>

#include "ntb-proto.h"
#include "ntb-util.h"

static const uint8_t
ntb_proto_magic[] = { 0xe9, 0xbe, 0xb4, 0xd9 };

void
ntb_proto_double_hash(const void *data,
                      int length,
                      uint8_t *hash)
{
        uint8_t hash1[SHA512_DIGEST_LENGTH];

        SHA512(data, length, hash1);
        SHA512(hash1, SHA512_DIGEST_LENGTH, hash);
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

bool
ntb_proto_get_message_va_list(const uint8_t *data,
                              uint32_t length,
                              va_list ap)
{
        enum ntb_proto_argument arg;
        struct ntb_netaddress *netaddress;
        struct ntb_proto_var_str *var_str;
        struct ntb_proto_var_int_list *var_int_list;

        while (true) {
                arg = va_arg(ap, enum ntb_proto_argument);

                switch (arg) {
                case NTB_PROTO_ARGUMENT_8:
                        if (length < sizeof (uint8_t))
                                return false;
                        *va_arg(ap, uint8_t *) = ntb_proto_get_8(data);
                        data += sizeof (uint8_t);
                        length -= sizeof (uint8_t);
                        break;
                case NTB_PROTO_ARGUMENT_16:
                        if (length < sizeof (uint16_t))
                                return false;
                        *va_arg(ap, uint16_t *) = ntb_proto_get_16(data);
                        data += sizeof (uint16_t);
                        length -= sizeof (uint16_t);
                        break;
                case NTB_PROTO_ARGUMENT_32:
                        if (length < sizeof (uint32_t))
                                return false;
                        *va_arg(ap, uint32_t *) = ntb_proto_get_32(data);
                        data += sizeof (uint32_t);
                        length -= sizeof (uint32_t);
                        break;
                case NTB_PROTO_ARGUMENT_64:
                        if (length < sizeof (uint64_t))
                                return false;
                        *va_arg(ap, uint64_t *) = ntb_proto_get_64(data);
                        data += sizeof (uint64_t);
                        length -= sizeof (uint64_t);
                        break;
                case NTB_PROTO_ARGUMENT_BOOL:
                        if (length < sizeof (uint8_t))
                                return false;
                        *va_arg(ap, bool *) = !!ntb_proto_get_8(data);
                        data += sizeof (uint8_t);
                        length -= sizeof (uint8_t);
                        break;
                case NTB_PROTO_ARGUMENT_VAR_INT:
                        if (!ntb_proto_get_var_int(&data,
                                                   &length,
                                                   va_arg(ap, uint64_t *)))
                                return false;
                        break;
                case NTB_PROTO_ARGUMENT_TIMESTAMP:
                        if (length < sizeof (uint64_t))
                                return false;
                        *va_arg(ap, int64_t *) = ntb_proto_get_64(data);
                        data += sizeof (uint64_t);
                        length -= sizeof (uint64_t);
                        break;
                case NTB_PROTO_ARGUMENT_NETADDRESS:
                        if (length < 16 + sizeof (uint16_t))
                                return false;
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
                                return false;
                        break;
                case NTB_PROTO_ARGUMENT_VAR_INT_LIST:
                        var_int_list =
                                va_arg(ap, struct ntb_proto_var_int_list *);
                        if (!ntb_proto_get_var_int_list(&data,
                                                        &length,
                                                        var_int_list))
                                return false;
                        break;
                case NTB_PROTO_ARGUMENT_END:
                        return true;
                }
        }
}

bool
ntb_proto_get_message(const uint8_t *data,
                      uint32_t length,
                      ...)
{
        bool result;
        va_list ap;

        va_start(ap, length);
        result = ntb_proto_get_message_va_list(data, length, ap);
        va_end(ap);

        return result;
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
ntb_proto_add_timestamp(struct ntb_buffer *buf)
{
        time_t now;

        time(&now);
        ntb_proto_add_64(buf, (uint64_t) now);
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
ntb_proto_add_command_va_list(struct ntb_buffer *buf,
                              const char *command,
                              va_list ap)
{
        enum ntb_proto_argument arg;
        const struct ntb_netaddress *netaddress;
        int command_length;
        int payload_start;
        uint32_t payload_length, payload_length_be;
        uint8_t hash[SHA512_DIGEST_LENGTH];
        uint8_t *header;

        ntb_buffer_ensure_size(buf,
                               buf->length +
                               NTB_PROTO_HEADER_SIZE);
        payload_start = buf->length + NTB_PROTO_HEADER_SIZE;
        header = buf->data;

        memcpy(header, ntb_proto_magic, sizeof ntb_proto_magic);
        command_length = strlen(command);
        memcpy(header + 4, command, command_length);
        memset(header + 4 + command_length, 0, 12 - command_length);

        buf->length = payload_start;

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
                case NTB_PROTO_ARGUMENT_TIMESTAMP:
                        ntb_proto_add_timestamp(buf);
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
        header = buf->data + payload_start - NTB_PROTO_HEADER_SIZE;
        payload_length = buf->length - payload_start;
        payload_length_be = NTB_UINT32_TO_BE(payload_length);

        memcpy(header + 16, &payload_length_be, sizeof payload_length_be);

        SHA512(buf->data + payload_start, payload_length, hash);
        memcpy(header + 20, hash, 4);
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
