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

#include <stdbool.h>
#include <string.h>
#include <openssl/ripemd.h>
#include <openssl/sha.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <assert.h>
#include <stdint.h>

#include "ntb-pub-key-maker.h"
#include "ntb-key.h"

struct ntb_pub_key_maker {
        BN_CTX *bn_ctx;
        BIGNUM bn;
        EC_GROUP *group;
        EC_POINT *pub_key_point;
};

void
ntb_pub_key_maker_make(struct ntb_pub_key_maker *maker,
                       const uint8_t *private_key,
                       uint8_t *public_key)
{
        BIGNUM *bn_result;
        int result;
        size_t oct_size;

        bn_result = BN_bin2bn(private_key,
                              NTB_KEY_PRIVATE_SIZE,
                              &maker->bn);
        assert(bn_result);

        result = EC_POINT_mul(maker->group,
                              maker->pub_key_point,
                              &maker->bn,
                              NULL,
                              NULL,
                              maker->bn_ctx);
        assert(result);

        oct_size = EC_POINT_point2oct(maker->group,
                                      maker->pub_key_point,
                                      POINT_CONVERSION_UNCOMPRESSED,
                                      public_key,
                                      NTB_KEY_PUBLIC_SIZE + 1, /* len */
                                      maker->bn_ctx);
        assert(oct_size == NTB_KEY_PUBLIC_SIZE + 1);
}

struct ntb_pub_key_maker *
ntb_pub_key_maker_new(void)
{
        struct ntb_pub_key_maker *maker = ntb_alloc(sizeof *maker);

        BN_init(&maker->bn);

        maker->bn_ctx = BN_CTX_new();

        if (maker->bn_ctx == NULL)
                ntb_fatal("Error creating BN_CTX");

        maker->group = EC_GROUP_new_by_curve_name(NID_secp256k1);

        if (maker->group == NULL)
                ntb_fatal("Error creating EC_GROUP");

        maker->pub_key_point = EC_POINT_new(maker->group);

        return maker;
}

void
ntb_pub_key_maker_free(struct ntb_pub_key_maker *maker)
{
        BN_free(&maker->bn);
        BN_CTX_free(maker->bn_ctx);
        EC_POINT_free(maker->pub_key_point);
        EC_GROUP_free(maker->group);

        ntb_free(maker);
}
