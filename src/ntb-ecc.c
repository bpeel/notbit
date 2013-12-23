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
#include <openssl/rand.h>
#include <openssl/ecdh.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <assert.h>
#include <stdint.h>

#include "ntb-ecc.h"
#include "ntb-proto.h"

struct ntb_ecc {
        BN_CTX *bn_ctx;
        BIGNUM bn, bn2;
        EC_GROUP *group;
        EC_POINT *pub_key_point;
};

static void
make_pub_key_in_point(struct ntb_ecc *ecc,
                      const uint8_t *private_key,
                      EC_POINT *point)
{
        BIGNUM *bn_result;
        int result;

        bn_result = BN_bin2bn(private_key,
                              NTB_ECC_PRIVATE_KEY_SIZE,
                              &ecc->bn);
        assert(bn_result);

        result = EC_POINT_mul(ecc->group,
                              point,
                              &ecc->bn,
                              NULL,
                              NULL,
                              ecc->bn_ctx);
        assert(result);
}

EC_POINT *
ntb_ecc_make_pub_key_point(struct ntb_ecc *ecc,
                           const uint8_t *private_key)
{
        EC_POINT *point;

        point = EC_POINT_new(ecc->group);
        assert(point);

        make_pub_key_in_point(ecc, private_key, point);

        return point;
}

void
ntb_ecc_make_pub_key_bin(struct ntb_ecc *ecc,
                         const uint8_t *private_key,
                         uint8_t *public_key)
{
        size_t oct_size;

        make_pub_key_in_point(ecc, private_key, ecc->pub_key_point);

        oct_size = EC_POINT_point2oct(ecc->group,
                                      ecc->pub_key_point,
                                      POINT_CONVERSION_UNCOMPRESSED,
                                      public_key,
                                      NTB_ECC_PUBLIC_KEY_SIZE,
                                      ecc->bn_ctx);
        assert(oct_size == NTB_ECC_PUBLIC_KEY_SIZE);
}

struct ntb_ecc *
ntb_ecc_new(void)
{
        struct ntb_ecc *ecc = ntb_alloc(sizeof *ecc);

        BN_init(&ecc->bn);
        BN_init(&ecc->bn2);

        ecc->bn_ctx = BN_CTX_new();

        if (ecc->bn_ctx == NULL)
                ntb_fatal("Error creating BN_CTX");

        ecc->group = EC_GROUP_new_by_curve_name(NID_secp256k1);

        if (ecc->group == NULL)
                ntb_fatal("Error creating EC_GROUP");

        ecc->pub_key_point = EC_POINT_new(ecc->group);

        return ecc;
}

void
ntb_ecc_free(struct ntb_ecc *ecc)
{
        BN_free(&ecc->bn2);
        BN_free(&ecc->bn);
        BN_CTX_free(ecc->bn_ctx);
        EC_POINT_free(ecc->pub_key_point);
        EC_GROUP_free(ecc->group);

        ntb_free(ecc);
}

static EC_KEY *
create_key(struct ntb_ecc *ecc,
           const uint8_t *private_key)
{
        EC_KEY *key;
        BIGNUM *bn_ret;
        int int_ret;

        key = EC_KEY_new();
        assert(key);

        EC_KEY_set_group(key, ecc->group);

        bn_ret = BN_bin2bn(private_key, NTB_ECC_PRIVATE_KEY_SIZE, &ecc->bn);
        assert(bn_ret);

        int_ret = EC_KEY_set_private_key(key, &ecc->bn);
        assert(int_ret);

        int_ret = EC_KEY_set_public_key(key, ecc->pub_key_point);
        assert(int_ret);

        return key;
}

EC_KEY *
ntb_ecc_create_key_with_public(struct ntb_ecc *ecc,
                               const uint8_t *private_key,
                               const uint8_t *public_key)
{
        int int_ret;

        int_ret = EC_POINT_oct2point(ecc->group,
                                     ecc->pub_key_point,
                                     public_key,
                                     NTB_ECC_PUBLIC_KEY_SIZE,
                                     NULL /* bignum context */);
        assert(int_ret);

        return create_key(ecc, private_key);
}

EC_KEY *
ntb_ecc_create_random_key(struct ntb_ecc *ecc)
{
        uint8_t private_key[NTB_ECC_PRIVATE_KEY_SIZE];
        int result;

        result = RAND_bytes(private_key, NTB_ECC_PRIVATE_KEY_SIZE);
        assert(result);

        return ntb_ecc_create_key(ecc, private_key);
}

EC_KEY *
ntb_ecc_create_key(struct ntb_ecc *ecc,
                   const uint8_t *private_key)
{
        EC_KEY *key;

        make_pub_key_in_point(ecc, private_key, ecc->pub_key_point);

        key = create_key(ecc, private_key);

        EC_KEY_set_public_key(key, ecc->pub_key_point);

        return key;
}

void
ntb_ecc_get_pub_key(struct ntb_ecc *ecc,
                    EC_KEY *key,
                    uint8_t *public_key)
{
        int oct_size;

        oct_size = EC_POINT_point2oct(ecc->group,
                                      EC_KEY_get0_public_key(key),
                                      POINT_CONVERSION_UNCOMPRESSED,
                                      public_key,
                                      NTB_ECC_PUBLIC_KEY_SIZE,
                                      ecc->bn_ctx);
        assert(oct_size == NTB_ECC_PUBLIC_KEY_SIZE);
}

static void *
kdf_sha512(const void *data,
           size_t data_length,
           void *hash,
           size_t *hash_length)
{
        if (*hash_length < SHA512_DIGEST_LENGTH)
                return NULL;

        *hash_length = SHA512_DIGEST_LENGTH;

        return SHA512(data, data_length, hash);
}

static void
encode_bignumber(struct ntb_ecc *ecc,
                 BIGNUM *bn,
                 struct ntb_buffer *data_out)
{
        int num_bytes = BN_num_bytes(bn);

        /* Encodes the binary representation of bn prefixed with its
         * length */

        ntb_proto_add_16(data_out, num_bytes);

        ntb_buffer_ensure_size(data_out, data_out->length + num_bytes);
        BN_bn2bin(bn, data_out->data + data_out->length);
        data_out->length += num_bytes;
}

static void
encode_pubkey(struct ntb_ecc *ecc,
              const EC_POINT *public_key,
              struct ntb_buffer *data_out)
{
        int int_result;

        /* Extract the x and y coordinates from the point */
        int_result = EC_POINT_get_affine_coordinates_GFp(ecc->group,
                                                         public_key,
                                                         &ecc->bn,
                                                         &ecc->bn2,
                                                         ecc->bn_ctx);
        assert(int_result);

        /* Add the curve type */
        ntb_proto_add_16(data_out, EC_GROUP_get_curve_name(ecc->group));

        /* Add the point coordinates */
        encode_bignumber(ecc, &ecc->bn, data_out);
        encode_bignumber(ecc, &ecc->bn2, data_out);
}

void
ntb_ecc_encrypt_with_point(struct ntb_ecc *ecc,
                           const EC_POINT *public_key,
                           const uint8_t *data_in,
                           size_t data_in_length,
                           struct ntb_buffer *data_out)
{
        uint8_t ecdh_keybuffer[SHA512_DIGEST_LENGTH];
        EC_KEY *ephemeral_key;
        int ecdh_keylen;
        const EVP_CIPHER *cipher = EVP_aes_256_cbc();
        EVP_CIPHER_CTX cipher_ctx;
        int int_result;
        void *pointer_result;
        int iv_length;
        int out_length;
        size_t iv_offset, ciphertext_offset;
        unsigned int hmac_len;

        assert(EVP_CIPHER_key_length(cipher) == sizeof ecdh_keybuffer / 2);

        ephemeral_key = ntb_ecc_create_random_key(ecc);

        ECDH_set_method(ephemeral_key, ECDH_OpenSSL());
        ecdh_keylen = ECDH_compute_key(ecdh_keybuffer,
                                       sizeof ecdh_keybuffer,
                                       public_key,
                                       ephemeral_key,
                                       kdf_sha512);
        assert(ecdh_keylen == sizeof ecdh_keybuffer);

        /* Add the initialisation vector to data_out */
        iv_offset = data_out->length;
        iv_length = EVP_CIPHER_iv_length(cipher);
        ntb_buffer_set_length(data_out, iv_offset + iv_length);
        int_result = RAND_bytes(data_out->data + iv_offset, iv_length);
        assert(int_result);

        /* Add the ephemeral key to data_out */
        encode_pubkey(ecc, EC_KEY_get0_public_key(ephemeral_key), data_out);

        EC_KEY_free(ephemeral_key);

        /* Add the ciphertext to data_out */
        ciphertext_offset = data_out->length;
        EVP_CIPHER_CTX_init(&cipher_ctx);

        /* The first half of the ecdh key is used for encryption */
        int_result = EVP_EncryptInit_ex(&cipher_ctx,
                                        cipher,
                                        NULL, /* default implementation */
                                        ecdh_keybuffer,
                                        data_out->data + iv_offset);
        assert(int_result);

        out_length = data_in_length + EVP_CIPHER_block_size(cipher);
        ntb_buffer_ensure_size(data_out,
                               data_out->length + out_length);

        int_result = EVP_EncryptUpdate(&cipher_ctx,
                                       data_out->data + data_out->length,
                                       &out_length,
                                       data_in,
                                       data_in_length);
        assert(int_result);

        data_out->length += out_length;

        out_length = EVP_CIPHER_block_size(cipher);
        ntb_buffer_ensure_size(data_out,
                               data_out->length + out_length);

        int_result = EVP_EncryptFinal_ex(&cipher_ctx,
                                         data_out->data + data_out->length,
                                         &out_length);
        assert(int_result);

        data_out->length += out_length;

        EVP_CIPHER_CTX_cleanup(&cipher_ctx);

        /* Add the HMAC to data_out */
        ntb_buffer_ensure_size(data_out,
                               data_out->length + SHA256_DIGEST_LENGTH);
        /* The second half of the ecdh key is used for the HMAC */
        hmac_len = data_out->size - data_out->length;
        pointer_result = HMAC(EVP_sha256(),
                              ecdh_keybuffer + sizeof ecdh_keybuffer / 2,
                              sizeof ecdh_keybuffer / 2,
                              data_out->data + ciphertext_offset,
                              data_out->length - ciphertext_offset,
                              data_out->data + data_out->length,
                              &hmac_len);
        assert(pointer_result);
        assert(hmac_len == SHA256_DIGEST_LENGTH);

        data_out->length += SHA256_DIGEST_LENGTH;
}

static bool
decode_big_number(struct ntb_ecc *ecc,
                  const uint8_t **data_in,
                  size_t *data_in_length,
                  BIGNUM *bn)
{
        uint16_t num_bytes;

        if (*data_in_length < sizeof (uint16_t))
                return false;

        num_bytes = ntb_proto_get_16(*data_in);

        bn = BN_bin2bn(*data_in + sizeof (uint16_t), num_bytes, bn);
        assert(bn);

        *data_in += sizeof (uint16_t) + num_bytes;
        *data_in_length -= sizeof (uint16_t) + num_bytes;

        return true;
}

static bool
decode_pub_key(struct ntb_ecc *ecc,
               const uint8_t **data_in,
               size_t *data_in_length,
               EC_POINT *public_key)
{
        int int_result;

        if (*data_in_length < sizeof (uint16_t) * 3)
                return false;

        /* Check the curve type matches the one we're using */
        if (ntb_proto_get_16(*data_in) != EC_GROUP_get_curve_name(ecc->group))
                return false;

        *data_in += sizeof (uint16_t);
        *data_in_length -= sizeof (uint16_t);

        if (!decode_big_number(ecc, data_in, data_in_length, &ecc->bn) ||
            !decode_big_number(ecc, data_in, data_in_length, &ecc->bn2))
                return false;

        int_result = EC_POINT_set_affine_coordinates_GFp(ecc->group,
                                                         public_key,
                                                         &ecc->bn,
                                                         &ecc->bn2,
                                                         ecc->bn_ctx);
        assert(int_result);

        return true;
}

bool
ntb_ecc_decrypt(struct ntb_ecc *ecc,
                EC_KEY *key,
                const uint8_t *data_in,
                size_t data_in_length,
                struct ntb_buffer *data_out)
{
        uint8_t ecdh_keybuffer[SHA512_DIGEST_LENGTH];
        uint8_t hmac_buf[SHA256_DIGEST_LENGTH];
        int ecdh_keylen;
        const uint8_t *mac, *iv;
        const EVP_CIPHER *cipher = EVP_aes_256_cbc();
        EVP_CIPHER_CTX cipher_ctx;
        int int_result;
        void *pointer_result;
        int iv_length;
        int out_length;
        unsigned int hmac_len;
        bool result = true;

        assert(EVP_CIPHER_key_length(cipher) == sizeof ecdh_keybuffer / 2);

        iv_length = EVP_CIPHER_iv_length(cipher);
        if (data_in_length < iv_length)
                return false;
        iv = data_in;
        data_in += iv_length;
        data_in_length -= iv_length;

        if (!decode_pub_key(ecc, &data_in, &data_in_length, ecc->pub_key_point))
                return false;

        ecdh_keylen = ECDH_compute_key(ecdh_keybuffer,
                                       sizeof ecdh_keybuffer,
                                       ecc->pub_key_point,
                                       key,
                                       kdf_sha512);
        assert(ecdh_keylen == sizeof ecdh_keybuffer);

        if (data_in_length < SHA256_DIGEST_LENGTH)
                return false;

        mac = data_in + data_in_length - SHA256_DIGEST_LENGTH;
        data_in_length -= SHA256_DIGEST_LENGTH;

        /* The second half of the ecdh key is used for the HMAC */
        hmac_len = sizeof hmac_buf;
        pointer_result = HMAC(EVP_sha256(),
                              ecdh_keybuffer + sizeof ecdh_keybuffer / 2,
                              sizeof ecdh_keybuffer / 2,
                              data_in,
                              data_in_length,
                              hmac_buf,
                              &hmac_len);
        assert(pointer_result);
        assert(hmac_len == sizeof hmac_buf);

        if (memcmp(hmac_buf, mac, sizeof hmac_buf))
                return false;

        EVP_CIPHER_CTX_init(&cipher_ctx);

        /* The first half of the ecdh key is used for encryption */
        int_result = EVP_DecryptInit_ex(&cipher_ctx,
                                        cipher,
                                        NULL, /* default implementation */
                                        ecdh_keybuffer,
                                        iv);
        assert(int_result);

        out_length = data_in_length + EVP_CIPHER_block_size(cipher);
        ntb_buffer_ensure_size(data_out,
                               data_out->length + out_length);

        int_result = EVP_DecryptUpdate(&cipher_ctx,
                                       data_out->data + data_out->length,
                                       &out_length,
                                       data_in,
                                       data_in_length);
        if (!int_result) {
                result = false;
        } else {
                data_out->length += out_length;

                out_length = EVP_CIPHER_block_size(cipher);
                ntb_buffer_ensure_size(data_out,
                                       data_out->length + out_length);

                int_result =
                        EVP_DecryptFinal_ex(&cipher_ctx,
                                            data_out->data + data_out->length,
                                            &out_length);
                if (!int_result)
                        result = false;
                else
                        data_out->length += out_length;
        }

        EVP_CIPHER_CTX_cleanup(&cipher_ctx);

        return result;
}
