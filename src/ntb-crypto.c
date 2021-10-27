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

#include <stdbool.h>
#include <string.h>
#include <openssl/ripemd.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <assert.h>

#include "ntb-crypto.h"
#include "ntb-util.h"
#include "ntb-slice.h"
#include "ntb-list.h"
#include "ntb-main-context.h"
#include "ntb-log.h"
#include "ntb-address.h"
#include "ntb-ecc.h"
#include "ntb-proto.h"
#include "ntb-pow.h"

struct ntb_crypto {
        pthread_mutex_t mutex;
        pthread_cond_t cond;
        pthread_t thread;
        bool quit;

        struct ntb_slice_allocator cookie_allocator;

        struct ntb_list queue;

        struct ntb_ecc *ecc;
};

enum ntb_crypto_cookie_type {
        NTB_CRYPTO_COOKIE_CREATE_KEY,
        NTB_CRYPTO_COOKIE_CREATE_PUBKEY_BLOB,
        NTB_CRYPTO_COOKIE_CHECK_PUBKEY,
        NTB_CRYPTO_COOKIE_CREATE_MSG_BLOB,
        NTB_CRYPTO_COOKIE_CREATE_PUBLIC_KEY,
        NTB_CRYPTO_COOKIE_DECRYPT_MSG,
        NTB_CRYPTO_COOKIE_GENERATE_ACKDATA
};

struct ntb_crypto_cookie {
        int ref_count;

        enum ntb_crypto_cookie_type type;

        void *func;
        void *user_data;

        struct ntb_list link;

        struct ntb_main_context_source *idle_source;

        struct ntb_crypto *crypto;

        bool in_queue;
        bool cancelled;

        union {
                struct {
                        struct ntb_key *key;
                        struct ntb_key_params params;
                        int leading_zeroes;
                } create_key;

                struct {
                        struct ntb_key *key;
                        struct ntb_blob *blob;
                } create_pubkey_blob;

                struct {
                        struct ntb_address address;
                        struct ntb_blob *blob;
                        struct ntb_key *key;
                } check_pubkey;

                struct {
                        struct ntb_key *from_key;
                        struct ntb_key *to_key;
                        struct ntb_blob *content;
                        struct ntb_blob *result;
                        int64_t timestamp;
                } create_msg_blob;

                struct {
                        struct ntb_key_params params;
                        uint8_t signing_key[NTB_ECC_PUBLIC_KEY_SIZE];
                        uint8_t encryption_key[NTB_ECC_PUBLIC_KEY_SIZE];
                        struct ntb_key *key;
                } create_public_key;

                struct {
                        struct ntb_blob *blob;
                        struct ntb_key **keys;
                        struct ntb_key *chosen_key;
                        struct ntb_blob *result;
                        int n_keys;
                } decrypt_msg;

                struct {
                        uint8_t ackdata[NTB_PROTO_ACKDATA_SIZE];
                } generate_ackdata;
        };
};

static struct ntb_crypto_cookie *
new_cookie(struct ntb_crypto *crypto,
           enum ntb_crypto_cookie_type type,
           void *func,
           void *user_data)
{
        struct ntb_crypto_cookie *cookie;

        /* This should only be called with the lock */

        cookie = ntb_slice_alloc(&crypto->cookie_allocator);
        /* One ref for the caller and one ref for being in the queue */
        cookie->ref_count = 2;
        cookie->type = type;
        cookie->cancelled = false;
        cookie->func = func;
        cookie->user_data = user_data;
        cookie->idle_source = NULL;
        cookie->crypto = crypto;
        cookie->in_queue = true;

        ntb_list_insert(crypto->queue.prev, &cookie->link);
        pthread_cond_signal(&crypto->cond);

        return cookie;
}

static void
free_create_key_cookie(struct ntb_crypto_cookie *cookie)
{
        if (cookie->create_key.key)
                ntb_key_unref(cookie->create_key.key);
        if ((cookie->create_key.params.flags & NTB_KEY_PARAM_LABEL))
                ntb_free((char *) cookie->create_key.params.label);
}

static void
free_create_pubkey_blob_cookie(struct ntb_crypto_cookie *cookie)
{
        if (cookie->create_pubkey_blob.key)
                ntb_key_unref(cookie->create_pubkey_blob.key);
        if (cookie->create_pubkey_blob.blob)
                ntb_blob_unref(cookie->create_pubkey_blob.blob);
}

static void
free_check_pubkey_cookie(struct ntb_crypto_cookie *cookie)
{
        if (cookie->check_pubkey.key)
                ntb_key_unref(cookie->check_pubkey.key);
        if (cookie->check_pubkey.blob)
                ntb_blob_unref(cookie->check_pubkey.blob);
}

static void
free_create_msg_blob_cookie(struct ntb_crypto_cookie *cookie)
{
        if (cookie->create_msg_blob.from_key)
                ntb_key_unref(cookie->create_msg_blob.from_key);
        if (cookie->create_msg_blob.to_key)
                ntb_key_unref(cookie->create_msg_blob.to_key);
        if (cookie->create_msg_blob.content)
                ntb_blob_unref(cookie->create_msg_blob.content);
        if (cookie->create_msg_blob.result)
                ntb_blob_unref(cookie->create_msg_blob.result);
}

static void
free_create_public_key_cookie(struct ntb_crypto_cookie *cookie)
{
        if (cookie->create_public_key.key)
                ntb_key_unref(cookie->create_public_key.key);
        if ((cookie->create_public_key.params.flags & NTB_KEY_PARAM_LABEL))
                ntb_free((char *) cookie->create_public_key.params.label);
}

static void
free_decrypt_msg_cookie(struct ntb_crypto_cookie *cookie)
{
        int i;

        for (i = 0; i < cookie->decrypt_msg.n_keys; i++)
                ntb_key_unref(cookie->decrypt_msg.keys[i]);
        ntb_free(cookie->decrypt_msg.keys);

        if (cookie->decrypt_msg.result)
                ntb_blob_unref(cookie->decrypt_msg.result);

        if (cookie->decrypt_msg.chosen_key)
                ntb_key_unref(cookie->decrypt_msg.chosen_key);

        ntb_blob_unref(cookie->decrypt_msg.blob);
}

static void
free_generate_ackdata_cookie(struct ntb_crypto_cookie *cookie)
{
}

static void
unref_cookie(struct ntb_crypto_cookie *cookie)
{
        /* This should only be called with the lock */

        if (--cookie->ref_count <= 0) {
                switch (cookie->type) {
                case NTB_CRYPTO_COOKIE_CREATE_KEY:
                        free_create_key_cookie(cookie);
                        break;
                case NTB_CRYPTO_COOKIE_CREATE_PUBKEY_BLOB:
                        free_create_pubkey_blob_cookie(cookie);
                        break;
                case NTB_CRYPTO_COOKIE_CHECK_PUBKEY:
                        free_check_pubkey_cookie(cookie);
                        break;
                case NTB_CRYPTO_COOKIE_CREATE_MSG_BLOB:
                        free_create_msg_blob_cookie(cookie);
                        break;
                case NTB_CRYPTO_COOKIE_CREATE_PUBLIC_KEY:
                        free_create_public_key_cookie(cookie);
                        break;
                case NTB_CRYPTO_COOKIE_DECRYPT_MSG:
                        free_decrypt_msg_cookie(cookie);
                        break;
                case NTB_CRYPTO_COOKIE_GENERATE_ACKDATA:
                        free_generate_ackdata_cookie(cookie);
                        break;
                }

                ntb_slice_free(&cookie->crypto->cookie_allocator, cookie);
        }
}

static void
create_key(struct ntb_crypto *crypto,
           uint8_t *private_key,
           uint8_t *public_key)
{
        int result;

        result = RAND_bytes(private_key, NTB_ECC_PRIVATE_KEY_SIZE);
        assert(result);

        ntb_ecc_make_pub_key_bin(crypto->ecc,
                                 private_key,
                                 public_key);
}

static int
count_leading_zeroes(const uint8_t *hash)
{
        int count = 0;

        while (hash[count] == 0 && count < RIPEMD160_DIGEST_LENGTH)
                count++;

        return count;
}

static void
handle_create_key(struct ntb_crypto_cookie *cookie)
{
        struct ntb_crypto *crypto = cookie->crypto;
        uint8_t private_signing_key[NTB_ECC_PRIVATE_KEY_SIZE];
        uint8_t pub_signing_key[NTB_ECC_PUBLIC_KEY_SIZE];
        uint8_t private_encryption_key[NTB_ECC_PRIVATE_KEY_SIZE];
        uint8_t pub_encryption_key[NTB_ECC_PUBLIC_KEY_SIZE];
        uint8_t sha_hash[SHA512_DIGEST_LENGTH];
        uint8_t ripe[RIPEMD160_DIGEST_LENGTH];
        char address_string[NTB_ADDRESS_MAX_LENGTH + 1];
        SHA512_CTX sha_ctx;
        int attempts = 0;

        ntb_log("Generating key pair");

        create_key(crypto, private_signing_key, pub_signing_key);

        /* Keep generating random keys until we've reached an address
         * with a certain number of leading zeroes */
        do {
                create_key(crypto, private_encryption_key, pub_encryption_key);

                SHA512_Init(&sha_ctx);
                SHA512_Update(&sha_ctx,
                              pub_signing_key,
                              NTB_ECC_PUBLIC_KEY_SIZE);
                SHA512_Update(&sha_ctx,
                              pub_encryption_key,
                              NTB_ECC_PUBLIC_KEY_SIZE);
                SHA512_Final(sha_hash, &sha_ctx);

                RIPEMD160(sha_hash, SHA512_DIGEST_LENGTH, ripe);

                attempts++;
        } while (count_leading_zeroes(ripe) <
                 cookie->create_key.leading_zeroes);

        cookie->create_key.params.flags |= NTB_KEY_PARAM_RIPE;
        cookie->create_key.params.ripe = ripe;

        cookie->create_key.params.flags |= NTB_KEY_PARAM_PRIVATE_KEYS;
        cookie->create_key.params.private_signing_key = private_signing_key;
        cookie->create_key.params.private_encryption_key =
                private_encryption_key;

        cookie->create_key.params.flags |= NTB_KEY_PARAM_PUBLIC_KEYS;
        cookie->create_key.params.public_signing_key = pub_signing_key;
        cookie->create_key.params.public_encryption_key = pub_encryption_key;

        cookie->create_key.key = ntb_key_new(crypto->ecc,
                                             &cookie->create_key.params);

        ntb_address_encode(&cookie->create_key.key->address, address_string);

        ntb_log("Key pair generated after %i attempt%s. Address is %s",
                attempts,
                attempts == 1 ? "" : "s",
                address_string);
}

static void
append_key_base(struct ntb_key *key,
                struct ntb_buffer *buffer,
                size_t *behaviors_offset)
{
        /* Leave space for the nonce. The caller will have to
         * calculate this */
        ntb_buffer_set_length(buffer, buffer->length + sizeof (uint64_t));

        ntb_proto_add_64(buffer,
                         key->last_pubkey_send_time +
                         NTB_PROTO_PUBKEY_EXPIRY_TIME);
        ntb_proto_add_32(buffer, NTB_PROTO_INV_TYPE_PUBKEY);
        ntb_proto_add_var_int(buffer, key->address.version);
        ntb_proto_add_var_int(buffer, key->address.stream);

        if (behaviors_offset)
                *behaviors_offset = buffer->length;

        ntb_proto_add_32(buffer, NTB_PROTO_PUBKEY_BEHAVIORS);
        ntb_proto_add_public_key(buffer, key->signing_key);
        ntb_proto_add_public_key(buffer, key->encryption_key);
}

static void
append_signature_from_digest(struct ntb_buffer *buffer,
                             struct ntb_key *key,
                             const uint8_t *digest)
{
        unsigned int sig_length = ECDSA_size(key->signing_key);
        uint8_t *sig = alloca(sig_length);
        int int_ret;

        int_ret = ECDSA_sign(0, /* type (ignored) */
                             digest,
                             SHA_DIGEST_LENGTH,
                             sig,
                             &sig_length,
                             key->signing_key);
        assert(int_ret);

        ntb_proto_add_var_int(buffer, sig_length);
        ntb_buffer_append(buffer, sig, sig_length);
}

static void
append_signature(struct ntb_buffer *buffer,
                 struct ntb_key *key,
                 const uint8_t *data,
                 size_t length)
{
        uint8_t digest[SHA_DIGEST_LENGTH];

        SHA1(data, length, digest);

        append_signature_from_digest(buffer, key, digest);
}

static void
append_v34_key_base(struct ntb_key *key,
                    struct ntb_buffer *buffer,
                    size_t *behaviors_offset)
{
        append_key_base(key, buffer, behaviors_offset);

        ntb_proto_add_var_int(buffer, key->pow_per_byte);
        ntb_proto_add_var_int(buffer, key->pow_extra_bytes);
}

static struct ntb_blob *
create_v4_key(struct ntb_crypto *crypto,
              struct ntb_key *key)
{
        struct ntb_blob *blob;
        struct ntb_buffer buffer;
        size_t behaviors_offset;
        EC_POINT *tag_public_key_point;
        struct ntb_buffer encrypted_buffer;
        SHA_CTX sha_ctx;
        uint8_t digest[SHA_DIGEST_LENGTH];

        ntb_buffer_init(&buffer);
        ntb_blob_dynamic_init(&encrypted_buffer);

        append_v34_key_base(key, &buffer, &behaviors_offset);

        SHA1_Init(&sha_ctx);
        SHA1_Update(&sha_ctx,
                    buffer.data + sizeof (uint64_t),
                    behaviors_offset - sizeof (uint64_t));
        SHA1_Update(&sha_ctx,
                    key->tag,
                    NTB_ADDRESS_TAG_SIZE);
        SHA1_Update(&sha_ctx,
                    buffer.data + behaviors_offset,
                    buffer.length - behaviors_offset);
        SHA1_Final(digest, &sha_ctx);

        append_signature_from_digest(&buffer, key, digest);

        tag_public_key_point =
                ntb_ecc_make_pub_key_point(crypto->ecc,
                                           key->tag_private_key);

        ntb_buffer_append(&encrypted_buffer,
                          buffer.data,
                          behaviors_offset);
        ntb_buffer_append(&encrypted_buffer,
                          key->tag,
                          NTB_ADDRESS_TAG_SIZE);

        ntb_ecc_encrypt_with_point(crypto->ecc,
                                   tag_public_key_point,
                                   buffer.data + behaviors_offset,
                                   buffer.length - behaviors_offset,
                                   &encrypted_buffer);

        EC_POINT_free(tag_public_key_point);

        blob = ntb_blob_dynamic_end(&encrypted_buffer);

        ntb_buffer_destroy(&buffer);

        return blob;
}

static struct ntb_blob *
create_v3_key(struct ntb_key *key)
{
        struct ntb_buffer buffer;

        ntb_blob_dynamic_init(&buffer);

        append_v34_key_base(key, &buffer, NULL);

        append_signature(&buffer,
                         key,
                         buffer.data + sizeof (uint64_t),
                         buffer.length - sizeof (uint64_t));

        return ntb_blob_dynamic_end(&buffer);
}

static struct ntb_blob *
create_v2_key(struct ntb_key *key)
{
        struct ntb_buffer buffer;

        ntb_blob_dynamic_init(&buffer);

        append_key_base(key, &buffer, NULL);

        return ntb_blob_dynamic_end(&buffer);
}

static void
handle_create_pubkey_blob(struct ntb_crypto_cookie *cookie)
{
        struct ntb_key *key = cookie->create_pubkey_blob.key;

        switch (key->address.version) {
        case 4:
                cookie->create_pubkey_blob.blob =
                        create_v4_key(cookie->crypto, key);
                break;
        case 3:
                cookie->create_pubkey_blob.blob = create_v3_key(key);
                break;
        default:
                cookie->create_pubkey_blob.blob = create_v2_key(key);
                break;
        }
}

static bool
check_signature_for_digest(struct ntb_crypto *crypto,
                           const uint8_t *network_public_key,
                           const uint8_t *digest,
                           size_t digest_length,
                           const uint8_t *signature,
                           size_t signature_length)
{
        uint8_t public_key[NTB_ECC_PUBLIC_KEY_SIZE];
        EC_KEY *key;
        int verify_result;

        /* The keys on the network have the 0x04 prefix stripped so we
         * need to add it back on */
        public_key[0] = 0x04;
        memcpy(public_key + 1, network_public_key, NTB_ECC_PUBLIC_KEY_SIZE - 1);

        key = ntb_ecc_create_key_with_public(crypto->ecc,
                                             NULL, /* private key */
                                             public_key);

        verify_result = ECDSA_verify(0, /* type, ignored */
                                     digest,
                                     digest_length,
                                     signature,
                                     signature_length,
                                     key);

        EC_KEY_free(key);

        return verify_result == 1;
}

static bool
check_signature_for_data(struct ntb_crypto *crypto,
                         const uint8_t *network_public_key,
                         const uint8_t *data,
                         size_t data_length,
                         const uint8_t *signature,
                         size_t signature_length)
{
        uint8_t digest[SHA_DIGEST_LENGTH];

        SHA1(data, data_length, digest);

        return check_signature_for_digest(crypto,
                                          network_public_key,
                                          digest,
                                          SHA_DIGEST_LENGTH,
                                          signature,
                                          signature_length);
}

static void
handle_check_unencrypted_pubkey(struct ntb_crypto_cookie *cookie,
                                const struct ntb_proto_pubkey *pubkey)
{
        uint8_t full_public_signing_key[NTB_ECC_PUBLIC_KEY_SIZE];
        uint8_t full_public_encryption_key[NTB_ECC_PUBLIC_KEY_SIZE];
        struct ntb_crypto *crypto = cookie->crypto;
        struct ntb_address address;
        struct ntb_key_params params;

        if (pubkey->signature &&
            !check_signature_for_data(crypto,
                                      pubkey->public_signing_key,
                                      pubkey->signed_data,
                                      pubkey->signed_data_length,
                                      pubkey->signature,
                                      pubkey->signature_length)) {
                ntb_log("The signature in the pubkey message is invalid");
                return;
        }

        ntb_address_from_network_keys(&address,
                                      pubkey->header.version,
                                      pubkey->header.stream,
                                      pubkey->public_signing_key,
                                      pubkey->public_encryption_key);

        if (!ntb_address_equal(&address, &cookie->check_pubkey.address)) {
                ntb_log("The keys in the decrypted pubkey msg do not match "
                        "the key's tag.");
                return;
        }

        /* The keys from the network don't have the 0x04 prefix so we
         * have to add it */
        full_public_signing_key[0] = 0x04;
        memcpy(full_public_signing_key + 1,
               pubkey->public_signing_key,
               NTB_ECC_PUBLIC_KEY_SIZE - 1);
        full_public_encryption_key[0] = 0x04;
        memcpy(full_public_encryption_key + 1,
               pubkey->public_encryption_key,
               NTB_ECC_PUBLIC_KEY_SIZE - 1);

        params.flags = (NTB_KEY_PARAM_VERSION |
                        NTB_KEY_PARAM_STREAM |
                        NTB_KEY_PARAM_PUBLIC_KEYS |
                        NTB_KEY_PARAM_POW_DIFFICULTY |
                        NTB_KEY_PARAM_RIPE);
        params.version = address.version;
        params.stream = address.stream;
        params.public_signing_key = full_public_signing_key;
        params.public_encryption_key = full_public_encryption_key;
        params.pow_per_byte = pubkey->pow_per_byte;
        params.pow_extra_bytes = pubkey->pow_extra_bytes;
        params.ripe = address.ripe;

        cookie->check_pubkey.key = ntb_key_new(crypto->ecc, &params);
}

static void
handle_check_encrypted_pubkey(struct ntb_crypto_cookie *cookie,
                              const struct ntb_proto_pubkey *pubkey)
{
        struct ntb_crypto *crypto = cookie->crypto;
        uint8_t tag[NTB_ADDRESS_TAG_SIZE];
        uint8_t tag_private_key[NTB_ECC_PRIVATE_KEY_SIZE];
        struct ntb_buffer buffer;
        struct ntb_proto_pubkey decrypted_pubkey;
        EC_KEY *key;

        ntb_address_get_tag(&cookie->check_pubkey.address,
                            tag,
                            tag_private_key);

        if (memcmp(tag, pubkey->tag, NTB_ADDRESS_TAG_SIZE))
                return;

        key = ntb_ecc_create_key(crypto->ecc, tag_private_key);

        ntb_buffer_init(&buffer);

        ntb_buffer_append(&buffer,
                          cookie->check_pubkey.blob->data,
                          pubkey->encrypted_data -
                          cookie->check_pubkey.blob->data);

        if (ntb_ecc_decrypt(crypto->ecc,
                            key,
                            pubkey->encrypted_data,
                            pubkey->encrypted_data_length,
                            &buffer) &&
            ntb_proto_get_pubkey(true, /* decrypted */
                                 buffer.data,
                                 buffer.length,
                                 &decrypted_pubkey)) {
                handle_check_unencrypted_pubkey(cookie,
                                                &decrypted_pubkey);
        }

        ntb_buffer_destroy(&buffer);

        EC_KEY_free(key);
}

static void
handle_check_pubkey(struct ntb_crypto_cookie *cookie)
{
        struct ntb_proto_pubkey pubkey;
        struct ntb_blob *blob = cookie->check_pubkey.blob;

        if (!ntb_proto_get_pubkey(false, /* not decrypted */
                                  blob->data,
                                  blob->size,
                                  &pubkey))
                return;

        if (pubkey.encrypted_data)
                handle_check_encrypted_pubkey(cookie, &pubkey);
        else
                handle_check_unencrypted_pubkey(cookie, &pubkey);
}

static void
handle_create_msg_blob(struct ntb_crypto_cookie *cookie)
{
        struct ntb_crypto *crypto = cookie->crypto;
        struct ntb_key *from_key = cookie->create_msg_blob.from_key;
        struct ntb_key *to_key = cookie->create_msg_blob.to_key;
        struct ntb_blob *content = cookie->create_msg_blob.content;
        const EC_POINT *encryption_key;
        struct ntb_buffer signature;
        struct ntb_buffer buf;
        size_t signature_data_start;
        SHA_CTX sha_ctx;
        uint8_t digest[SHA_DIGEST_LENGTH];

        ntb_blob_dynamic_init(&buf);

        /* Leave space for the nonce. The caller will have to
         * calculate this */
        ntb_buffer_set_length(&buf, buf.length + sizeof (uint64_t));

        signature_data_start = buf.length;

        ntb_proto_add_64(&buf,
                         cookie->create_msg_blob.timestamp +
                         NTB_PROTO_MSG_EXPIRY_TIME);
        ntb_proto_add_32(&buf, NTB_PROTO_INV_TYPE_MSG);
        ntb_proto_add_var_int(&buf, 1 /* message version */);
        ntb_proto_add_var_int(&buf, to_key->address.stream);

        SHA1_Init(&sha_ctx);
        SHA1_Update(&sha_ctx,
                    buf.data + signature_data_start,
                    buf.length - signature_data_start);
        SHA1_Update(&sha_ctx,
                    content->data,
                    content->size);
        SHA1_Final(digest, &sha_ctx);

        encryption_key = EC_KEY_get0_public_key(to_key->encryption_key);

        ntb_ecc_encrypt_with_point_begin(crypto->ecc,
                                         encryption_key,
                                         &buf);
        ntb_ecc_encrypt_update(crypto->ecc,
                               content->data,
                               content->size,
                               &buf);

        ntb_buffer_init(&signature);

        append_signature_from_digest(&signature, from_key, digest);

        ntb_ecc_encrypt_update(crypto->ecc,
                               signature.data,
                               signature.length,
                               &buf);

        ntb_buffer_destroy(&signature);

        ntb_ecc_encrypt_end(crypto->ecc, &buf);

        cookie->create_msg_blob.result = ntb_blob_dynamic_end(&buf);
}

static void
handle_create_public_key(struct ntb_crypto_cookie *cookie)
{
        struct ntb_crypto *crypto = cookie->crypto;
        struct ntb_key *key;

        key = ntb_key_new(crypto->ecc,
                          &cookie->create_public_key.params);

        cookie->create_public_key.key = key;
}

static void
check_signature_in_decrypted_msg(const uint8_t *header,
                                 size_t header_size,
                                 struct ntb_crypto_cookie *cookie)
{
        struct ntb_proto_decrypted_msg msg;
        uint8_t digest1[SHA_DIGEST_LENGTH];
        uint8_t digest2[SHA256_DIGEST_LENGTH];
        SHA_CTX sha1_ctx;
        SHA256_CTX sha2_ctx;

        ntb_log("Successfully decrypted a message using the key “%s”",
                cookie->decrypt_msg.chosen_key->label);

        if (!ntb_proto_get_decrypted_msg(cookie->decrypt_msg.result->data,
                                         cookie->decrypt_msg.result->size,
                                         &msg)) {
                ntb_log("The decrypted message is invalid");
                goto invalid;
        }

        SHA1_Init(&sha1_ctx);
        SHA1_Update(&sha1_ctx,
                    header + sizeof (uint64_t),
                    header_size - sizeof (uint64_t));
        SHA1_Update(&sha1_ctx,
                    cookie->decrypt_msg.result->data,
                    msg.signed_data_length);
        SHA1_Final(digest1, &sha1_ctx);

        if (!check_signature_for_digest(cookie->crypto,
                                        msg.sender_signing_key,
                                        digest1,
                                        SHA_DIGEST_LENGTH,
                                        msg.sig,
                                        msg.sig_length)) {
                // fallback to check sha256
                SHA256_Init(&sha2_ctx);
                SHA256_Update(&sha2_ctx,
                              header + sizeof (uint64_t),
                              header_size - sizeof (uint64_t));
                SHA256_Update(&sha2_ctx,
                              cookie->decrypt_msg.result->data,
                              msg.signed_data_length);
                SHA256_Final(digest2, &sha2_ctx);

                if (!check_signature_for_digest(cookie->crypto,
                                                msg.sender_signing_key,
                                                digest2,
                                                SHA256_DIGEST_LENGTH,
                                                msg.sig,
                                                msg.sig_length)) {
                        ntb_log("The signature in the decrypted message is invalid");
                        goto invalid;
                }
        }

        return;

invalid:
        ntb_key_unref(cookie->decrypt_msg.chosen_key);
        cookie->decrypt_msg.chosen_key = NULL;
        ntb_blob_unref(cookie->decrypt_msg.result);
        cookie->decrypt_msg.result = NULL;
}

static void
handle_decrypt_msg(struct ntb_crypto_cookie *cookie)
{
        struct ntb_crypto *crypto = cookie->crypto;
        struct ntb_blob *blob = cookie->decrypt_msg.blob;
        struct ntb_buffer buffer;
        struct ntb_key *key;
        ssize_t header_size;
        struct ntb_proto_object_header header;
        const uint8_t *data;
        size_t data_length;
        size_t decryption_start;
        uint64_t pow_value;
        uint64_t target;
        int64_t remaining_time;
        int i;

        header_size = ntb_proto_get_object_header(blob->data,
                                                  blob->size,
                                                  &header);

        remaining_time = (header.expires_time -
                          ntb_main_context_get_wall_clock(NULL));

        assert(header_size != -1);

        data = blob->data + header_size;
        data_length = blob->size - header_size;

        pow_value = ntb_pow_calculate_value(blob->data, blob->size);

        ntb_blob_dynamic_init(&buffer);

        decryption_start = buffer.length;

        for (i = 0; i < cookie->decrypt_msg.n_keys; i++) {
                key = cookie->decrypt_msg.keys[i];

                if (!key->enabled)
                        continue;

                if (!ntb_key_has_private(key))
                        continue;

                target = ntb_pow_calculate_target(data_length,
                                                  key->pow_per_byte,
                                                  key->pow_extra_bytes,
                                                  remaining_time);

                if (pow_value > target)
                        continue;

                if (ntb_ecc_decrypt(crypto->ecc,
                                    key->encryption_key,
                                    data,
                                    data_length,
                                    &buffer)) {
                        cookie->decrypt_msg.chosen_key = ntb_key_ref(key);
                        cookie->decrypt_msg.result =
                                ntb_blob_dynamic_end(&buffer);
                        check_signature_in_decrypted_msg(blob->data,
                                                         header_size,
                                                         cookie);
                        return;
                }

                buffer.length = decryption_start;
        }

        ntb_buffer_destroy(&buffer);
}

static void
handle_generate_ackdata(struct ntb_crypto_cookie *cookie)
{
        int result;

        result = RAND_bytes(cookie->generate_ackdata.ackdata,
                            NTB_PROTO_ACKDATA_SIZE);
        assert(result);
}

static void
idle_cb(struct ntb_main_context_source *source,
        void *user_data)
{
        struct ntb_crypto_cookie *cookie = user_data;
        struct ntb_crypto *crypto = cookie->crypto;
        ntb_crypto_create_key_func create_key_func;
        ntb_crypto_create_pubkey_blob_func create_pubkey_blob_func;
        ntb_crypto_create_msg_blob_func create_msg_blob_func;
        ntb_crypto_decrypt_msg_func decrypt_msg_func;
        ntb_crypto_generate_ackdata_func generate_ackdata_func;

        switch (cookie->type) {
        case NTB_CRYPTO_COOKIE_CREATE_KEY:
                create_key_func = cookie->func;
                create_key_func(cookie->create_key.key, cookie->user_data);
                break;
        case NTB_CRYPTO_COOKIE_CREATE_PUBKEY_BLOB:
                create_pubkey_blob_func = cookie->func;
                create_pubkey_blob_func(cookie->create_pubkey_blob.blob,
                                        cookie->user_data);
                break;
        case NTB_CRYPTO_COOKIE_CHECK_PUBKEY:
                create_key_func = cookie->func;
                create_key_func(cookie->check_pubkey.key,
                                cookie->user_data);
                break;
        case NTB_CRYPTO_COOKIE_CREATE_MSG_BLOB:
                create_msg_blob_func = cookie->func;
                create_msg_blob_func(cookie->create_msg_blob.result,
                                     cookie->user_data);
                break;
        case NTB_CRYPTO_COOKIE_CREATE_PUBLIC_KEY:
                create_key_func = cookie->func;
                create_key_func(cookie->create_public_key.key,
                                cookie->user_data);
                break;
        case NTB_CRYPTO_COOKIE_DECRYPT_MSG:
                decrypt_msg_func = cookie->func;
                decrypt_msg_func(cookie->decrypt_msg.chosen_key,
                                 cookie->decrypt_msg.result,
                                 cookie->user_data);
                break;
        case NTB_CRYPTO_COOKIE_GENERATE_ACKDATA:
                generate_ackdata_func = cookie->func;
                generate_ackdata_func(cookie->generate_ackdata.ackdata,
                                      cookie->user_data);
                break;
        }

        pthread_mutex_lock(&crypto->mutex);

        unref_cookie(cookie);

        pthread_mutex_unlock(&crypto->mutex);

        ntb_main_context_remove_source(source);
}

static void *
thread_func(void *user_data)
{
        struct ntb_crypto *crypto = user_data;
        struct ntb_crypto_cookie *cookie;
        enum ntb_crypto_cookie_type type;

        /* Seed the random number generator. I think this will happen
         * anyway but it's not really clear from the docs */
        RAND_poll();

        pthread_mutex_lock(&crypto->mutex);

        while (true) {
                while (!crypto->quit && ntb_list_empty(&crypto->queue))
                        pthread_cond_wait(&crypto->cond, &crypto->mutex);

                if (crypto->quit)
                        break;

                cookie = ntb_container_of(crypto->queue.next,
                                          struct ntb_crypto_cookie,
                                          link);

                /* The cookie would have had a reference for being in
                 * the queue. We'll steal this reference */
                ntb_list_remove(&cookie->link);
                cookie->in_queue = false;

                if (!cookie->cancelled) {
                        type = cookie->type;

                        pthread_mutex_unlock(&crypto->mutex);

                        switch (type) {
                        case NTB_CRYPTO_COOKIE_CREATE_KEY:
                                handle_create_key(cookie);
                                break;
                        case NTB_CRYPTO_COOKIE_CREATE_PUBKEY_BLOB:
                                handle_create_pubkey_blob(cookie);
                                break;
                        case NTB_CRYPTO_COOKIE_CHECK_PUBKEY:
                                handle_check_pubkey(cookie);
                                break;
                        case NTB_CRYPTO_COOKIE_CREATE_MSG_BLOB:
                                handle_create_msg_blob(cookie);
                                break;
                        case NTB_CRYPTO_COOKIE_CREATE_PUBLIC_KEY:
                                handle_create_public_key(cookie);
                                break;
                        case NTB_CRYPTO_COOKIE_DECRYPT_MSG:
                                handle_decrypt_msg(cookie);
                                break;
                        case NTB_CRYPTO_COOKIE_GENERATE_ACKDATA:
                                handle_generate_ackdata(cookie);
                                break;
                        }

                        pthread_mutex_lock(&crypto->mutex);

                        /* The cookie may have been cancelled while we were
                         * processing it without the lock */
                        if (!cookie->cancelled)
                                cookie->idle_source =
                                        ntb_main_context_add_idle(NULL,
                                                                  idle_cb,
                                                                  cookie);
                }

                unref_cookie(cookie);
        }

        pthread_mutex_unlock(&crypto->mutex);

        return NULL;
}

struct ntb_crypto *
ntb_crypto_new(void)
{
        struct ntb_crypto *crypto = ntb_alloc(sizeof *crypto);

        crypto->quit = false;

        ntb_list_init(&crypto->queue);

        ntb_slice_allocator_init(&crypto->cookie_allocator,
                                 sizeof (struct ntb_crypto_cookie),
                                 NTB_ALIGNOF (struct ntb_crypto_cookie));

        pthread_cond_init(&crypto->cond, NULL);
        pthread_mutex_init(&crypto->mutex, NULL);
        crypto->thread = ntb_create_thread(thread_func, crypto);

        crypto->ecc = ntb_ecc_new();

        return crypto;
}

struct ntb_crypto_cookie *
ntb_crypto_create_key(struct ntb_crypto *crypto,
                      const struct ntb_key_params *params,
                      int leading_zeroes,
                      ntb_crypto_create_key_func callback,
                      void *user_data)
{
        struct ntb_crypto_cookie *cookie;

        assert((params->flags & (NTB_KEY_PARAM_PRIVATE_KEYS |
                                 NTB_KEY_PARAM_PUBLIC_KEYS |
                                 NTB_KEY_PARAM_RIPE)) == 0);

        pthread_mutex_lock(&crypto->mutex);

        cookie = new_cookie(crypto,
                            NTB_CRYPTO_COOKIE_CREATE_KEY,
                            callback,
                            user_data);

        cookie->create_key.params = *params;

        if ((params->flags & NTB_KEY_PARAM_LABEL))
                cookie->create_key.params.label = ntb_strdup(params->label);

        cookie->create_key.leading_zeroes = leading_zeroes;
        cookie->create_key.key = NULL;

        pthread_mutex_unlock(&crypto->mutex);

        return cookie;
}

struct ntb_crypto_cookie *
ntb_crypto_create_pubkey_blob(struct ntb_crypto *crypto,
                              struct ntb_key *key,
                              ntb_crypto_create_pubkey_blob_func callback,
                              void *user_data)
{
        struct ntb_crypto_cookie *cookie;

        pthread_mutex_lock(&crypto->mutex);

        cookie = new_cookie(crypto,
                            NTB_CRYPTO_COOKIE_CREATE_PUBKEY_BLOB,
                            callback,
                            user_data);
        cookie->create_pubkey_blob.key = ntb_key_ref(key);
        cookie->create_pubkey_blob.blob = NULL;

        pthread_mutex_unlock(&crypto->mutex);

        return cookie;
}

struct ntb_crypto_cookie *
ntb_crypto_create_msg_blob(struct ntb_crypto *crypto,
                           int64_t timestamp,
                           struct ntb_key *from_key,
                           struct ntb_key *to_key,
                           struct ntb_blob *content,
                           ntb_crypto_create_msg_blob_func callback,
                           void *user_data)
{
        struct ntb_crypto_cookie *cookie;

        pthread_mutex_lock(&crypto->mutex);

        cookie = new_cookie(crypto,
                            NTB_CRYPTO_COOKIE_CREATE_MSG_BLOB,
                            callback,
                            user_data);
        cookie->create_msg_blob.timestamp = timestamp;
        cookie->create_msg_blob.from_key = ntb_key_ref(from_key);
        cookie->create_msg_blob.to_key = ntb_key_ref(to_key);
        cookie->create_msg_blob.content = ntb_blob_ref(content);
        cookie->create_msg_blob.result = NULL;

        pthread_mutex_unlock(&crypto->mutex);

        return cookie;
}

struct ntb_crypto_cookie *
ntb_crypto_create_public_key(struct ntb_crypto *crypto,
                             const struct ntb_key_params *params,
                             ntb_crypto_create_key_func callback,
                             void *user_data)
{
        struct ntb_crypto_cookie *cookie;

        assert((params->flags & (NTB_KEY_PARAM_PUBLIC_KEYS |
                                 NTB_KEY_PARAM_PRIVATE_KEYS |
                                 NTB_KEY_PARAM_RIPE)) ==
               NTB_KEY_PARAM_PUBLIC_KEYS);

        pthread_mutex_lock(&crypto->mutex);

        cookie = new_cookie(crypto,
                            NTB_CRYPTO_COOKIE_CREATE_PUBLIC_KEY,
                            callback,
                            user_data);

        cookie->create_public_key.params = *params;

        memcpy(cookie->create_public_key.signing_key,
               params->public_signing_key,
               NTB_ECC_PUBLIC_KEY_SIZE);
        cookie->create_public_key.params.public_signing_key =
                cookie->create_public_key.signing_key;

        memcpy(cookie->create_public_key.encryption_key,
               params->public_encryption_key,
               NTB_ECC_PUBLIC_KEY_SIZE);
        cookie->create_public_key.params.public_encryption_key =
                cookie->create_public_key.encryption_key;

        cookie->create_public_key.key = NULL;

        pthread_mutex_unlock(&crypto->mutex);

        return cookie;
}


struct ntb_crypto_cookie *
ntb_crypto_check_pubkey(struct ntb_crypto *crypto,
                        const struct ntb_address *address,
                        struct ntb_blob *blob,
                        ntb_crypto_create_key_func callback,
                        void *user_data)
{
        struct ntb_crypto_cookie *cookie;

        pthread_mutex_lock(&crypto->mutex);

        cookie = new_cookie(crypto,
                            NTB_CRYPTO_COOKIE_CHECK_PUBKEY,
                            callback,
                            user_data);
        cookie->check_pubkey.address = *address;
        cookie->check_pubkey.blob = ntb_blob_ref(blob);
        cookie->check_pubkey.key = NULL;

        pthread_mutex_unlock(&crypto->mutex);

        return cookie;
}

struct ntb_crypto_cookie *
ntb_crypto_decrypt_msg(struct ntb_crypto *crypto,
                       struct ntb_blob *blob,
                       struct ntb_key * const *keys,
                       int n_keys,
                       ntb_crypto_decrypt_msg_func callback,
                       void *user_data)
{
        struct ntb_crypto_cookie *cookie;
        int i;

        pthread_mutex_lock(&crypto->mutex);

        cookie = new_cookie(crypto,
                            NTB_CRYPTO_COOKIE_DECRYPT_MSG,
                            callback,
                            user_data);
        cookie->decrypt_msg.blob = ntb_blob_ref(blob);
        cookie->decrypt_msg.keys =
                ntb_memdup(keys, n_keys * sizeof (struct ntb_key *));
        cookie->decrypt_msg.n_keys = n_keys;
        cookie->decrypt_msg.result = NULL;
        cookie->decrypt_msg.chosen_key = NULL;

        for (i = 0; i < n_keys; i++)
                ntb_key_ref(keys[i]);

        pthread_mutex_unlock(&crypto->mutex);

        return cookie;
}

struct ntb_crypto_cookie *
ntb_crypto_generate_ackdata(struct ntb_crypto *crypto,
                            ntb_crypto_generate_ackdata_func callback,
                            void *user_data)
{
        struct ntb_crypto_cookie *cookie;

        pthread_mutex_lock(&crypto->mutex);

        cookie = new_cookie(crypto,
                            NTB_CRYPTO_COOKIE_GENERATE_ACKDATA,
                            callback,
                            user_data);

        pthread_mutex_unlock(&crypto->mutex);

        return cookie;
}

void
ntb_crypto_cancel_task(struct ntb_crypto_cookie *cookie)
{
        struct ntb_crypto *crypto = cookie->crypto;

        pthread_mutex_lock(&crypto->mutex);

        /* The queue holds a reference to the cookie */
        if (cookie->in_queue) {
                ntb_list_remove(&cookie->link);
                unref_cookie(cookie);
        }

        cookie->cancelled = true;

        if (cookie->idle_source)
                ntb_main_context_remove_source(cookie->idle_source);

        /* One reference is held by the caller */
        unref_cookie(cookie);

        pthread_mutex_unlock(&crypto->mutex);
}

void
ntb_crypto_free(struct ntb_crypto *crypto)
{
        pthread_mutex_lock(&crypto->mutex);
        crypto->quit = true;
        pthread_cond_signal(&crypto->cond);
        pthread_mutex_unlock(&crypto->mutex);
        pthread_join(crypto->thread, NULL);

        pthread_cond_destroy(&crypto->cond);
        pthread_mutex_destroy(&crypto->mutex);

        ntb_slice_allocator_destroy(&crypto->cookie_allocator);

        ntb_ecc_free(crypto->ecc);

        ntb_free(crypto);
}
