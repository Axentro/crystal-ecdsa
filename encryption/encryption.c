
/*
 * Home: https://github.com/insanum/ecies
 * Author: Eric Davis <edavis@insanum.com>
 */

#include <stdio.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/evp.h>

#define err(fmt, ...)                                \
        do {                                         \
                printf("ERROR:" fmt, ##__VA_ARGS__); \
                exit(1);                             \
        } while (0)

#define log(fmt, ...)                       \
        do {                                \
                printf(fmt, ##__VA_ARGS__); \
        } while (0)

// Error strings are returned to the caller via this static pointer
static char *error_string = NULL;

/*
 * This function takes a buffer with binary data and dumps
 * out a hex string prefixed with a label.
 */
void dump_hex(char *label, uint8_t *buf, int len)
{
        int i;
        log("%-10s: ", label);
        for (i = 0; i < len; ++i) { log("%02x", buf[i]); }
        log("\n");
}

/* Convert an EC key's public key to a binary array. */
int ec_key_public_key_to_bin(const EC_KEY  *ec_key,
                             uint8_t      **pubk,     // out (must free)
                             size_t        *pubk_len) // out
{
        const EC_GROUP *ec_group   = EC_KEY_get0_group(ec_key);
        const EC_POINT *pub        = EC_KEY_get0_public_key(ec_key);
        BIGNUM         *pub_bn     = BN_new();
        BN_CTX         *pub_bn_ctx = BN_CTX_new();

        BN_CTX_start(pub_bn_ctx);

        EC_POINT_point2bn(ec_group, pub, POINT_CONVERSION_UNCOMPRESSED,
                          pub_bn, pub_bn_ctx);
        *pubk_len = BN_num_bytes(pub_bn);
        *pubk = OPENSSL_malloc(*pubk_len);

        if (BN_bn2bin(pub_bn, *pubk) != *pubk_len) {
                BN_CTX_free(pub_bn_ctx);
                BN_clear_free(pub_bn);
                error_string = "Failed to decode pubkey";
                return -1;
        }

        BN_CTX_end(pub_bn_ctx);
        BN_CTX_free(pub_bn_ctx);
        BN_clear_free(pub_bn);

        return 0;
}

/* Convert a public key binary array to an EC point. */
int ec_key_public_key_hex_to_point(const EC_GROUP  *ec_group,
                                   const char      *pubk,
                                   EC_POINT       **pubk_point) // out
{
        BN_CTX   *pubk_bn_ctx;

        *pubk_point = EC_POINT_new(ec_group);

        pubk_bn_ctx = BN_CTX_new();
        BN_CTX_start(pubk_bn_ctx);

        EC_POINT_hex2point(ec_group, pubk, *pubk_point, pubk_bn_ctx);

        BN_CTX_end(pubk_bn_ctx);
        BN_CTX_free(pubk_bn_ctx);

        return 0;
}

/* (TX) Generate an ephemeral EC key and associated shared symmetric key. */
int ecies_transmitter_generate_symkey(const int       curve,
                                      const char     *peer_pubk,
                                      uint8_t       **epubk,         // out (must free)
                                      size_t         *epubk_len,     // out
                                      uint8_t       **skey,          // out (must free)
                                      size_t         *skey_len)      // out
{
        EC_KEY         *ec_key          = NULL; /* ephemeral keypair */
        const EC_GROUP *ec_group        = NULL;
        EC_POINT       *peer_pubk_point = NULL;

        /* Create and initialize a new empty key pair on the curve. */
        ec_key = EC_KEY_new_by_curve_name(curve);
        EC_KEY_generate_key(ec_key);
        ec_group = EC_KEY_get0_group(ec_key);

        /* Allocate a buffer to hold the shared symmetric key. */
        *skey_len = ((EC_GROUP_get_degree(ec_group) + 7) / 8);
        *skey     = OPENSSL_malloc(*skey_len);

        /* Convert the peer public key to an EC point. */
        ec_key_public_key_hex_to_point(ec_group, peer_pubk, &peer_pubk_point);

        /* Generate the shared symmetric key (diffie-hellman primitive). */
        *skey_len = ECDH_compute_key(*skey, *skey_len, peer_pubk_point,
                                     ec_key, NULL);

        /* Write the ephemeral key's public key to the output buffer. */
        if (ec_key_public_key_to_bin(ec_key, epubk, epubk_len) < 0) {
                return -1;
        }

        return 0;
}

/* Convert a public key binary array to an EC point. */
int ec_key_public_key_bin_to_point(const EC_GROUP  *ec_group,
                                   const uint8_t   *pubk,
                                   const size_t     pubk_len,
                                   EC_POINT       **pubk_point) // out
{
        BIGNUM   *pubk_bn;
        BN_CTX   *pubk_bn_ctx;

        *pubk_point = EC_POINT_new(ec_group);

        pubk_bn = BN_bin2bn(pubk, pubk_len, NULL);
        pubk_bn_ctx = BN_CTX_new();
        BN_CTX_start(pubk_bn_ctx);

        EC_POINT_bn2point(ec_group, pubk_bn, *pubk_point, pubk_bn_ctx);

        BN_CTX_end(pubk_bn_ctx);
        BN_CTX_free(pubk_bn_ctx);
        BN_clear_free(pubk_bn);

        return 0;
}


/* (RX) Generate the shared symmetric key. */
int ecies_receiver_generate_symkey(const EC_KEY   *ec_key,
                                   const uint8_t  *peer_pubk,
                                   const size_t    peer_pubk_len,
                                   uint8_t       **skey,          // out (must free)
                                   size_t         *skey_len)      // out
{
        const EC_GROUP *ec_group        = EC_KEY_get0_group(ec_key);
        EC_POINT       *peer_pubk_point = NULL;

        /* Allocate a buffer to hold the shared symmetric key. */
        *skey_len = ((EC_GROUP_get_degree(ec_group) + 7) / 8);
        *skey     = OPENSSL_malloc(*skey_len);

        /* Convert the peer public key to an EC point. */
        ec_key_public_key_bin_to_point(ec_group, peer_pubk, peer_pubk_len,
                                       &peer_pubk_point);

        /* Generate the shared symmetric key (diffie-hellman primitive). */
        *skey_len = ECDH_compute_key(*skey, *skey_len, peer_pubk_point,
                                     (EC_KEY *)ec_key, NULL);

        return 0;
}

/* Encrypt plaintext data using 256b AES-GCM. */
int aes_gcm_256b_encrypt(uint8_t  *plaintext,
                         size_t    plaintext_len,
                         uint8_t  *skey,
                         uint8_t  *aad,
                         size_t    aad_len,
                         uint8_t **iv,             // out (must free)
                         int      *iv_len,         // out
                         uint8_t **tag,            // out (must free)
                         int      *tag_len,        // out
                         uint8_t **ciphertext,     // out (must free)
                         size_t   *ciphertext_len) // out
{
        EVP_CIPHER_CTX *ctx;
        int len;

        /* Allocate buffers for the IV, tag, and ciphertext. */
        *iv_len = 12;
        *iv = OPENSSL_malloc(*iv_len);
        *tag_len = 12;
        *tag = OPENSSL_malloc(*tag_len);
        *ciphertext = OPENSSL_malloc((plaintext_len + 0xf) & ~0xf);

        /* Initialize the context and encryption operation. */
        ctx = EVP_CIPHER_CTX_new();
        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);

        /* Generate a new random IV. */
        RAND_pseudo_bytes(*iv, *iv_len);

        /* Prime the key and IV. */
        EVP_EncryptInit_ex(ctx, NULL, NULL, skey, *iv);

        /* Prime with any additional authentication data. */
        if (aad && aad_len)
            EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len);

        /* Encrypt the data. */
        EVP_EncryptUpdate(ctx, *ciphertext, &len, plaintext, plaintext_len);
        *ciphertext_len = len;

        /* Finalize the encryption session. */
        EVP_EncryptFinal_ex(ctx, (*ciphertext + len), &len);
        *ciphertext_len += len;

        /* Get the authentication tag. */
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, *tag_len, *tag);

        EVP_CIPHER_CTX_free(ctx);

        return 0;
}

/* Decrypt ciphertext data using 256b AES-GCM. */
int aes_gcm_256b_decrypt(uint8_t  *ciphertext,
                         size_t    ciphertext_len,
                         uint8_t  *skey,
                         uint8_t  *aad,
                         size_t    aad_len,
                         uint8_t  *iv,
                         int       iv_len,
                         uint8_t  *tag,
                         int       tag_len,
                         uint8_t **plaintext,     // out (must free)
                         size_t   *plaintext_len) // out
{
        EVP_CIPHER_CTX *ctx;
        int len, rc;

        /* Allocate a buffer for the plaintext. */
        *plaintext = OPENSSL_malloc(ciphertext_len);

        /* Initialize the context and encryption operation. */
        ctx = EVP_CIPHER_CTX_new();
        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);

        /* Prime the key and IV (+length). */
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL);
        EVP_DecryptInit_ex(ctx, NULL, NULL, skey, iv);

        /* Prime with any additional authentication data. */
        if (aad && aad_len)
                EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len);

        /* Decrypt the data. */
        EVP_DecryptUpdate(ctx, *plaintext, &len, ciphertext, ciphertext_len);
        *plaintext_len = len;

        /* Set the expected tag value. */
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag_len, tag);

        /* Finalize the decryption session. Returns 0 with a bad tag! */
        rc = EVP_DecryptFinal_ex(ctx, (*plaintext + len), &len);

        EVP_CIPHER_CTX_free(ctx);

        if (rc > 0)
        {
                *plaintext_len += len;
                return 0;
        }

        /* verification failed */
        error_string = "Decryption verification failed";
        return -1;
}


int encrypt_message(uint8_t        *msg,
                    int             msg_len,
                    int             curve,
                    const char     *peer_pubk,
                    uint8_t       **epubk,          // out (must free)
                    size_t         *epubk_len,      // out
                    uint8_t       **iv,             // out (must free)
                    int            *iv_len,         // out
                    uint8_t       **tag,            // out (must free)
                    int            *tag_len,        // out
                    uint8_t       **ciphertext,     // out (must free)
                    size_t         *ciphertext_len) // out
{
        uint8_t *skey      = NULL; // DH generated shared symmetric key
        size_t   skey_len  = 0;

        error_string = NULL;

        /* Generate the shared symmetric key (transmitter). */
        ecies_transmitter_generate_symkey(curve, peer_pubk,
                                          epubk, epubk_len, &skey, &skey_len);
        if (skey_len != 32) {
                error_string = "Invalid public key";
        }
        else {
                /* Valid key, so encrypt the data using 256b AES-GCM. */
                aes_gcm_256b_encrypt(msg, msg_len, skey, NULL, 0, iv, iv_len, tag, tag_len, ciphertext, ciphertext_len);
        }

        free(skey);

        if (error_string != NULL) {
                *ciphertext_len = strlen(error_string);
                *ciphertext = (uint8_t *) error_string;
                return -1;
        }
        return 0;
}

int decrypt_message(int            curve,
                    const char    *receiver_hex_private_key,
                    const uint8_t *epubk,
                    const size_t   epubk_len,
                    uint8_t       *iv,
                    int            iv_len,
                    uint8_t       *tag,
                    int            tag_len,
                    uint8_t       *ciphertext,
                    size_t         ciphertext_len,
                    char          **decrypted_message)    // out (must free)
{
        EC_KEY     *ec_key      = NULL; /* ephemeral keypair */
        BIGNUM     *priv_bn     = BN_new();

        // Shared symmetric encryption key (DH generated)
        uint8_t *skey     = NULL;
        size_t   skey_len = 0;

        // Decrypted data (plaintext)
        uint8_t *plaintext     = NULL;
        size_t   plaintext_len = 0;

        error_string = NULL;

        /* Generate the shared symmetric key (receiver). */
        ec_key = EC_KEY_new_by_curve_name(curve);
        BN_hex2bn(&priv_bn, receiver_hex_private_key);
        EC_KEY_set_private_key(ec_key, priv_bn);
        ecies_receiver_generate_symkey(ec_key, epubk, epubk_len, &skey, &skey_len);

        if (skey_len != 32) {
                error_string = "Invalid private key";
        }
        else {
                /* Valid key, decrypt the data using 256b AES-GCM. */
                aes_gcm_256b_decrypt(ciphertext, ciphertext_len, skey, NULL, 0,
                                     iv, iv_len, tag, tag_len,
                                     &plaintext, &plaintext_len);
        }

        if (error_string != NULL) {
                free(plaintext);
                free(skey);
                *decrypted_message = error_string;
                return -1;
        }

        *decrypted_message = OPENSSL_malloc(plaintext_len);
        memcpy(*decrypted_message, plaintext, plaintext_len);

        free(plaintext);
        free(skey);

        return 0;
}
