#ifndef UTILPROGRAM_H
#define UTILPROGRAM_H

#include "openssl/x509.h"
#include "openssl/evp.h"

int urandom_random_bytes(uint8_t array[16]);
int verify_cert(const unsigned char *der, size_t der_len, const char *ca_pem_path);
EVP_PKEY* extract_pubkey(const unsigned char *der, size_t der_len);
int aes_encrypt(const unsigned char *plaintext, int plaintext_len,
                const unsigned char *key, const unsigned char *iv,
                unsigned char *ciphertext, int *ciphertext_len);
int encrypt_with_pubkey(EVP_PKEY *pubkey, const unsigned char *plaintext, size_t plaintext_len,
                        unsigned char *ciphertext, size_t *ciphertext_len);
int aes_decrypt(const unsigned char *ciphertext, int ciphertext_len,
                const unsigned char *key, const unsigned char *iv,
                unsigned char *plaintext, int *plaintext_len);
/*char* nvread();*/
int sign_sha256_hash(uint8_t hash[SHA256_DIGEST_LENGTH], EVP_PKEY *pkey,
                     uint8_t **signature, size_t *sig_len);

#endif