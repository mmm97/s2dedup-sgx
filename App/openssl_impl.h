#include "symmetric.h"
#include "auth_encryption.h"
#include <openssl/sha.h>
#include <openssl/hmac.h>

#include <stdlib.h>
#include <string.h>

void init_u_openssl(unsigned char* client_key, int key_size, int iv_size, int tag_size, int ops);

int encode(unsigned char* key, int key_size, uint8_t *dest, size_t dest_size, uint8_t* src, size_t src_size);
int decode(unsigned char* key, int key_size, uint8_t *dest, size_t dest_size, uint8_t* src, size_t src_size);

int compute_hash(unsigned char *src, int src_len, unsigned char *digest, int digest_len);
int reencrypt(uint8_t *dest, size_t dest_size, uint8_t* src, size_t src_size);
int reencrypt_hash_epoch(uint8_t *dest, size_t dest_size, uint8_t *digest, size_t digest_size, uint8_t* src, size_t src_size);
int decrypt_hash_epoch(uint8_t *dest, size_t dest_size, uint8_t *digest, size_t digest_size, uint8_t* src, size_t src_size);

int check_integrity(uint8_t* plaintext, size_t plaintext_size, uint8_t *ciphertext, size_t ciphertext_size);