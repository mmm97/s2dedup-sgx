#include "symmetric.h"
#include "auth_encryption.h"
#include <openssl/sha.h>

#include <stdlib.h>
#include <string.h>

void init_u_openssl(unsigned char* key, int key_size);
int encode(unsigned char* key, int key_size, uint8_t *dest, size_t dest_size, uint8_t* src, size_t src_size);
int decode(unsigned char* key, int key_size, uint8_t *dest, size_t dest_size, uint8_t* src, size_t src_size);
int compute_hash(unsigned char *src, int src_len, unsigned char *digest, int digest_len);
int reencrypt(uint8_t *dest, size_t dest_size, uint8_t* src, size_t src_size);
int reencrypt_hash(uint8_t *dest, size_t dest_size, uint8_t *digest, size_t digest_size, uint8_t* src, size_t src_size);