#include "symmetric.h"
#include "auth_encryption.h"
#include <openssl/sha.h>
#include <openssl/hmac.h>

#include <stdlib.h>
#include <string.h>

void init_u_openssl(char* client_key, int key_size, int iv_size, int tag_size, int operation_mode, int ops);
void clear_u_openssl();

int encode(uint8_t *dest, size_t dest_size, uint8_t* src, size_t src_size);
int decode(uint8_t *dest, size_t dest_size, uint8_t* src, size_t src_size);

int reencrypt(uint8_t *dest, size_t dest_size, uint8_t* src, size_t src_size);
int decrypt_hash_epoch(uint8_t *digest, size_t digest_size, uint8_t* src, size_t src_size);
