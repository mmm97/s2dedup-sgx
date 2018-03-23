#include "symmetric.h"
#include <openssl/sha.h>

#include <stdlib.h>
#include <string.h>

void init_u_openssl(char* key, int key_size);
int compute_hash(unsigned char *src, int src_len, unsigned char *digest, int digest_len);
int reencrypt(unsigned char *iv, int iv_size, unsigned char *dest, int dest_len, unsigned char *src, int src_len);
int reencrypt_hash(unsigned char *iv, int iv_size, unsigned char *dest, int dest_len, unsigned char *src, int src_len, unsigned char *digest, int digest_len);