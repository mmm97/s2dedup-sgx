
#ifndef __HASH_SHA_256__
#define __HASH_SHA_256__

#include <openssl/sha.h>
#include <stdlib.h>
#include <string.h>

int sha256_init(SHA256_CTX *context);

int sha256_update(SHA256_CTX *context, const char *data, unsigned long data_len);

int sha256_final(SHA256_CTX *context, unsigned char *digest);

int sha256_get_digest_length();

#endif