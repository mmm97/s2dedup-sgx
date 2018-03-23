
#ifndef __HASH_MD5__
#define __HASH_MD5__

#include <openssl/md5.h>
#include <stdlib.h>
#include <string.h>

int md5_init(MD5_CTX *context);

int md5_update(MD5_CTX *context, const char *data, unsigned long data_len);

int md5_final(MD5_CTX *context, unsigned char *digest);

int md5_get_digest_length();

#endif