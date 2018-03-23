#include "hash_sha256.h"

int sha256_init(SHA256_CTX *context) {
    return SHA256_Init(context);
}

int sha256_update(SHA256_CTX *context, const char *data, unsigned long data_len) {    
    if (data_len > 0) {
        return SHA256_Update(context, data, data_len);        
    }
    return -1;
}

int sha256_final(SHA256_CTX *context, unsigned char *digest) {
    return SHA256_Final(digest, context);
}

int sha256_get_digest_length() {
    return SHA256_DIGEST_LENGTH;
}