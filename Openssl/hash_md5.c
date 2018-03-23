
#include "hash_md5.h"

int md5_init(MD5_CTX *context) {    
    return MD5_Init(context)-1;
}

int md5_update(MD5_CTX *context, const char *data, unsigned long data_len) {
    if (data_len > 0) {
        return MD5_Update(context, data, data_len)-1;        
    }
    return -1;
}

int md5_final(MD5_CTX *context, unsigned char *digest) {
    return MD5_Final(digest, context)-1;
}

int md5_get_digest_length() {
    return MD5_DIGEST_LENGTH;
}