#ifndef __AUTH_ENCRYPTION_H__
#define __AUTH_ENCRYPTION_H__

#include <openssl/ossl_typ.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>


#define GCM 1
#define CCM 2


int auth_init(int key_size, int tweak_size);

int auth_encode(unsigned char* key, unsigned char* tweak, unsigned char* dest, const unsigned char* src, int size);

int auth_decode(unsigned char* key, unsigned char* tweak, unsigned char* dest, const unsigned char* src, int size);

int auth_clean();

void auth_handleErrors(void);



#endif
