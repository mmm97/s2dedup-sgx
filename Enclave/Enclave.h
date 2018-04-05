#ifndef _ENCLAVE_H_
#define _ENCLAVE_H_

#include <stdlib.h>
#include <assert.h>

#define TEST_CHECK(status)	\
{	\
	if (status != SGX_SUCCESS) {	\
		printf("OCALL status check failed %s(%d), status = %d\n", __FUNCTION__, __LINE__, status);	\
		abort();	\
	}	\
}

#if defined(__cplusplus)
extern "C" {
#endif

#define HASH_MD5 1
#define HASH_SHA256 17

void printf(const char *fmt, ...);

int puts(const char* str);
char* getenv(char* name);
int fflush(void* stream);
void exit(int status);

int trusted_encode(unsigned char* key, int key_size, uint8_t *dest, size_t dest_size, uint8_t* src, size_t src_size);
int trusted_decode(unsigned char* key, int key_size, uint8_t *dest, size_t dest_size, uint8_t* src, size_t src_size);

void trusted_init(unsigned char* client_key, int key_size, int iv_size, int tag_size, int ops);


int trusted_compute_hash(uint8_t *data, size_t data_size, uint8_t *digest, size_t digest_size);
int trusted_reencrypt(uint8_t *dest, size_t dest_size, uint8_t* src, size_t src_size);
int trusted_reencrypt_hash_epoch(uint8_t *dest, size_t dest_size, uint8_t *digest, size_t digest_size, uint8_t* src, size_t src_size);
int trusted_decrypt_hash_epoch(uint8_t *dest, size_t dest_size, uint8_t *digest, size_t digest_size, uint8_t* src, size_t src_size);

#if defined(__cplusplus)
}
#endif

#endif /* !_ENCLAVE_H_ */
