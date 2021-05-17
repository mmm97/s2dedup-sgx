#ifndef _ENCLAVE_H_
#define _ENCLAVE_H_

#include "Ocalls.h"
#include "Seal.h"
#include "sgx_utils.h"

#include <unistd.h> 
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#include <openssl/hmac.h>

int trusted_decode(uint8_t *dest, size_t dest_size, uint8_t* src, size_t src_size, uint64_t src_offset);

void trusted_init_sgx(char* client_key, int key_size, int tweak_size, int security_level, int epoch_or_threshold);
void trusted_clear_sgx();

int trusted_reencrypt(uint8_t *dest, size_t dest_size, uint64_t dest_offset, uint8_t* src, size_t src_size, uint64_t src_offset);
int trusted_reencrypt_reverse(uint8_t *dest, size_t dest_size, uint64_t dest_offset, uint8_t* src, size_t src_size, uint64_t src_offset);
int trusted_compute_hash(uint8_t *digest, size_t digest_size, uint8_t *data, size_t data_size,uint64_t data_offset);

#endif /* !_ENCLAVE_H_ */
