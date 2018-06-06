#include "sgx_tseal.h"
#include "sgx_utils.h"

#include <stdint.h>
#include <string.h>

int seal(unsigned char *plaintext, size_t plaintext_size, unsigned char *sealed_data);
int unseal(unsigned char *sealed_data, unsigned char *unsealed_data, uint32_t unsealed_buf_size);