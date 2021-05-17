#include "Seal.h"

uint32_t getSealedSize(size_t key_size) {
    return sgx_calc_sealed_data_size(0, key_size);
}

int seal(unsigned char *plaintext, size_t plaintext_size, unsigned char *sealed_data) {    
    int sealed_data_size = sgx_calc_sealed_data_size(0, plaintext_size);  
    sgx_sealed_data_t *aux_sealed_data = (sgx_sealed_data_t*) malloc (sizeof(sgx_sealed_data_t) * sealed_data_size);
    sgx_status_t err = sgx_seal_data(0, NULL, plaintext_size, plaintext, sealed_data_size, aux_sealed_data);
    if (err != SGX_SUCCESS) usgx_exit("seal", err);
    memcpy(sealed_data, aux_sealed_data, sealed_data_size);
    free(aux_sealed_data);
    return 0;
}

int unseal(unsigned char *sealed_data, unsigned char *unsealed_data, uint32_t unsealed_buf_size) {
    uint32_t unsealed_data_size = unsealed_buf_size;
    unsigned char *aux_unsealed_data = (unsigned char*) malloc(sizeof(unsigned char) * unsealed_buf_size);
    int err = sgx_unseal_data((const sgx_sealed_data_t *) sealed_data, NULL, NULL, aux_unsealed_data, &unsealed_data_size);
    if (err != SGX_SUCCESS) usgx_exit("unseal", err);
    memcpy(unsealed_data, aux_unsealed_data, unsealed_data_size);
    free(aux_unsealed_data);
    return 0;
}
