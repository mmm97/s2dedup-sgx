#include "sgx_trts.h"
#include "sgx_tcrypto.h"
#include "sgx_tseal.h"
#include "sgx_utils.h"
#include "tSgxSSL_api.h"

#include "Enclave.h"
#include "Enclave_t.h"

#include <unistd.h> 
#include <stdio.h>
#include <string.h>

#define MAC_SIZE 16
#define KEY_SIZE 16
#define IV_SIZE  12

unsigned char *SERVER_KEY;
unsigned char *CLIENT_KEY;

/* 
 * printf: 
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
void printf(const char *fmt, ...) {
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    uprint(buf);
}

int seal(unsigned char *plaintext, size_t plaintext_size, unsigned char *sealed_data) {    
    int sealed_data_size = sgx_calc_sealed_data_size(0, plaintext_size);  
    sgx_sealed_data_t *aux_sealed_data = (sgx_sealed_data_t*) malloc (sizeof(sgx_sealed_data_t) * sealed_data_size);
    sgx_status_t err = sgx_seal_data(0, NULL, plaintext_size, plaintext, sealed_data_size, aux_sealed_data);
    if (err != SGX_SUCCESS) { printf("sgx_seal_data\n"); usgx_exit(err);}
    memcpy(sealed_data, aux_sealed_data, sealed_data_size);
    free(aux_sealed_data);
    return 0;
}

int unseal(unsigned char *sealed_data, unsigned char *unsealed_data, uint32_t unsealed_buf_size) {
    uint32_t unsealed_data_size = unsealed_buf_size;
    unsigned char *aux_unsealed_data = (unsigned char*) malloc(sizeof(unsigned char) * unsealed_buf_size);
    int err = sgx_unseal_data((const sgx_sealed_data_t *) sealed_data, NULL, NULL, aux_unsealed_data, &unsealed_data_size);
    if (err != SGX_SUCCESS) { printf("sgx_unseal_data\n"); usgx_exit(err);}
    memcpy(unsealed_data, aux_unsealed_data, unsealed_data_size);
    free(aux_unsealed_data);
    return 0;
}

uint32_t getKey() {

    uint32_t err, sealed_sdata_len_in;
    uint32_t sealed_sdata_len = sgx_calc_sealed_data_size(0, KEY_SIZE);
    uint8_t *sealed_sdata     = (uint8_t*) malloc(sizeof(uint8_t) * sealed_sdata_len);

    SERVER_KEY = (unsigned char*) malloc (sizeof(unsigned char*) * KEY_SIZE);

    // check if exists
    if (load_sdata(&err, sealed_sdata, sealed_sdata_len, &sealed_sdata_len_in))
        return SGX_ERROR_UNEXPECTED;
    
    // if !exist
    if (err != 0) {
        // printf("<T> Generating a new server key...\n");

        // generate random key
        memset(SERVER_KEY, 0, KEY_SIZE);
        err = sgx_read_rand((unsigned char*)SERVER_KEY, KEY_SIZE);
        if (err != SGX_SUCCESS) { printf("sgx_read_rand\n"); usgx_exit(err);}

        // seal server key
        seal(SERVER_KEY, KEY_SIZE, sealed_sdata);

        // save sealed key
        if (save_sdata(&err, sealed_sdata, sealed_sdata_len))
            return EXIT_FAILURE;
    }
    // if exists
    else {
        // printf("<T> ekey found! -> %d\n", sealed_sdata_len_in);

        // check sealed size
        if (sealed_sdata_len_in != sealed_sdata_len) {
            // printf("<T> wrong sealed key size!\n");
            return EXIT_FAILURE;
        }

        // unseal sdata
        unseal(sealed_sdata, SERVER_KEY, KEY_SIZE);
    }
    free(sealed_sdata);
    return EXIT_SUCCESS;
}

int encode(unsigned char* key, int key_size, uint8_t *iv, size_t iv_size, uint8_t *mac, size_t mac_size, \
           uint8_t *dest, size_t dest_size, uint8_t* src, size_t src_size) {
    
    sgx_status_t err;
    
    err = sgx_rijndael128GCM_encrypt((sgx_aes_gcm_128bit_key_t*)key, src, src_size, dest, iv, iv_size, NULL, 0, (sgx_aes_gcm_128bit_tag_t*) mac);
    if (err != SGX_SUCCESS) { printf("sgx_rijndael128GCM_encrypt\n"); usgx_exit(err);}

    return src_size;
}

int decode(unsigned char* key, int key_size, uint8_t *iv, size_t iv_size,  uint8_t *mac, size_t mac_size, \
           uint8_t *dest, size_t dest_size, uint8_t* src, size_t src_size) {

    sgx_status_t err;
    
    err = sgx_rijndael128GCM_decrypt((sgx_aes_gcm_128bit_key_t*) key, src, src_size, dest, iv, iv_size, NULL, 0, (const sgx_aes_gcm_128bit_tag_t*) mac);
    if (err != SGX_SUCCESS) { printf("sgx_rijndael128GCM_decrypt\n"); usgx_exit(err);}

    return src_size;
}

int trusted_encode(unsigned char* key, int key_size, uint8_t *dest, size_t dest_size, uint8_t* src, size_t src_size) {
    sgx_status_t err;
    int ciphertext_size;

    unsigned char *iv = (unsigned char*) malloc(sizeof(unsigned char) * IV_SIZE);
    unsigned char *ciphertext = (unsigned char*) malloc(sizeof(unsigned char) * src_size);    
    unsigned char *p_out_mac = (unsigned char*) malloc(sizeof(unsigned char) * (MAC_SIZE));

    /* choose random nonce */
    err = sgx_read_rand(iv, IV_SIZE);
    if (err != SGX_SUCCESS) { usgx_exit(err); }

    ciphertext_size = encode(key, key_size, iv, IV_SIZE, p_out_mac, MAC_SIZE, ciphertext, src_size, src, src_size);

    memcpy(dest, ciphertext, ciphertext_size);
    memcpy(&dest[ciphertext_size], iv, IV_SIZE);
    memcpy(&dest[ciphertext_size + IV_SIZE], p_out_mac, MAC_SIZE);

    free(ciphertext);
    free(p_out_mac);

    return ciphertext_size + IV_SIZE + MAC_SIZE;
}

int trusted_decode(unsigned char* key, int key_size, uint8_t *dest, size_t dest_size, uint8_t* src, size_t src_size) {
    int plaintext_size = src_size - IV_SIZE - MAC_SIZE;
    
    unsigned char *plaintext = (unsigned char*) malloc(sizeof(unsigned char) * plaintext_size);

    plaintext_size = decode(key, key_size, &src[plaintext_size], IV_SIZE, &src[plaintext_size+IV_SIZE], MAC_SIZE, plaintext, plaintext_size, src, plaintext_size);

    memcpy(dest, plaintext, plaintext_size);

    free(plaintext);

    return plaintext_size;
}

int trusted_init(unsigned char* key, int key_size) {
    if (KEY_SIZE != key_size) return -1;
    // CLIENT_KEY = key;
    CLIENT_KEY = (unsigned char*) malloc(sizeof(unsigned char) * KEY_SIZE);
    memcpy(CLIENT_KEY, key, KEY_SIZE);
    if (getKey() != EXIT_SUCCESS) printf("<T> getKey error!\n");
    return 0;
}

/*
 * Compute Hash (init, update, final):
 *   Return 0 -> success, -1 fail
 */
int trusted_compute_hash(uint8_t *data, size_t data_size, uint8_t *digest, size_t digest_size) {    
    sgx_status_t err;
    err = sgx_sha256_msg(data, data_size, (sgx_sha256_hash_t*) digest);
    if (err != SGX_SUCCESS) { printf("sgx_sha256_msg\n"); usgx_exit(err);}
    return  (int) err;
}

/*
 * Reencrypt function:
 *   Decrypt data with client key and encrypt with server key
 */
int trusted_reencrypt(uint8_t *dest, size_t dest_size, uint8_t* src, size_t src_size) {

    unsigned char *plaintext, *ciphertext, *p_out_mac;
    int plaintext_size, ciphertext_size;

    // *****************************
    // Decode data with server key
    plaintext_size = src_size - IV_SIZE - MAC_SIZE;
    plaintext = (unsigned char*) malloc(sizeof(unsigned char) * plaintext_size);
    plaintext_size = decode(CLIENT_KEY, KEY_SIZE, &src[plaintext_size], IV_SIZE, &src[plaintext_size+IV_SIZE], MAC_SIZE, plaintext, plaintext_size, src, plaintext_size);

    // *****************************
    // Encode data with client key
    ciphertext = (unsigned char*) malloc (sizeof(unsigned char*) * dest_size);
    p_out_mac  = (unsigned char*) malloc (sizeof(unsigned char*) * (MAC_SIZE+1));
    ciphertext_size = encode(SERVER_KEY, KEY_SIZE, &src[plaintext_size], IV_SIZE, p_out_mac, MAC_SIZE, ciphertext, plaintext_size, plaintext, plaintext_size); 

    memcpy(dest, ciphertext, ciphertext_size);
    memcpy(&dest[ciphertext_size], &src[plaintext_size], IV_SIZE);
    memcpy(&dest[ciphertext_size+IV_SIZE], p_out_mac, MAC_SIZE);
    free(plaintext);
    free(ciphertext);
    free(p_out_mac);

    return ciphertext_size + IV_SIZE + MAC_SIZE;
}

/*
 * Reencrypt function:
 *   Decrypt data with client key, compute plaintext hash and encrypt with server key
 */
int trusted_reencrypt_hash(uint8_t *dest, size_t dest_size, uint8_t *digest, size_t digest_size, uint8_t* src, size_t src_size) {

    unsigned char *plaintext, *ciphertext, *aux_digest, *p_out_mac;
    int plaintext_size, ciphertext_size;

    // *****************************
    // Decode data with server key
    plaintext_size = src_size - IV_SIZE - MAC_SIZE;
    plaintext = (unsigned char*) malloc(sizeof(unsigned char) * plaintext_size);
    plaintext_size = decode(CLIENT_KEY, KEY_SIZE, &src[plaintext_size], IV_SIZE, &src[plaintext_size+IV_SIZE], MAC_SIZE, plaintext, plaintext_size, src, plaintext_size);
    // *****************************
    // Compute Hash
    aux_digest = (unsigned char*) malloc(sizeof(unsigned char) * digest_size);
    trusted_compute_hash(plaintext, plaintext_size, aux_digest, digest_size);

    // *****************************
    // Encode data with client key
    ciphertext = (unsigned char*) malloc (sizeof(unsigned char*) * dest_size);
    p_out_mac  = (unsigned char*) malloc (sizeof(unsigned char*) * (MAC_SIZE+1));
    ciphertext_size = encode(SERVER_KEY, KEY_SIZE, &src[plaintext_size], IV_SIZE, p_out_mac, MAC_SIZE, ciphertext, plaintext_size, plaintext, plaintext_size); 

    memcpy(dest, ciphertext, ciphertext_size);
    memcpy(&dest[ciphertext_size], &src[plaintext_size], IV_SIZE);
    memcpy(&dest[ciphertext_size+IV_SIZE], p_out_mac, MAC_SIZE);
    memcpy(digest, aux_digest, digest_size);
    
    free(plaintext);
    free(ciphertext);
    free(p_out_mac);
    free(aux_digest);

    return IV_SIZE + ciphertext_size + MAC_SIZE;
}
