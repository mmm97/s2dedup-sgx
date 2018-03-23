#include "sgx_trts.h"
#include "sgx_tseal.h"
#include "sgx_utils.h"
#include "tSgxSSL_api.h"

#include "Enclave.h"
#include "Enclave_t.h"

#include <unistd.h> 
#include <stdio.h>
#include <string.h>

#include "symmetric.h"
#include "hash_md5.h"
#include "hash_sha256.h"

uint32_t HASH_ALGORITHM;
uint32_t KEY_SIZE;
uint32_t IV_SIZE;
char *CLIENTKEY;

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

void print_digest(unsigned char *digest, int digest_size) {
    int n;
	char mdString[(digest_size * 2) + 1];
	for (n = 0; n < digest_size; ++n) {
        snprintf(&(mdString[n*2]), digest_size*2, "%02x", (unsigned int)digest[n]);
    }
	printf("<T> [%d] Digest: \'%s\'\n\n", digest_size, mdString);
}


int seal(unsigned char *plaintext, size_t plaintext_size, unsigned char *sealed_data) {    
    int sealed_data_size = sgx_calc_sealed_data_size(0, plaintext_size);  
    sgx_sealed_data_t *aux_sealed_data = (sgx_sealed_data_t*) malloc (sizeof(sgx_sealed_data_t) * sealed_data_size);
    sgx_status_t err = sgx_seal_data(0, NULL, plaintext_size, plaintext, sealed_data_size, aux_sealed_data);
    if (err != SGX_SUCCESS) usgx_exit(err);
    memcpy(sealed_data, aux_sealed_data, sealed_data_size);
    free(aux_sealed_data);
    return 0;
}

int unseal(unsigned char *sealed_data, unsigned char *unsealed_data, uint32_t unsealed_buf_size) {
    uint32_t unsealed_data_size = unsealed_buf_size;
    unsigned char *aux_unsealed_data = (unsigned char*) malloc(sizeof(unsigned char) * unsealed_buf_size);
    int err = sgx_unseal_data((const sgx_sealed_data_t *) sealed_data, NULL, NULL, aux_unsealed_data, &unsealed_data_size);
    if (err != SGX_SUCCESS) usgx_exit(err);
    memcpy(unsealed_data, aux_unsealed_data, unsealed_data_size);
    free(aux_unsealed_data);
    return 0;
}


int trusted_init(int algorithm, char* key, int key_size) {
    HASH_ALGORITHM = algorithm;
    KEY_SIZE = key_size;
    IV_SIZE = key_size;
    CLIENTKEY = key;
    return 0;
}

uint32_t getKey(uint8_t *skey, uint32_t skey_len, uint8_t *siv, uint32_t siv_len) {

    uint32_t err, sealed_sdata_len_in, sdata_len = skey_len + siv_len;
    uint32_t sealed_sdata_len = sgx_calc_sealed_data_size(0, sdata_len);
    uint8_t *sealed_sdata     = (uint8_t*) malloc(sizeof(uint8_t) * sealed_sdata_len);
    uint8_t *sdata            = (uint8_t*) malloc(sizeof(uint8_t) * sdata_len);

    // check if exists
    if (load_sdata(&err, sealed_sdata, sealed_sdata_len, &sealed_sdata_len_in))
        return SGX_ERROR_UNEXPECTED;
    
    // if !exist
    if (err != 0) {
        // printf("<T> Generating a new server key...\n");

        // generate random key
        memset(skey, 0, skey_len);
        err = sgx_read_rand(skey, skey_len);
        if (err != SGX_SUCCESS) usgx_exit(err);

        // generate random iv
        memset(siv, 0, siv_len);
        err = sgx_read_rand(siv, siv_len);
        if (err != SGX_SUCCESS) usgx_exit(err);

        // concatenate skey + siv
        memcpy(sdata, skey, skey_len);
        memcpy(sdata + skey_len, siv, siv_len);

        // seal server data
        seal(sdata, sdata_len, sealed_sdata);

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
        unseal(sealed_sdata, sdata, sdata_len);

        memcpy(skey, sdata, skey_len);
        memcpy(siv, sdata + skey_len, siv_len);
    }
    free(sdata);
    free(sealed_sdata);
    return EXIT_SUCCESS;
}

/**
 * Get digest length:
 *   return digest length if success, -1 if fail 
 */
int get_digest_length(int algorithm) {
    int res = -1;
    switch(algorithm) {
        case HASH_MD5:
            res = md5_get_digest_length();
            break;
        case HASH_SHA256:
            res = sha256_get_digest_length();
            break;   
        default:
            break;  
    }
    // printf("<T> digest_length: %d\n", res);
    return res;
}

/*
 * Compute Hash (init, update, final):
 *   Return 0 -> success, -1 fail
 */
int trusted_compute_hash(int algorithm, uint8_t *data, size_t data_size, uint8_t *digest, size_t digest_size) {    
    int res = 0;
    unsigned char *tmp = (unsigned char*) malloc (sizeof(unsigned char) * digest_size);
    MD5_CTX context_md5;
    SHA256_CTX context_sha256;

    switch(algorithm) {
        case HASH_MD5:        
            res += md5_init(&context_md5);   
            res += md5_update(&context_md5, (const char*) data, data_size);
            res += md5_final(&context_md5, tmp);       
            break;
        case HASH_SHA256:
            res += sha256_init(&context_sha256);
            res += sha256_update(&context_sha256, (const char*) data, data_size);
            res += sha256_final(&context_sha256, tmp);  
            break;     
        default : 
            // printf("<T> Unrecognized hash hash_type\n");
            return -1;
    }
    memcpy(digest, tmp, digest_size);
    // print_digest(digest, digest_size);
    free(tmp);
    return res;
}

/*
 * Encode function:
 *   Unseal file, encode file to client
 */
int trusted_encode(uint8_t *iv, size_t iv_len, \
                   uint8_t *dest, size_t dest_size, \
                   const uint8_t* src, size_t src_size) {

    unsigned char *plaintext, *ciphertext;
    int plaintext_size, ciphertext_size;
    uint8_t server_key[KEY_SIZE];
    uint8_t server_iv[IV_SIZE];                

    // *****************************
    // Decode data with server key
    plaintext = (unsigned char*) malloc(sizeof(unsigned char) * src_size);
    if (getKey(server_key, KEY_SIZE, server_iv, IV_SIZE) != EXIT_SUCCESS) printf("<T> getKey error!\n");
    if (openssl_init((char*) server_key, KEY_SIZE) != EXIT_SUCCESS) printf("<T> openssl init error!\n");
    plaintext_size = openssl_decode(server_iv, plaintext, src, src_size); 

    // *****************************
    // Encode data with client key
    ciphertext = (unsigned char*) malloc (sizeof(unsigned char*) * dest_size);
    if (openssl_init(CLIENTKEY, KEY_SIZE) != EXIT_SUCCESS) printf("<T> openssl init error!\n");
    ciphertext_size = openssl_encode(iv, ciphertext, plaintext, plaintext_size);    

    memcpy(dest, ciphertext, ciphertext_size);
    free(plaintext);
    free(ciphertext);

    return ciphertext_size;
}

/*
 * Decode function:
 *   Decrypt file from client, compute hash, seal file
 */
int trusted_decode(uint8_t *iv, size_t iv_len, \
                   uint8_t *dest, size_t dest_size, \
                   uint8_t *digest, size_t digest_size, \
                   const uint8_t* src, size_t src_size) {

    unsigned char *plaintext, *ciphertext, *aux_digest;
    int plaintext_size, ciphertext_size;
    uint8_t server_key[KEY_SIZE];
    uint8_t server_iv[IV_SIZE];

    // *****************************
    // Decode data with client key
    plaintext = (unsigned char*) malloc(sizeof(unsigned char) * src_size);
    if (openssl_init(CLIENTKEY, KEY_SIZE) != EXIT_SUCCESS) printf("<T> openssl init error!\n");
    plaintext_size = openssl_decode(iv, plaintext, src, src_size);     
    
    // *****************************
    // Compute hash
    aux_digest = (unsigned char*) malloc (sizeof(unsigned char) * digest_size);
    if (trusted_compute_hash(HASH_ALGORITHM, plaintext, plaintext_size, aux_digest, digest_size) != EXIT_SUCCESS) printf("<T> compute_hash error!\n");
    // print_digest(aux_digest, digest_size);    

    // *****************************
    // Encode data with server key
    ciphertext = (unsigned char*) malloc (sizeof(unsigned char*) * dest_size);
    if (getKey(server_key, KEY_SIZE, server_iv, IV_SIZE) != EXIT_SUCCESS) printf("<T> getKey error!\n");
    if (openssl_init((char*) server_key, KEY_SIZE) != EXIT_SUCCESS) printf("<T> openssl init error!\n");
    ciphertext_size = openssl_encode(server_iv, ciphertext, plaintext, plaintext_size);
    openssl_clean();
    memcpy(digest, aux_digest, digest_size);
    memcpy(dest, ciphertext, ciphertext_size);
    free(aux_digest);
    free(plaintext);
    free(ciphertext);    

    return ciphertext_size;
}

int trusted_reencrypt(uint8_t *iv, size_t iv_len, \
                   uint8_t *dest, size_t dest_size, \
                   const uint8_t* src, size_t src_size) {

    unsigned char *plaintext, *ciphertext;
    int plaintext_size, ciphertext_size;
    uint8_t server_key[KEY_SIZE];
    uint8_t server_iv[IV_SIZE];

    // *****************************
    // Decode data with client key
    plaintext = (unsigned char*) malloc(sizeof(unsigned char) * src_size);
    if (openssl_init(CLIENTKEY, KEY_SIZE) != EXIT_SUCCESS) printf("<T> openssl init error!\n");
    plaintext_size = openssl_decode(iv, plaintext, src, src_size);     
    
    // *****************************
    // Encode data with server key
    ciphertext = (unsigned char*) malloc (sizeof(unsigned char*) * dest_size);
    if (getKey(server_key, KEY_SIZE, server_iv, IV_SIZE) != EXIT_SUCCESS) printf("<T> getKey error!\n");
    if (openssl_init((char*) server_key, KEY_SIZE) != EXIT_SUCCESS) printf("<T> openssl init error!\n");
    ciphertext_size = openssl_encode(server_iv, ciphertext, plaintext, plaintext_size);
    openssl_clean();
    memcpy(dest, ciphertext, ciphertext_size);
    free(plaintext);
    free(ciphertext);    

    return ciphertext_size;
}