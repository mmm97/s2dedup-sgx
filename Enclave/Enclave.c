#include "Enclave.h"

int N_OPS;
int MAX_OPS;
int IV_SIZE;
int MAC_SIZE;
int KEY_SIZE;
int EPOCH_KEY_SIZE;
unsigned char *CLIENT_KEY;
unsigned char *SERVER_KEY;
unsigned char *EPOCH_KEY;

int IV_SIZE;
int MAC_SIZE;
int KEY_SIZE;
unsigned char *CLIENT_KEY;
unsigned char *SERVER_KEY;

int MAX_OPS;
int N_OPS;
int epoch_rnd_size = 32;
unsigned char *epoch_rnd;

uint32_t getKey() {

    uint32_t err, sealed_sdata_len_in;
    uint32_t sealed_sdata_len = getSealedSize(KEY_SIZE);
    uint8_t *sealed_sdata     = (uint8_t*) malloc(sizeof(uint8_t) * sealed_sdata_len);

    // check if exists
    if (load_sdata(&err, sealed_sdata, sealed_sdata_len, &sealed_sdata_len_in))
        return SGX_ERROR_UNEXPECTED;
    
    // if !exist
    if (err != 0) {
        // generate random key
        memset(SERVER_KEY, 0, KEY_SIZE);
        err = sgx_read_rand((unsigned char*)SERVER_KEY, KEY_SIZE);
        if (err != SGX_SUCCESS) { usgx_exit("sgx_read_rand", err);}

        // seal server key
        seal(SERVER_KEY, KEY_SIZE, sealed_sdata);

        // save sealed key
        if (save_sdata(&err, sealed_sdata, sealed_sdata_len))
            return EXIT_FAILURE;
    }
    // if exists
    else {
        // check sealed size
        if (sealed_sdata_len_in != sealed_sdata_len)
            return EXIT_FAILURE;

        // unseal sdata
        unseal(sealed_sdata, SERVER_KEY, KEY_SIZE);
    }
    free(sealed_sdata);
    return EXIT_SUCCESS;
}

void trusted_init_sgx(char* client_key, int key_size, int iv_size, int mac_size, int operation_mode, int ops) {            
    int res;

    N_OPS           = 0;
    MAX_OPS         = ops;
    IV_SIZE         = iv_size;
    MAC_SIZE        = mac_size;
    KEY_SIZE        = key_size;    
    EPOCH_KEY_SIZE  = key_size; 

    CLIENT_KEY      = (unsigned char*) malloc (sizeof(unsigned char) * KEY_SIZE);
    SERVER_KEY      = (unsigned char*) malloc (sizeof(unsigned char) * KEY_SIZE);
    EPOCH_KEY       = (unsigned char*) malloc (sizeof(unsigned char) * EPOCH_KEY_SIZE);

    memcpy(CLIENT_KEY, client_key, KEY_SIZE);
    res = getKey(); if (res != EXIT_SUCCESS) exit_error("<T> getKey error!\n");    
}

void trusted_clear_sgx() {    
    free(EPOCH_KEY);
    free(CLIENT_KEY);
    free(SERVER_KEY);
}

unsigned int compute_epoch_hash(unsigned char *msg, int msg_size, unsigned char *hash) {    
    sgx_status_t err;
    unsigned int hash_size=32;

    if (N_OPS == 0 || N_OPS >= MAX_OPS) {
        err = sgx_read_rand(EPOCH_KEY, EPOCH_KEY_SIZE);
        if (err != SGX_SUCCESS) usgx_exit("sgx_read_rand", err);
        N_OPS = 0;
    } 
    N_OPS++;

    // HMAC(EVP_sha256(), EPOCH_KEY, EPOCH_KEY_SIZE, msg, msg_size, hash, &hash_size);   
    ippsHMAC_Message(msg, msg_size, EPOCH_KEY, EPOCH_KEY_SIZE, hash, hash_size, ippHashAlg_SHA256);

    return hash_size;
}

int encode(unsigned char* key, uint8_t *iv, uint8_t *mac, uint8_t *dest, uint8_t* src, size_t src_size) {
    
    sgx_status_t err;
    
    err = sgx_rijndael128GCM_encrypt((sgx_aes_gcm_128bit_key_t*)key, src, src_size, dest, iv, IV_SIZE, NULL, 0, (sgx_aes_gcm_128bit_tag_t*) mac);
    if (err != SGX_SUCCESS) usgx_exit("sgx_rijndael128GCM_encrypt", err);

    return src_size;
}

int decode(unsigned char* key, uint8_t *iv, uint8_t *mac, uint8_t *dest, uint8_t* src, size_t src_size) {

    sgx_status_t err;
    
    err = sgx_rijndael128GCM_decrypt((sgx_aes_gcm_128bit_key_t*) key, src, src_size, dest, iv, IV_SIZE, NULL, 0, (const sgx_aes_gcm_128bit_tag_t*) mac);
    if (err != SGX_SUCCESS) usgx_exit("sgx_rijndael128GCM_decrypt", err);

    return src_size;
}

int trusted_encode(uint8_t *dest, size_t dest_size, uint8_t* src, size_t src_size) {

    sgx_status_t err;
    int ciphertext_size;

    unsigned char *iv = (unsigned char*) malloc(sizeof(unsigned char) * IV_SIZE);
    unsigned char *ciphertext = (unsigned char*) malloc(sizeof(unsigned char) * src_size);    
    unsigned char *p_out_mac = (unsigned char*) malloc(sizeof(unsigned char) * (MAC_SIZE));

    /* choose random nonce */
    err = sgx_read_rand(iv, IV_SIZE);
    if (err != SGX_SUCCESS) usgx_exit("sgx_read_rand", err);

    ciphertext_size = encode(CLIENT_KEY, iv, p_out_mac, ciphertext, src, src_size);

    memcpy(dest, ciphertext, ciphertext_size);
    memcpy(&dest[ciphertext_size], iv, IV_SIZE);
    memcpy(&dest[ciphertext_size + IV_SIZE], p_out_mac, MAC_SIZE);

    free(ciphertext);
    free(p_out_mac);
    free(iv);

    return ciphertext_size + IV_SIZE + MAC_SIZE;
}

int trusted_decode(uint8_t *dest, size_t dest_size, uint8_t* src, size_t src_size) {
    
    int plaintext_size = src_size - IV_SIZE - MAC_SIZE;
    unsigned char *plaintext;
    
    plaintext = (unsigned char*) malloc(sizeof(unsigned char) * plaintext_size);
    plaintext_size = decode(SERVER_KEY, &src[plaintext_size], &src[plaintext_size+IV_SIZE], plaintext, src, plaintext_size);
    if (plaintext_size < 0) return -1;

    memcpy(dest, plaintext, plaintext_size);

    free(plaintext);

    return plaintext_size;
}

/*
 * Dedup Encode function:
 *   Decrypt file with client key and reencrypt with server key
 */
int trusted_reencrypt(uint8_t *dest, size_t dest_size, uint8_t* src, size_t src_size) {    
    sgx_status_t err;
    int plaintext_size, ciphertext_size;
    unsigned char *plaintext, *ciphertext, *iv_out, *p_out_mac;

    // *****************************
    // Decode data with client key
    plaintext_size = src_size - IV_SIZE - MAC_SIZE;
    plaintext = (unsigned char*) malloc(sizeof(unsigned char) * plaintext_size);
    plaintext_size = decode(CLIENT_KEY, &src[plaintext_size], &src[plaintext_size+IV_SIZE], plaintext, src, plaintext_size);

    // *****************************
    // Encode data with server key
    ciphertext = (unsigned char*) malloc (sizeof(unsigned char*) * src_size);
    iv_out     = (unsigned char*) malloc (sizeof(unsigned char*) * IV_SIZE);
    p_out_mac  = (unsigned char*) malloc (sizeof(unsigned char*) * MAC_SIZE);
    err = sgx_read_rand(iv_out, IV_SIZE);
    if (err != SGX_SUCCESS) usgx_exit("sgx_read_rand", err);
    ciphertext_size = encode(SERVER_KEY, iv_out, p_out_mac, ciphertext, plaintext, plaintext_size); 

    memcpy(dest, ciphertext, ciphertext_size);
    memcpy(&dest[ciphertext_size], iv_out, IV_SIZE);
    memcpy(&dest[ciphertext_size+IV_SIZE], p_out_mac, MAC_SIZE);

    free(plaintext);
    free(ciphertext);
    free(iv_out);
    free(p_out_mac);

    return ciphertext_size + IV_SIZE + MAC_SIZE;
}

/*
 * Dedup hash function:
 *   Decrypt file with client key and compute hash
 */
int trusted_compute_hash(uint8_t *digest, size_t digest_size, uint8_t* src, size_t src_size) {
    int plaintext_size, aux_digest_size;
    unsigned char *plaintext;

    // *****************************
    // Decode data with client key
    plaintext_size = src_size - IV_SIZE - MAC_SIZE;
    plaintext = (unsigned char*) malloc(sizeof(unsigned char) * plaintext_size);
    plaintext_size = decode(CLIENT_KEY, &src[plaintext_size], &src[plaintext_size+IV_SIZE], plaintext, src, plaintext_size);

    // *****************************
    // Compute hash    
    aux_digest_size = compute_epoch_hash(plaintext, plaintext_size, digest);    
    if (aux_digest_size != digest_size) usgx_exit_error("<T> compute_hash error: wrong digest size", aux_digest_size);

    free(plaintext);
    return aux_digest_size;
}