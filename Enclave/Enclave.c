#include "sgx_trts.h"
#include "sgx_tseal.h"
#include "sgx_utils.h"
#include "tSgxSSL_api.h"

#include "Enclave.h"
#include "Enclave_t.h"

#include <unistd.h> 
#include <stdio.h>
#include <string.h>

#include <openssl/sha.h>
#include "symmetric.h"
#include "auth_encryption.h"

int IV_SIZE;
int MAC_SIZE;
int KEY_SIZE;
unsigned char *CLIENT_KEY;
unsigned char *SERVER_KEY;

int MAX_OPS;
int N_OPS;
int epoch_rnd_size = 32;
unsigned char *epoch_rnd;

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

void exit_error(const char *fmt, ...) {
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    usgx_exit_error(buf);
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
        if (err != SGX_SUCCESS) { printf("sgx_read_rand\n"); usgx_exit("sgx_read_rand", err);}

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

void getEpochKey(unsigned char *msg, int msg_size, unsigned char *epoch_key) {    
    sgx_status_t err;
    if (N_OPS == 0 || N_OPS >= MAX_OPS) {
        // printf("<T> new epoch!! %d\n", N_OPS);
        err = sgx_read_rand(epoch_rnd, epoch_rnd_size);
        if (err != SGX_SUCCESS) usgx_exit("sgx_read_rand", err);
        N_OPS = 0;
    } 
    N_OPS++;
    unsigned int epoch_si=0;
    HMAC(EVP_sha256(), epoch_rnd, epoch_rnd_size, msg, msg_size, epoch_key, &epoch_si);
}

void trusted_init(unsigned char* client_key, int key_size, int iv_size, int tag_size, int ops) {
    // printf("<T> TRUSTED INIT\n");
    N_OPS = 0;
    MAX_OPS = ops;    
    KEY_SIZE = key_size;
    IV_SIZE = iv_size;
    MAC_SIZE = tag_size;
    CLIENT_KEY = (unsigned char*) malloc (sizeof(unsigned char) * KEY_SIZE);
    epoch_rnd = (unsigned char*) malloc (sizeof(unsigned char) * epoch_rnd_size);
    memcpy(CLIENT_KEY, client_key, KEY_SIZE);
    auth_init(key_size, iv_size, tag_size, 1);
    if (getKey() != EXIT_SUCCESS) exit_error("<T> getKey error!\n");
}

int encode(unsigned char* key, uint8_t *iv, uint8_t *mac, uint8_t *dest, uint8_t* src, size_t src_size) {

    int res;
    
    res = auth_encode(key, iv, dest, src, src_size, mac);
    if (res <= 0) exit_error("<T> Encode Error -> auth_encode return %d\n", res);

    if (dest == NULL) exit_error("<T> Encode Error -> ciphertext = NULL\n");

    return res;
}

int decode(unsigned char* key, uint8_t *iv, uint8_t *mac, uint8_t *dest, uint8_t* src, size_t src_size) {

    int res;

    res = auth_decode(key, iv, dest, src, src_size, mac);
    if (res <= 0) exit_error("<T> Decode Error -> auth_decode return %d\n", res);

    return res;
}

int trusted_encode(unsigned char* key, int key_size, uint8_t *dest, size_t dest_size, uint8_t* src, size_t src_size) {

    sgx_status_t err;
    int ciphertext_size = src_size + IV_SIZE + MAC_SIZE;
    unsigned char *ciphertext, *iv, *mac;

    ciphertext = (unsigned char*) malloc(sizeof(unsigned char) * ciphertext_size);
    iv = (unsigned char*) malloc(sizeof(unsigned char) * IV_SIZE);
    mac = (unsigned char*) malloc(sizeof(unsigned char) * MAC_SIZE);

    err = sgx_read_rand(iv, IV_SIZE);
    if (err != SGX_SUCCESS) { usgx_exit("sgx_read_rand", err); }


    ciphertext_size = encode(key, iv, mac, ciphertext, src, src_size);

    memcpy(dest, ciphertext, ciphertext_size);
    memcpy(&dest[ciphertext_size], iv, IV_SIZE);
    memcpy(&dest[ciphertext_size+IV_SIZE], mac, MAC_SIZE);

    free(ciphertext);
    free(iv);
    free(mac);

    return ciphertext_size + IV_SIZE + MAC_SIZE;

}

int trusted_decode(unsigned char* key, int key_size, uint8_t *dest, size_t dest_size, uint8_t* src, size_t src_size) {
    
    int plaintext_size = src_size - IV_SIZE - MAC_SIZE;
    unsigned char *plaintext;
    
    plaintext = (unsigned char*) malloc(sizeof(unsigned char) * plaintext_size);
    plaintext_size = decode(key, &src[plaintext_size], &src[plaintext_size+IV_SIZE], plaintext, src, plaintext_size);
    if (plaintext_size < 0) return -1;

    memcpy(dest, plaintext, plaintext_size);

    free(plaintext);

    return plaintext_size;
}

/*
 * Compute Hash (init, update, final):
 *   Return 0 -> success, -1 fail
 */
int trusted_compute_hash(uint8_t *data, size_t data_size, uint8_t *digest, size_t digest_size) {    

    SHA256_CTX context;

    if (SHA256_Init(&context) != 1) return EXIT_FAILURE;
    if (SHA256_Update(&context, data, data_size) != 1) return EXIT_FAILURE;
    if (SHA256_Final(digest, &context) != 1) return EXIT_FAILURE;

    return EXIT_SUCCESS;
}

/*
 * Reencrypt function:
 *   Decrypt data with client key and encrypt with server key
 */
int trusted_reencrypt(uint8_t *dest, size_t dest_size, uint8_t* src, size_t src_size) {

    sgx_status_t err;
    unsigned char *plaintext, *ciphertext, *iv_out, *p_out_mac;
    int plaintext_size, ciphertext_size;

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
    free(p_out_mac);
    free(iv_out);

    return ciphertext_size + IV_SIZE + MAC_SIZE;
}

/*
 * Reencrypt function:
 *   Decrypt data with client key, compute hash and encrypt with server key
 */
int trusted_reencrypt_hash_epoch(uint8_t *dest, size_t dest_size, uint8_t *digest, size_t digest_size, uint8_t* src, size_t src_size) {

    sgx_status_t err;
    unsigned char *plaintext, *ciphertext, *aux_digest, *iv_out, *p_out_mac, *det_key, *det_iv, *det_ciphertext;
    int plaintext_size, ciphertext_size, det_ciphertext_size;

    // *****************************
    // Decode data with client key
    plaintext_size = src_size - IV_SIZE - MAC_SIZE;
    plaintext = (unsigned char*) malloc(sizeof(unsigned char) * plaintext_size);
    plaintext_size = decode(CLIENT_KEY, &src[plaintext_size], &src[plaintext_size+IV_SIZE], plaintext, src, plaintext_size);

    // *****************************
    // Encode CGM DET
    det_key = (unsigned char*) malloc(sizeof(unsigned char) * KEY_SIZE);
    getEpochKey(plaintext, plaintext_size, det_key);
    det_iv = (unsigned char*) malloc (sizeof(unsigned char*) * IV_SIZE);  
    memset(det_iv, '0', IV_SIZE);

    det_ciphertext = (unsigned char*) malloc (sizeof(unsigned char*) * src_size);
    p_out_mac  = (unsigned char*) malloc (sizeof(unsigned char*) * (MAC_SIZE));
    det_ciphertext_size = encode(det_key, det_iv, p_out_mac, det_ciphertext, plaintext, plaintext_size); 

    memcpy(&det_ciphertext[det_ciphertext_size], det_iv, IV_SIZE);
    memcpy(&det_ciphertext[det_ciphertext_size+IV_SIZE], p_out_mac, MAC_SIZE);
    // *****************************
    // Compute hash
    aux_digest = (unsigned char*) malloc (sizeof(unsigned char) * digest_size);
    if (trusted_compute_hash(det_ciphertext, det_ciphertext_size+IV_SIZE+MAC_SIZE, aux_digest, digest_size) != EXIT_SUCCESS) printf("<T> compute_hash error!\n");
    
    // *****************************
    // Encode data with server key
    ciphertext = (unsigned char*) malloc (sizeof(unsigned char*) * src_size);
    iv_out     = (unsigned char*) malloc (sizeof(unsigned char*) * IV_SIZE);
    err = sgx_read_rand(iv_out, IV_SIZE);
    if (err != SGX_SUCCESS) usgx_exit("sgx_read_rand", err);
    ciphertext_size = encode(SERVER_KEY, iv_out, p_out_mac, ciphertext, plaintext, plaintext_size); 

    memcpy(digest, aux_digest, digest_size);

    memcpy(dest, ciphertext, ciphertext_size);
    memcpy(&dest[ciphertext_size], iv_out, IV_SIZE);
    memcpy(&dest[ciphertext_size+IV_SIZE], p_out_mac, MAC_SIZE);
    free(plaintext);
    free(ciphertext);
    free(aux_digest);
    free(p_out_mac);
    free(iv_out);
    free(det_iv);
    free(det_key);
    free(det_ciphertext);

    // printf("<T> trusted_dedup_encode_and_hash return %d\n", ciphertext_size + IV_SIZE + MAC_SIZE);

    return ciphertext_size + IV_SIZE + MAC_SIZE;
}

/*
 * Reencrypt function:
 *   Decrypt data with client key and compute hash 
 */
int trusted_decrypt_hash_epoch(uint8_t *dest, size_t dest_size, uint8_t *digest, size_t digest_size, uint8_t* src, size_t src_size) {

    unsigned char *plaintext, *aux_digest, *p_out_mac, *det_key, *det_iv, *det_ciphertext;
    int plaintext_size, det_ciphertext_size;

    // *****************************
    // Decode data with client key
    plaintext_size = src_size - IV_SIZE - MAC_SIZE;
    plaintext = (unsigned char*) malloc(sizeof(unsigned char) * plaintext_size);
    plaintext_size = decode(CLIENT_KEY, &src[plaintext_size], &src[plaintext_size+IV_SIZE], plaintext, src, plaintext_size);

    // *****************************
    // Encode CGM DET
    det_key = (unsigned char*) malloc(sizeof(unsigned char) * KEY_SIZE);
    getEpochKey(plaintext, plaintext_size, det_key);
    det_iv = (unsigned char*) malloc (sizeof(unsigned char*) * IV_SIZE);  
    memset(det_iv, '0', IV_SIZE);

    det_ciphertext = (unsigned char*) malloc (sizeof(unsigned char*) * src_size);
    p_out_mac  = (unsigned char*) malloc (sizeof(unsigned char*) * (MAC_SIZE));
    det_ciphertext_size = encode(det_key, det_iv, p_out_mac, det_ciphertext, plaintext, plaintext_size); 

    memcpy(&det_ciphertext[det_ciphertext_size], det_iv, IV_SIZE);
    memcpy(&det_ciphertext[det_ciphertext_size+IV_SIZE], p_out_mac, MAC_SIZE);
    // *****************************
    // Compute hash
    aux_digest = (unsigned char*) malloc (sizeof(unsigned char) * digest_size);
    if (trusted_compute_hash(det_ciphertext, det_ciphertext_size+IV_SIZE+MAC_SIZE, aux_digest, digest_size) != EXIT_SUCCESS) printf("<T> compute_hash error!\n");
    
    memcpy(digest, aux_digest, digest_size);

    free(plaintext);
    free(aux_digest);
    free(p_out_mac);
    free(det_iv);
    free(det_key);
    free(det_ciphertext);

    return src_size;
}

int check_integrity(uint8_t* plaintext, size_t plaintext_size, uint8_t *ciphertext, size_t ciphertext_size) {

    unsigned char *aux_plaintext;
    int aux_plaintext_size, integrity = EXIT_FAILURE;

    // *****************************
    // Decode data with server key
    aux_plaintext_size = ciphertext_size - IV_SIZE - MAC_SIZE;
    aux_plaintext = (unsigned char*) malloc(sizeof(unsigned char) * aux_plaintext_size);
    aux_plaintext_size = decode(SERVER_KEY, &ciphertext[aux_plaintext_size], &ciphertext[aux_plaintext_size+IV_SIZE], aux_plaintext, ciphertext, aux_plaintext_size);
    
    // *****************************
    // Compare aux_plaintext with plaintext
    if (aux_plaintext_size == plaintext_size && (memcmp(plaintext, aux_plaintext, plaintext_size) == 0))
        integrity = EXIT_SUCCESS;

    free(aux_plaintext);
    return integrity;
}