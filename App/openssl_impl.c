#include "openssl_impl.h"

int IV_SIZE;
int MAC_SIZE;
int KEY_SIZE;
unsigned char *CLIENT_KEY;
unsigned char *SERVER_KEY;

int MAX_OPS;
int N_OPS;
int epoch_rnd_size = 32;
unsigned char *epoch_rnd;

void init_u_openssl(unsigned char* client_key, int key_size, int iv_size, int tag_size, int ops) {    
    N_OPS = 0;
    MAX_OPS = ops;    
    KEY_SIZE = key_size;
    IV_SIZE = iv_size;
    MAC_SIZE = tag_size;
    CLIENT_KEY = (unsigned char*) malloc (sizeof(unsigned char) * KEY_SIZE);
    SERVER_KEY = (unsigned char*) malloc (sizeof(unsigned char) * KEY_SIZE);
    epoch_rnd = (unsigned char*) malloc (sizeof(unsigned char) * epoch_rnd_size);
    memcpy(CLIENT_KEY, client_key, KEY_SIZE);
    auth_init(key_size, iv_size, tag_size, 1);

    SERVER_KEY = openssl_rand_str(KEY_SIZE);
}

void getEpochKey(unsigned char *msg, int msg_size, unsigned char *epoch_key) {        
    if (N_OPS == 0 || N_OPS >= MAX_OPS) {
        epoch_rnd = openssl_rand_str(epoch_rnd_size);
        N_OPS = 0;
    } 
    N_OPS++;
    unsigned int epoch_si=0;
    HMAC(EVP_sha256(), epoch_rnd, epoch_rnd_size, msg, msg_size, epoch_key, &epoch_si);
}

int compute_hash(unsigned char *src, int src_len, unsigned char *digest, int digest_len) {
    SHA256_CTX context;

    if (SHA256_Init(&context) != 1) return EXIT_FAILURE;
    if (SHA256_Update(&context, src, src_len) != 1) return EXIT_FAILURE;
    if (SHA256_Final(digest, &context) != 1) return EXIT_FAILURE;

    return EXIT_SUCCESS;
}

int _encode(unsigned char* key, uint8_t *iv, uint8_t *mac, uint8_t *dest, uint8_t* src, size_t src_size) {

    int res;
    
    res = auth_encode(key, iv, dest, src, src_size, mac);
    if (res <= 0) printf("<T> Encode Error -> auth_encode return %d\n", res);

    if (dest == NULL) printf("<T> Encode Error -> ciphertext = NULL\n");

    return res;
}

int _decode(unsigned char* key, uint8_t *iv, uint8_t *mac, uint8_t *dest, uint8_t* src, size_t src_size) {

    int res;

    res = auth_decode(key, iv, dest, src, src_size, mac);
    if (res <= 0) printf("<T> Decode Error -> auth_decode return %d\n", res);

    return res;
}

int encode(unsigned char* key, int key_size, uint8_t *dest, size_t dest_size, uint8_t* src, size_t src_size) {

    int ciphertext_size = src_size + IV_SIZE + MAC_SIZE;
    unsigned char *ciphertext, *iv, *mac;

    ciphertext = (unsigned char*) malloc(sizeof(unsigned char) * ciphertext_size);
    iv = (unsigned char*) malloc(sizeof(unsigned char) * IV_SIZE);
    mac = (unsigned char*) malloc(sizeof(unsigned char) * MAC_SIZE);

    iv = openssl_rand_str(IV_SIZE);
    
    ciphertext_size = _encode(key, iv, mac, ciphertext, src, src_size);

    memcpy(dest, ciphertext, ciphertext_size);
    memcpy(&dest[ciphertext_size], iv, IV_SIZE);
    memcpy(&dest[ciphertext_size+IV_SIZE], mac, MAC_SIZE);

    free(ciphertext);
    free(iv);
    free(mac);

    return ciphertext_size + IV_SIZE + MAC_SIZE;
}


int decode(unsigned char* key, int key_size, uint8_t *dest, size_t dest_size, uint8_t* src, size_t src_size) {
    
    int plaintext_size = src_size - IV_SIZE - MAC_SIZE;
    unsigned char* plaintext;
    
    plaintext = (unsigned char*) malloc(sizeof(unsigned char) * plaintext_size);
    
    plaintext_size = _decode(key, &src[plaintext_size], &src[plaintext_size+IV_SIZE], plaintext, src, plaintext_size);
    if (plaintext_size < 0) return -1;

    memcpy(dest, plaintext, plaintext_size);

    free(plaintext);

    return plaintext_size;
}
/*
 * Reencrypt function:
 *   Decrypt data with client key and encrypt with server key
 */
int reencrypt(uint8_t *dest, size_t dest_size, uint8_t* src, size_t src_size) {

    unsigned char *plaintext, *ciphertext, *iv_out, *p_out_mac;
    int plaintext_size, ciphertext_size;

    // *****************************
    // Decode data with client key
    plaintext_size = src_size - IV_SIZE - MAC_SIZE;
    plaintext = (unsigned char*) malloc(sizeof(unsigned char) * plaintext_size);
    plaintext_size = _decode(CLIENT_KEY, &src[plaintext_size], &src[plaintext_size+IV_SIZE], plaintext, src, plaintext_size);

    // *****************************
    // Encode data with server key
    ciphertext = (unsigned char*) malloc (sizeof(unsigned char*) * src_size);
    iv_out     = (unsigned char*) malloc (sizeof(unsigned char*) * IV_SIZE);
    p_out_mac  = (unsigned char*) malloc (sizeof(unsigned char*) * MAC_SIZE);

    iv_out = openssl_rand_str(IV_SIZE);

    ciphertext_size = _encode(SERVER_KEY, iv_out, p_out_mac, ciphertext, plaintext, plaintext_size); 
    
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
int reencrypt_hash_epoch(uint8_t *dest, size_t dest_size, uint8_t *digest, size_t digest_size, uint8_t* src, size_t src_size) {

    unsigned char *plaintext, *ciphertext, *aux_digest, *iv_out, *p_out_mac, *det_key, *det_iv, *det_ciphertext;
    int plaintext_size, ciphertext_size, det_ciphertext_size;

    // *****************************
    // Decode data with client key
    plaintext_size = src_size - IV_SIZE - MAC_SIZE;
    plaintext = (unsigned char*) malloc(sizeof(unsigned char) * plaintext_size);
    plaintext_size = _decode(CLIENT_KEY, &src[plaintext_size], &src[plaintext_size+IV_SIZE], plaintext, src, plaintext_size);
    
    // *****************************
    // Encode CGM DET
    det_key = (unsigned char*) malloc(sizeof(unsigned char) * KEY_SIZE);
    getEpochKey(plaintext, plaintext_size, det_key);
    det_iv = (unsigned char*) malloc (sizeof(unsigned char*) * IV_SIZE);  
    memset(det_iv, '0', IV_SIZE);

    det_ciphertext = (unsigned char*) malloc (sizeof(unsigned char*) * src_size);
    p_out_mac  = (unsigned char*) malloc (sizeof(unsigned char*) * (MAC_SIZE));
    det_ciphertext_size = _encode(det_key, det_iv, p_out_mac, det_ciphertext, plaintext, plaintext_size); 

    memcpy(&det_ciphertext[det_ciphertext_size], det_iv, IV_SIZE);
    memcpy(&det_ciphertext[det_ciphertext_size+IV_SIZE], p_out_mac, MAC_SIZE);

    // *****************************
    // Compute hash
    aux_digest = (unsigned char*) malloc (sizeof(unsigned char) * digest_size);
    if (compute_hash(det_ciphertext, det_ciphertext_size+IV_SIZE+MAC_SIZE, aux_digest, digest_size) != EXIT_SUCCESS) printf("<T> compute_hash error!\n");
    
    // *****************************
    // Encode data with server key
    ciphertext = (unsigned char*) malloc (sizeof(unsigned char*) * src_size);
    iv_out     = (unsigned char*) malloc (sizeof(unsigned char*) * IV_SIZE);
    
    iv_out = openssl_rand_str(IV_SIZE);

    ciphertext_size = _encode(SERVER_KEY, iv_out, p_out_mac, ciphertext, plaintext, plaintext_size);            

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

    return ciphertext_size + IV_SIZE + MAC_SIZE;
}

/*
 * Reencrypt function:
 *   Decrypt data with client key and compute hash 
 */
int decrypt_hash_epoch(uint8_t *dest, size_t dest_size, uint8_t *digest, size_t digest_size, uint8_t* src, size_t src_size) {

    unsigned char *plaintext, *aux_digest, *p_out_mac, *det_key, *det_iv, *det_ciphertext;
    int plaintext_size, det_ciphertext_size;

    // *****************************
    // Decode data with client key
    plaintext_size = src_size - IV_SIZE - MAC_SIZE;
    plaintext = (unsigned char*) malloc(sizeof(unsigned char) * plaintext_size);
    plaintext_size = _decode(CLIENT_KEY, &src[plaintext_size], &src[plaintext_size+IV_SIZE], plaintext, src, plaintext_size);

    // *****************************
    // Encode CGM DET
    det_key = (unsigned char*) malloc(sizeof(unsigned char) * KEY_SIZE);
    getEpochKey(plaintext, plaintext_size, det_key);
    det_iv = (unsigned char*) malloc (sizeof(unsigned char*) * IV_SIZE);  
    memset(det_iv, '0', IV_SIZE);

    det_ciphertext = (unsigned char*) malloc (sizeof(unsigned char*) * src_size);
    p_out_mac  = (unsigned char*) malloc (sizeof(unsigned char*) * (MAC_SIZE));
    det_ciphertext_size = _encode(det_key, det_iv, p_out_mac, det_ciphertext, plaintext, plaintext_size); 

    memcpy(&det_ciphertext[det_ciphertext_size], det_iv, IV_SIZE);
    memcpy(&det_ciphertext[det_ciphertext_size+IV_SIZE], p_out_mac, MAC_SIZE);
    
    // *****************************
    // Compute hash
    aux_digest = (unsigned char*) malloc (sizeof(unsigned char) * digest_size);
    if (compute_hash(det_ciphertext, det_ciphertext_size+IV_SIZE+MAC_SIZE, aux_digest, digest_size) != EXIT_SUCCESS) printf("<T> compute_hash error!\n");
    
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
    aux_plaintext_size = _decode(SERVER_KEY, &ciphertext[aux_plaintext_size], &ciphertext[aux_plaintext_size+IV_SIZE], aux_plaintext, ciphertext, aux_plaintext_size);
    
    // *****************************
    // Compare aux_plaintext with plaintext
    if (aux_plaintext_size == plaintext_size && (memcmp(plaintext, aux_plaintext, plaintext_size) == 0))
        integrity = EXIT_SUCCESS;

    free(aux_plaintext);
    return integrity;
}