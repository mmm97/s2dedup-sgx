#include "openssl_impl.h"

int N_OPS;
int MAX_OPS;
int IV_SIZE;
int MAC_SIZE;
int KEY_SIZE;
int EPOCH_KEY_SIZE;
unsigned char *CLIENT_KEY;
unsigned char *SERVER_KEY;
unsigned char *EPOCH_KEY;

void init_u_openssl(char* client_key, int key_size, int iv_size, int mac_size, int operation_mode, int ops) {            
    N_OPS           = 0;
    MAX_OPS         = ops;
    IV_SIZE         = iv_size;
    MAC_SIZE        = mac_size;
    KEY_SIZE        = key_size;    
    EPOCH_KEY_SIZE  = key_size; 

    CLIENT_KEY      = (unsigned char*) malloc (sizeof(unsigned char) * KEY_SIZE);
    // SERVER_KEY      = (unsigned char*) malloc (sizeof(unsigned char) * KEY_SIZE);
    // EPOCH_KEY       = (unsigned char*) malloc (sizeof(unsigned char) * EPOCH_KEY_SIZE);

    memcpy(CLIENT_KEY, client_key, KEY_SIZE);
    auth_init(KEY_SIZE, IV_SIZE, MAC_SIZE, operation_mode);
    SERVER_KEY = openssl_rand_str(KEY_SIZE);
}

void clear_u_openssl() {    
    free(EPOCH_KEY);
    free(CLIENT_KEY);
    free(SERVER_KEY);
}

unsigned int compute_epoch_hash(unsigned char *msg, int msg_size, unsigned char *hash) {    
    unsigned int hash_size;

    if (N_OPS == 0 || N_OPS >= MAX_OPS) {        
        EPOCH_KEY = openssl_rand_str(EPOCH_KEY_SIZE);        
        N_OPS = 0;
    } 
    N_OPS++;

    HMAC(EVP_sha256(), EPOCH_KEY, EPOCH_KEY_SIZE, msg, msg_size, hash, &hash_size);   
    return hash_size;
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

int encode(uint8_t *dest, size_t dest_size, uint8_t* src, size_t src_size) {

    int ciphertext_size = src_size + IV_SIZE + MAC_SIZE;
    unsigned char *ciphertext, *iv, *mac;

    ciphertext = (unsigned char*) malloc(sizeof(unsigned char) * ciphertext_size);
    // iv = (unsigned char*) malloc(sizeof(unsigned char) * IV_SIZE);
    mac = (unsigned char*) malloc(sizeof(unsigned char) * MAC_SIZE);

    iv = openssl_rand_str(IV_SIZE);
    
    ciphertext_size = _encode(CLIENT_KEY, iv, mac, ciphertext, src, src_size);

    memcpy(dest, ciphertext, ciphertext_size);
    memcpy(&dest[ciphertext_size], iv, IV_SIZE);
    memcpy(&dest[ciphertext_size+IV_SIZE], mac, MAC_SIZE);

    free(ciphertext);
    free(iv);
    free(mac);

    return ciphertext_size + IV_SIZE + MAC_SIZE;
}


int decode(uint8_t *dest, size_t dest_size, uint8_t* src, size_t src_size) {
    
    int plaintext_size = src_size - IV_SIZE - MAC_SIZE;
    unsigned char* plaintext;
    
    plaintext = (unsigned char*) malloc(sizeof(unsigned char) * plaintext_size);
    
    plaintext_size = _decode(SERVER_KEY, &src[plaintext_size], &src[plaintext_size+IV_SIZE], plaintext, src, plaintext_size);
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
 *   Decrypt data with client key and compute hash 
 */
int decrypt_hash_epoch(uint8_t *digest, size_t digest_size, uint8_t* src, size_t src_size) {

    int plaintext_size, aux_digest_size;
    unsigned char *plaintext;

    // *****************************
    // Decode data with client key
    plaintext_size = src_size - IV_SIZE - MAC_SIZE;
    plaintext = (unsigned char*) malloc(sizeof(unsigned char) * plaintext_size);
    plaintext_size = _decode(CLIENT_KEY, &src[plaintext_size], &src[plaintext_size+IV_SIZE], plaintext, src, plaintext_size);

    // *****************************
    // Compute hash    
    aux_digest_size = compute_epoch_hash(plaintext, plaintext_size, digest);    
    if (aux_digest_size != digest_size) { printf("compute_hash error: wrong digest size %d", aux_digest_size); exit(EXIT_FAILURE); }

    free(plaintext);
    return aux_digest_size;
}
