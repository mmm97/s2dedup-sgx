#include "openssl_impl.h"

#define MAC_SIZE 16
#define KEY_SIZE 16
#define IV_SIZE  12

unsigned char *SERVER_KEY;
unsigned char *CLIENT_KEY;

void init_u_openssl(unsigned char* key, int key_size) {
    if (key_size != KEY_SIZE) { printf("Invalid Key size\n"); return; }
    
    CLIENT_KEY = key;
    SERVER_KEY = (unsigned char*) "123456798132456";
}


int compute_hash(unsigned char *src, int src_len, unsigned char *digest, int digest_len) {
    SHA256_CTX context;

    if (SHA256_Init(&context) != 1) return EXIT_FAILURE;
    if (SHA256_Update(&context, src, src_len) != 1) return EXIT_FAILURE;
    if (SHA256_Final(digest, &context) != 1) return EXIT_FAILURE;

    return EXIT_SUCCESS;
}

int _encode(unsigned char* key, int key_size, uint8_t *iv, size_t iv_size, uint8_t *mac, size_t mac_size, \
           uint8_t *dest, size_t dest_size, uint8_t* src, size_t src_size) {

    int res;

    if (auth_init((char*)key, key_size, iv_size, mac_size, 2) != 0) {
        printf("encode: error auth_init\n");
        return EXIT_FAILURE;
    }
    res = auth_encode(iv, dest, src, src_size, mac);
    
    return res;
}

int _decode(unsigned char* key, int key_size, uint8_t *iv, size_t iv_size, uint8_t *mac, size_t mac_size, \
           uint8_t *dest, size_t dest_size, uint8_t* src, size_t src_size) {

    int res;

    if (auth_init((char*)key, key_size, iv_size, mac_size, 2) != 0) {
        printf("decode: error auth_init\n");
        return EXIT_FAILURE;
    }
    res = auth_decode(iv, dest, src, src_size, mac);
    
    return res;
}

int encode(unsigned char* key, int key_size, uint8_t *dest, size_t dest_size, uint8_t* src, size_t src_size) {

    int ciphertext_size = src_size + IV_SIZE + MAC_SIZE;
    unsigned char *ciphertext, *iv, *mac;

    ciphertext = (unsigned char*) malloc(sizeof(unsigned char) * ciphertext_size);
    iv = (unsigned char*) malloc(sizeof(unsigned char) * IV_SIZE);
    mac = (unsigned char*) malloc(sizeof(unsigned char) * MAC_SIZE);

    iv = openssl_rand_str(IV_SIZE);
    
    ciphertext_size = _encode(key, KEY_SIZE, iv, IV_SIZE, mac, MAC_SIZE, ciphertext, ciphertext_size, src, src_size);

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
    
    plaintext_size = _decode(key, KEY_SIZE, &src[plaintext_size], IV_SIZE, &src[plaintext_size+IV_SIZE], MAC_SIZE, plaintext, plaintext_size, src, plaintext_size);
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

    unsigned char *plaintext, *ciphertext, *p_out_mac;
    int plaintext_size, ciphertext_size;

    // *****************************
    // Decode data with server key
    plaintext_size = src_size - IV_SIZE - MAC_SIZE;
    plaintext = (unsigned char*) malloc(sizeof(unsigned char) * plaintext_size);
    plaintext_size = _decode(CLIENT_KEY, KEY_SIZE, &src[plaintext_size], IV_SIZE, &src[plaintext_size+IV_SIZE], MAC_SIZE, plaintext, plaintext_size, src, plaintext_size);

    // *****************************
    // Encode data with client key
    ciphertext = (unsigned char*) malloc (sizeof(unsigned char*) * dest_size);
    p_out_mac  = (unsigned char*) malloc (sizeof(unsigned char*) * (MAC_SIZE+1));
    ciphertext_size = _encode(SERVER_KEY, KEY_SIZE, &src[plaintext_size], IV_SIZE, p_out_mac, MAC_SIZE, ciphertext, plaintext_size, plaintext, plaintext_size); 

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
int reencrypt_hash(uint8_t *dest, size_t dest_size, uint8_t *digest, size_t digest_size, uint8_t* src, size_t src_size) {

    unsigned char *plaintext, *ciphertext, *aux_digest, *p_out_mac;
    int plaintext_size, ciphertext_size;

    // *****************************
    // Decode data with server key
    plaintext_size = src_size - IV_SIZE - MAC_SIZE;
    plaintext = (unsigned char*) malloc(sizeof(unsigned char) * plaintext_size);
    plaintext_size = _decode(CLIENT_KEY, KEY_SIZE, &src[plaintext_size], IV_SIZE, &src[plaintext_size+IV_SIZE], MAC_SIZE, plaintext, plaintext_size, src, plaintext_size);
    // *****************************
    // Compute Hash
    aux_digest = (unsigned char*) malloc(sizeof(unsigned char) * digest_size);
    compute_hash(plaintext, plaintext_size, aux_digest, digest_size);

    // *****************************
    // Encode data with client key
    ciphertext = (unsigned char*) malloc (sizeof(unsigned char*) * dest_size);
    p_out_mac  = (unsigned char*) malloc (sizeof(unsigned char*) * (MAC_SIZE+1));
    ciphertext_size = _encode(SERVER_KEY, KEY_SIZE, &src[plaintext_size], IV_SIZE, p_out_mac, MAC_SIZE, ciphertext, plaintext_size, plaintext, plaintext_size); 

    memcpy(dest, ciphertext, ciphertext_size);
    memcpy(&dest[ciphertext_size], &src[plaintext_size], IV_SIZE);
    memcpy(&dest[ciphertext_size+IV_SIZE], p_out_mac, MAC_SIZE);
    memcpy(digest, aux_digest, digest_size);
    
    free(plaintext);
    free(ciphertext);
    free(p_out_mac);
    free(aux_digest);

    return ciphertext_size + IV_SIZE + MAC_SIZE;
}