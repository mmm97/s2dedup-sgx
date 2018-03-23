#include "openssl_impl.h"

#define KEY_SIZE 16
#define IV_SIZE  16

char *CLIENT_KEY;
char *SERVER_KEY;

void init_u_openssl(char* key, int key_size) {
    if (key_size != KEY_SIZE) { printf("Invalid Key size\n"); return; }
    
    CLIENT_KEY = key;
    SERVER_KEY = (char*) "123456798132456";
}


int compute_hash(unsigned char *src, int src_len, unsigned char *digest, int digest_len) {
    SHA256_CTX context;

    if (SHA256_Init(&context) != 1) return EXIT_FAILURE;
    if (SHA256_Update(&context, src, src_len) != 1) return EXIT_FAILURE;
    if (SHA256_Final(digest, &context) != 1) return EXIT_FAILURE;

    return EXIT_SUCCESS;
}

int reencrypt(unsigned char *iv, int iv_size, unsigned char *dest, int dest_len, unsigned char *src, int src_len) {

    int plaintext_size, ciphertext_size;
    unsigned char *plaintext, *ciphertext;

    // decrypt from client 
    plaintext = (unsigned char*) malloc (sizeof(unsigned char) * src_len);
    if (openssl_init(CLIENT_KEY, KEY_SIZE) != EXIT_SUCCESS) {printf("<T> openssl init error!\n"); return EXIT_FAILURE;}
    plaintext_size = openssl_decode(iv, plaintext, src, src_len);

    // encrypt with server key
    ciphertext = (unsigned char*) malloc (sizeof(unsigned char) * src_len);
    if (openssl_init(SERVER_KEY, KEY_SIZE) != EXIT_SUCCESS) {printf("<T> openssl init error!\n"); return EXIT_FAILURE;}
    ciphertext_size = openssl_encode(iv, ciphertext, plaintext, plaintext_size);

    memcpy(dest, ciphertext, ciphertext_size);
    free(plaintext);
    free(ciphertext);
    return ciphertext_size;
}

int reencrypt_hash(unsigned char *iv, int iv_size, unsigned char *dest, int dest_len, \
                   unsigned char *src, int src_len, unsigned char *digest, int digest_len) {

    int plaintext_size, ciphertext_size;
    unsigned char *plaintext, *ciphertext, *aux_digest;

    // decrypt from client 
    plaintext = (unsigned char*) malloc (sizeof(unsigned char) * src_len);
    if (openssl_init(CLIENT_KEY, KEY_SIZE) != EXIT_SUCCESS) {printf("<T> openssl init error!\n"); return EXIT_FAILURE;}
    plaintext_size = openssl_decode(iv, plaintext, src, src_len);

    // compute hash
    aux_digest = (unsigned char*) malloc (sizeof(unsigned char) * digest_len);
    compute_hash(plaintext, plaintext_size, aux_digest, digest_len);

    // encrypt with server key
    ciphertext = (unsigned char*) malloc (sizeof(unsigned char) * src_len);
    if (openssl_init(SERVER_KEY, KEY_SIZE) != EXIT_SUCCESS) {printf("<T> openssl init error!\n"); return EXIT_FAILURE;}
    ciphertext_size = openssl_encode(iv, ciphertext, plaintext, plaintext_size);

    memcpy(dest, ciphertext, ciphertext_size);
    memcpy(digest, aux_digest, digest_len);
    free(plaintext);
    free(ciphertext);
    free(aux_digest);
    return ciphertext_size;
}

