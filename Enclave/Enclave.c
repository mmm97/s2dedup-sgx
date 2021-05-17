
#include "Enclave.h"
#include <stdio.h>
#include <stdlib.h>

int SECURITY_LEVEL;
int N_OPS;
int MAX_OPS;
int T_THRESHOLD;
int TWEAK_SIZE;
int KEY_SIZE;
int EPOCH_KEY_SIZE;
unsigned char *CLIENT_KEY;
unsigned char *SERVER_KEY;
unsigned char *EPOCH_KEY;

struct node {
   unsigned char * hash;
   uint32_t counter;
   struct node *next;
};
typedef struct node *LINKNODE;
LINKNODE* hashtable_exact_counter;
int nbuckets = 65536;

uint64_t **matrix_counter;
int w_counters = 1048576;
int r_counters = 4;

/***********************GET KEY************************/
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

/***********************INIT_ENCLAVE************************/
void trusted_init_sgx(char* client_key, int key_size, int tweak_size, int security_level, int epoch_or_threshold) {            
    int res;

    SECURITY_LEVEL = security_level;
    if (SECURITY_LEVEL == 0){
        MAX_OPS = -1;
    }
    else if (SECURITY_LEVEL == 1){
        MAX_OPS = epoch_or_threshold;
    }
    else if (SECURITY_LEVEL == 2){
        MAX_OPS = -1;
	if (epoch_or_threshold == -1) {
	    T_THRESHOLD = 15;
	}
	else {
	    T_THRESHOLD = epoch_or_threshold;
	}
    }
    else if (SECURITY_LEVEL == 3){
        MAX_OPS = -1;
        if (epoch_or_threshold == -1) {
            T_THRESHOLD = 15;
        }
        else {
            T_THRESHOLD = epoch_or_threshold;
        }    
    }
    else {
    	exit_error("Security level does not exist!\n");
    }

    N_OPS = 0;
    TWEAK_SIZE      = tweak_size;
    KEY_SIZE        = key_size;    
    EPOCH_KEY_SIZE  = key_size; 

    CLIENT_KEY      = (unsigned char*) malloc (sizeof(unsigned char) * KEY_SIZE);
    SERVER_KEY      = (unsigned char*) malloc (sizeof(unsigned char) * KEY_SIZE);
    EPOCH_KEY       = (unsigned char*) malloc (sizeof(unsigned char) * EPOCH_KEY_SIZE);

    matrix_counter = (uint64_t **)malloc(r_counters * sizeof(uint64_t *));
    for(int i=0;i<r_counters;i++)
    {
        matrix_counter[i]=(uint64_t*)malloc(w_counters*sizeof(uint64_t));
        memset(matrix_counter[i], 0 , w_counters * sizeof(uint64_t));
    }

    hashtable_exact_counter = (LINKNODE *)malloc(nbuckets * sizeof(LINKNODE));
    for (int i=0; i<nbuckets; i++){
	    hashtable_exact_counter[i] = NULL;
    }

    memcpy(CLIENT_KEY, client_key, KEY_SIZE);
    auth_init(KEY_SIZE, TWEAK_SIZE);
    res = getKey(); if (res != EXIT_SUCCESS) exit_error("<T> getKey error!\n");    
}

/***********************CLEAR FUNCTIONS************************/

void recreate_hash_counter() {
    N_OPS = 0;
    for (int i=0; i<nbuckets; i++){
        struct node* current = hashtable_exact_counter[i];
        struct node* next;
        while (current != NULL){
            next = current->next;
            free(current->hash);
            free(current);
            current = next;
        }
        hashtable_exact_counter[i] = NULL;
    }
}


void trusted_clear_sgx() {    
    recreate_hash_counter();
    free(hashtable_exact_counter);
    free(EPOCH_KEY);
    free(CLIENT_KEY);
    free(SERVER_KEY);
    for(int i=0;i<r_counters;i++){
            free(matrix_counter[i]);
    }
    free(matrix_counter);
}


/***********************COMPUTE HASH************************/

/* 
 * Basic and Epoch based scheme 
 */
unsigned int compute_epoch_hash(unsigned char *msg, int msg_size, unsigned char *hash) {    
    sgx_status_t err;
    unsigned int hash_size;
    
    if (N_OPS == 0 || ((MAX_OPS > 0) && (N_OPS >= MAX_OPS)) ) {        
        err = sgx_read_rand(EPOCH_KEY, EPOCH_KEY_SIZE);
        if (err != SGX_SUCCESS) usgx_exit("sgx_read_rand", err);
        N_OPS = 0;
    	printf("================================NEW EPOCH==============================\n");	
    } 
    N_OPS++;
    
    HMAC(EVP_sha256(), EPOCH_KEY, EPOCH_KEY_SIZE, msg, msg_size, hash, &hash_size);   
    return hash_size;
}

/* 
 * Estimated based scheme 
 */
unsigned int compute_epoch_hash_with_matrix(unsigned char *msg, int msg_size, unsigned char *hash) {
    sgx_status_t err;
    unsigned int hash_size;

    if (N_OPS == 0 || ((MAX_OPS > 0) && (N_OPS >= MAX_OPS)) ) {
        err = sgx_read_rand(EPOCH_KEY, EPOCH_KEY_SIZE);
        if (err != SGX_SUCCESS) usgx_exit("sgx_read_rand", err);
        N_OPS = 0;
    }
    N_OPS++;
    
    unsigned char * hash2 = (unsigned char*) malloc (sizeof(unsigned char) * 64);
    HMAC(EVP_sha512(), EPOCH_KEY, EPOCH_KEY_SIZE, msg, msg_size, hash2, &hash_size);
  
    uint64_t sum = 0;
    uint64_t sum1 = 0;
    uint64_t sum2 = 0;
    uint64_t sum3 = 0;
    for(int x = 0; x < 64; x++){
            sum = sum + x * hash2[x];
	    if (x%2)sum1 = sum1 + x * hash2[x];
	    else sum2 = sum2 + x * hash2[x];
	    if (x%3) sum3 = sum3 + x * hash2[x];
    }

    free(hash2);

    int xs[4];
    xs[0] = sum * 499 % w_counters;
    xs[1] = sum1 * 499 % w_counters;
    xs[2] = sum2 * 499 % w_counters;
    xs[3] = sum3 * 499 % w_counters;

    uint64_t min_counter = matrix_counter[0][xs[0]] + 1;
    for(int x = 0; x < r_counters; x++){
        matrix_counter[x][xs[x]] ++;
	if (min_counter >  matrix_counter[x][xs[x]] ){
            min_counter =  matrix_counter[x][xs[x]];
        }
    }
    
    min_counter = min_counter/T_THRESHOLD;

    unsigned char *msg_with_counter = (unsigned char*) malloc (sizeof(unsigned char*) * msg_size + sizeof(uint64_t));
    memcpy(msg_with_counter, msg, msg_size);
    memcpy(&msg_with_counter[msg_size], (char*) &(min_counter), sizeof(uint64_t));
    memset(hash, '0', 32);
    HMAC(EVP_sha256(), EPOCH_KEY, EPOCH_KEY_SIZE, msg_with_counter, msg_size + sizeof(uint64_t), hash, &hash_size);

    free(msg_with_counter);
    return hash_size;
}


uint32_t insert_and_increment_NodeInLINK(unsigned char * hash);

/* 
 * Exact based scheme 
 */
unsigned int compute_epoch_hash_exact_counter(unsigned char *msg, int msg_size, unsigned char *hash) {
    sgx_status_t err;
    unsigned int hash_size;

    if (N_OPS == 0 || ((MAX_OPS > 0) && (N_OPS >= MAX_OPS)) ) {
        err = sgx_read_rand(EPOCH_KEY, EPOCH_KEY_SIZE);
        if (err != SGX_SUCCESS) usgx_exit("sgx_read_rand", err);
        N_OPS = 0;
        printf("================================NEW EPOCH==============================\n");
    }

    N_OPS++;
    HMAC(EVP_sha256(), EPOCH_KEY, EPOCH_KEY_SIZE, msg, msg_size, hash, &hash_size);

    uint32_t counter;
    counter = insert_and_increment_NodeInLINK(hash);


    unsigned char *msg_with_counter = (unsigned char*) malloc (sizeof(unsigned char*) * msg_size + sizeof(uint32_t));
    if (msg_with_counter == NULL) {
        recreate_hash_counter();
	N_OPS = 0;
	msg_with_counter = (unsigned char*) malloc (sizeof(unsigned char*) * msg_size + sizeof(uint32_t));
    }

    counter = counter /T_THRESHOLD;
    memcpy(msg_with_counter, msg, msg_size);
    memcpy(&msg_with_counter[msg_size], (char*) &(counter), sizeof(uint32_t));

    memset(hash, '0', 32);
    HMAC(EVP_sha256(), EPOCH_KEY, EPOCH_KEY_SIZE, msg_with_counter, msg_size + sizeof(uint32_t), hash, &hash_size);
    
    free(msg_with_counter);
    return hash_size;
}


/*
 * Decrypt file with client key and compute hash
 */
int trusted_compute_hash(uint8_t *digest, size_t digest_size, uint8_t *data, size_t data_size,uint64_t data_offset) {
    int plaintext_size, aux_digest_size;
    unsigned char *plaintext;
    unsigned char tweak[16] = {0};
    memcpy(tweak, (char*) &data_offset, 8);
    memcpy(tweak + 8, (char*) &data_offset, 8);

    // *****************************
    // Decode data with client key
    plaintext_size = data_size ;
    plaintext = (unsigned char*) malloc(sizeof(unsigned char) * plaintext_size);
    if (plaintext == NULL) {
        recreate_hash_counter();
        plaintext = (unsigned char*) malloc(sizeof(unsigned char) * plaintext_size);
    }

    plaintext_size = decode(CLIENT_KEY, tweak, plaintext, data, plaintext_size);


    // *****************************
    // Compute hash
    if (SECURITY_LEVEL == 0 || SECURITY_LEVEL == 1) {
	    aux_digest_size = compute_epoch_hash(plaintext, plaintext_size, digest);
    }
    else if (SECURITY_LEVEL == 2){
	aux_digest_size = compute_epoch_hash_with_matrix(plaintext, plaintext_size, digest); 
    }
    else {
        aux_digest_size = compute_epoch_hash_exact_counter(plaintext, plaintext_size, digest); 
    }
    
    if (aux_digest_size != digest_size) usgx_exit_error("<T> compute_hash error: wrong digest size %d", aux_digest_size);

    free(plaintext);
    return aux_digest_size;
}

/*********************** END COMPUTE HASH************************/


/*********************** ENCODE AND DECODE************************/

int encode(unsigned char* key, uint8_t *tweak, uint8_t *dest, uint8_t* src, size_t src_size) {

    int res;

    res = auth_encode(key, tweak, dest, src, src_size);
    if (res <= 0) {
	    	printf("Trying again<T> Encode Error -> auth_encode return %d\n", res);

	        recreate_hash_counter();

    		res = auth_encode(key, tweak, dest, src, src_size);
    		if (res <= 0) exit_error("<T> Encode Error -> auth_encode return %d\n", res);
    }
    return res;
}

int decode(unsigned char* key, uint8_t *tweak, uint8_t *dest, uint8_t* src, size_t src_size) {

    int res;
    res = auth_decode(key, tweak, dest, src, src_size);
    if (res <= 0) {
                printf("Trying again<T> Decode Error -> auth_decode return %d\n", res);

	        recreate_hash_counter();

	        res = auth_decode(key, tweak, dest, src, src_size);

                if (res <= 0) exit_error("<T> Decode Error -> auth_decode return %d\n", res);
    }
    return res;
}

int trusted_decode(uint8_t *dest, size_t dest_size, uint8_t* src, size_t src_size, uint64_t src_offset) {
    
    int plaintext_size = src_size;
    unsigned char *plaintext;
    unsigned char tweak[16] = {0};
 
    memcpy(tweak, (char*) &src_offset, 8);
    memcpy(tweak + 8, (char*) &src_offset, 8);

    plaintext = (unsigned char*) malloc(sizeof(unsigned char) * plaintext_size);
    plaintext_size = decode(SERVER_KEY, tweak, plaintext, src, plaintext_size);
    
    if (plaintext_size < 0) return -1;
    
    memcpy(dest, plaintext, plaintext_size);
    free(plaintext);
    
    return plaintext_size;
}

/*
 * Decrypt file with client key and reencrypt with server key
 */
int trusted_reencrypt(uint8_t *dest, size_t dest_size, uint64_t dest_offset, uint8_t* src, size_t src_size, uint64_t src_offset) {    
    int plaintext_size, ciphertext_size;
    unsigned char *plaintext, *ciphertext;
    

    unsigned char tweak_o[16] = {0};
    memcpy(tweak_o, (char*) &src_offset, 8);
    memcpy(tweak_o + 8, (char*) &src_offset, 8);

    // *****************************
    // Decode data with client key
    plaintext_size = src_size ;
    plaintext = (unsigned char*) malloc(sizeof(unsigned char) * plaintext_size);
    
    if (plaintext == NULL) {
        recreate_hash_counter();
    	plaintext = (unsigned char*) malloc(sizeof(unsigned char) * plaintext_size);
    }

    plaintext_size = decode(CLIENT_KEY, tweak_o, plaintext, src, plaintext_size);

    unsigned char tweak_i[16] = {0};
    memcpy(tweak_i, (char*) &dest_offset, 8);
    memcpy(tweak_i + 8, (char*) &dest_offset, 8);

    // *****************************
    // Encode data with server key
    ciphertext = (unsigned char*) malloc (sizeof(unsigned char*) * src_size);

    if (ciphertext == NULL) {
        recreate_hash_counter();
	ciphertext = (unsigned char*) malloc (sizeof(unsigned char*) * src_size);
    }
    
    ciphertext_size = encode(SERVER_KEY, tweak_i, ciphertext, plaintext, plaintext_size); 
    memcpy(dest, ciphertext, ciphertext_size);
    free(plaintext);
    free(ciphertext);

    return ciphertext_size;
}


/*
 * Decrypt file with server key and reencrypt with client key
 */
int trusted_reencrypt_reverse(uint8_t *dest, size_t dest_size, uint64_t dest_offset, uint8_t* src, size_t src_size, uint64_t src_offset) {
    int plaintext_size, ciphertext_size;
    unsigned char *plaintext, *ciphertext;

    unsigned char tweak_i[16] = {0};
    memcpy(tweak_i, (char*) &src_offset, 8);
    memcpy(tweak_i + 8, (char*) &src_offset, 8);

    // *****************************
    // Decode data with server key
    plaintext_size = src_size ;
    plaintext = (unsigned char*) malloc(sizeof(unsigned char) * plaintext_size);
    if (plaintext == NULL) {
        recreate_hash_counter();
        plaintext = (unsigned char*) malloc(sizeof(unsigned char) * plaintext_size);
    }
    plaintext_size = decode(SERVER_KEY, tweak_i, plaintext, src, plaintext_size);

    unsigned char tweak_o[16] = {0};
    memcpy(tweak_o, (char*) &dest_offset, 8);
    memcpy(tweak_o + 8, (char*) &dest_offset, 8);
    
    // *****************************
    // Encode data with client key
    ciphertext = (unsigned char*) malloc (sizeof(unsigned char*) * src_size);

   if (ciphertext == NULL) {
        recreate_hash_counter();
        ciphertext = (unsigned char*) malloc (sizeof(unsigned char*) * src_size);

    }
    
    ciphertext_size = encode(CLIENT_KEY, tweak_o, ciphertext, plaintext, plaintext_size);
    memcpy(dest, ciphertext, ciphertext_size);
    free(plaintext);
    free(ciphertext);

    return ciphertext_size;
}

/*********************** END ENCODE AND DECODE************************/


/***********************AUXILIARY FUNCTIONS************************/

unsigned int hash_code(const void * v){
        uint32_t h = 5381;
        const signed char *p;
        p=v;
        for (int i=0; i<32; i++){
                h = (h << 5) + h + *p;
                p++;
        }
        return h;
}

int get_hash_index(unsigned char * hash){
        return (hash_code(hash) * 11) & (nbuckets - 1);
}

void insertFirst(int node_index, unsigned char * hash) {
   struct node *link = (struct node*) malloc(sizeof(struct node));
   if (link == NULL) {
        recreate_hash_counter();
        link = (struct node*) malloc(sizeof(struct node));
   }
  link->hash = (unsigned char*) malloc (sizeof(unsigned char) * 32);
   if (link->hash == NULL) {
        recreate_hash_counter();
        link->hash = (unsigned char*) malloc (sizeof(unsigned char) * 32);
   }
   memcpy(link->hash, hash, 32);
   link->counter = 1;
   link->next = hashtable_exact_counter[node_index];
   hashtable_exact_counter[node_index] = link;
}

uint32_t insert_and_increment_NodeInLINK(unsigned char * hash){

        int node_index = get_hash_index(hash);
        struct node* current = hashtable_exact_counter[node_index];

        if(current == NULL) {
                insertFirst(node_index,hash);
                return 1;
        }

        while(memcmp(current->hash, hash, 32)) {
                if(current->next == NULL) {
                        insertFirst(node_index,hash);
                        return 1;
                } else {
                        current = current->next;
                }
        }

        current->counter = current->counter + 1;
        return current->counter;
}

/***********************END AUXILIARY FUNCTIONS************************/
