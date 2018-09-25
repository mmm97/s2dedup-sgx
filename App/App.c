#include "App.h"

#define EPOCH_OPS -1
//#define EPOCH_OPS 100000
#define KEY_SIZE 32 
#define IV_SIZE  12
#define MAC_SIZE 16
#define HASH_LEN 32


struct thread_args
 {
    unsigned char *dest;
    int dest_size;
    unsigned char *ciphertext;
    int ciphertext_size;
    unsigned char *hash;
    int threadid;  
};
 
//  pthread_mutex_t eid_mutex;// = PTHREAD_MUTEX_INITIALIZER;
unsigned char CLIENT_KEY[KEY_SIZE]  = "C53C0E2F1B0B19AC53C0E2F1B0B19AA";

zlog_category_t *c;

void print_digest(unsigned char *digest, int digest_size) {
    int n;
	char mdString[(digest_size * 2) + 1];
	for (n = 0; n < digest_size; ++n) {
        snprintf(&(mdString[n*2]), digest_size*2, "%02x", (unsigned int)digest[n]);
    }
    
    printf("[%d] \'%s\'\n", digest_size, mdString);
}

void randstring(unsigned char *dest, size_t length) {

    static char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789,.-#'?!";        
    unsigned char *randomString = NULL;

    if (length) {
        randomString = (unsigned char*) malloc(sizeof(unsigned char) * length);

        if (randomString) {            
            for (size_t n = 0;n < length-1;n++) {            
                int key = rand() % (int)(sizeof(charset) -1);
                randomString[n] = charset[key];
            }

            randomString[length] = '\0';
        }
    }
    memcpy(dest, randomString, length);
    free(randomString);
}

/* if the enclave is lost, release its resources, and bring the enclave back up. */

void recreateEnclave() {
    printf("[ENCLAVE_LOST] old enclave id = %d\n", (int) eid); 
    /* if the enclave is lost, release its resources, and bring the enclave back up. */
    if (SGX_SUCCESS != sgxDestroyEnclave(eid)) exit(EXIT_FAILURE);
    if (SGX_SUCCESS != sgxCreateEnclave()) exit(EXIT_FAILURE);        
    if (SGX_SUCCESS != trusted_init_sgx(eid, CLIENT_KEY, KEY_SIZE, IV_SIZE, MAC_SIZE, 1, EPOCH_OPS))  exit(EXIT_FAILURE);
    
    printf("[ENCLAVE_LOST] New enclave id = %d\n", (int) eid);    
}

/* TEST1: Reencrypt data */
void *func_test1(void *args_in) {
    int res=0;
    clock_t enclave_startTime, enclave_endTime;
    struct thread_args *args = args_in;
    printf("Test1: threadid=%d\n", args->threadid);
    enclave_startTime = clock();
    // pthread_mutex_lock(&eid_mutex);
    while (trusted_reencrypt(eid, &res, args->dest, args->dest_size, args->ciphertext, args->ciphertext_size) == SGX_ERROR_ENCLAVE_LOST)    
        recreateEnclave();
    // pthread_mutex_unlock(&eid_mutex);
    enclave_endTime = clock();
    
    // return (double)(enclave_endTime - enclave_startTime) / CLOCKS_PER_SEC;

    return NULL;
}

/* TEST2: Decrypt data and compute hash */
void* func_test2(void *args) {
    int res;
    clock_t enclave_startTime, enclave_endTime;
    
    // enclave_startTime = clock();
    // while (trusted_compute_hash(eid, &res, hash, HASH_LEN, str, str_len) == SGX_ERROR_ENCLAVE_LOST) 
    //     recreateEnclave();    
    // enclave_endTime = clock();

    // return (double)(enclave_endTime - enclave_startTime) / CLOCKS_PER_SEC;
    return NULL;
}

void *run_test_ops(void* (*func_test)(void*), uint8_t *dest, size_t dest_len, uint8_t *str, size_t str_len, uint64_t n_ops) {
    double total_enclave_time_elapsed=0;
    uint64_t ops = 0;

    unsigned char *hash = (unsigned char*) malloc (sizeof(unsigned char) * HASH_LEN);

	while (ops < n_ops) 
	{
		// call test func
        // total_enclave_time_elapsed += ((struct thread_args*) args)->func_test(((struct thread_args*) args)->dest, ((struct thread_args*) args)->dest_size, ((struct thread_args*) args)->ciphertext, ((struct thread_args*) args)->ciphertext_size, hash);
        // ops++;
	}

    free(hash);
    
    // print results
    printf("\n\nTotal ops:  %lu\n", ops);
    printf("Throughput: %.3f ops/second\n", (double) ops / total_enclave_time_elapsed);
    printf("Latency:    %.3f miliseconds\n", (total_enclave_time_elapsed / ops) * 1000);
    printf("Total time (SGX): %f \n", total_enclave_time_elapsed);     

    return NULL;      
}
/*
void *run_test_time(void* (*func_test)(void*), uint8_t *dest, size_t dest_len, uint8_t *str, size_t str_len, uint8_t time_to_run) {
	unsigned int x_seconds=0, x_last_print_s=0, x_milliseconds=0;
	unsigned int count_down_time_in_secs, time_left=0;
	double operation_time=0, total_enclave_time_elapsed=0;
    clock_t x_startTime, x_countTime;
    uint64_t ops = 0;

    // struct thread_args *targs = malloc (sizeof(struct thread_args));
    // targs->dest = dest;
    // targs->dest_size = dest_len;
    // targs->ciphertext = str;
    // targs->ciphertext_size = str_len;
    
    unsigned char *hash = (unsigned char*) malloc (sizeof(unsigned char) * HASH_LEN);

    count_down_time_in_secs = time_to_run * 10;
    x_startTime=clock();  // start clock
    time_left=count_down_time_in_secs-x_seconds;   // update timer
	while (time_left>0) {
        // if ((time_left != x_last_print_s) && (time_left % 10 == 0)) {
        //     zlog_info(c, "ILAT=%f", operation_time); 
        //     x_last_print_s = time_left;
        // }
            
        sleep(1);
        // call test func
        // args->func_test((void*)args);
        // func_test((void*)args);
        // total_enclave_time_elapsed += operation_time;
        ops++;
		
		x_countTime=clock(); 
        x_milliseconds=x_countTime-x_startTime;
        x_seconds=(x_milliseconds/(CLOCKS_PER_SEC));
        time_left=count_down_time_in_secs-x_seconds;
        printf("%.2d\n", time_left);
	}
    // pthread_join(tid,NULL);
    // zlog_info(c, "ILAT=%f", operation_time);
    // zlog_info(c, "TETIME=%f", total_enclave_time_elapsed);
    zlog_info(c, "TOPS=%lu", ops);
    free(hash);
    
    // print results
    // printf("\n\nTotal ops:  %lu\n", ops);
    // printf("Throughput: %.3f ops/second\n", (double) ops / total_enclave_time_elapsed);
    // printf("Latency:    %.3f miliseconds\n", (total_enclave_time_elapsed / ops) * 1000);
    // printf("Total time (SGX): %f \n", total_enclave_time_elapsed);    
    return NULL;       
}*/
/*
void run_test_time(void* (*func_test)(void*), uint8_t *dest, size_t dest_len, uint8_t *str, size_t str_len, uint8_t time_to_run) {
	unsigned int x_seconds=0, x_last_print_s=0, x_milliseconds=0;
	unsigned int count_down_time_in_secs, time_left=0;
	double operation_time=0, total_enclave_time_elapsed=0;
    clock_t x_startTime, x_countTime;
    uint64_t ops = 0;

    unsigned char *hash = (unsigned char*) malloc (sizeof(unsigned char) * HASH_LEN);

    count_down_time_in_secs = time_to_run * 60;
    x_startTime=clock();  // start clock

    time_left=count_down_time_in_secs-x_seconds;   // update timer
	while (time_left>0) {
        // if ((time_left != x_last_print_s) && (time_left % 10 == 0)) {
        //     zlog_info(c, "ILAT=%f", operation_time); 
        //     x_last_print_s = time_left;
        // }
            
        sleep(1);

        // call test func
        // operation_time = func_test(dest, dest_len, str, str_len, hash);    
        // total_enclave_time_elapsed += operation_time;
        ops++;
		
		x_countTime=clock(); 
        x_milliseconds=x_countTime-x_startTime;
        x_seconds=(x_milliseconds/(CLOCKS_PER_SEC));
        time_left=count_down_time_in_secs-x_seconds;
        printf("%.2d\n", time_left);
	}
    // zlog_info(c, "ILAT=%f", operation_time);
    // zlog_info(c, "TETIME=%f", total_enclave_time_elapsed);
    zlog_info(c, "TOPS=%lu", ops);
    free(hash);
    
    // print results
    printf("\n\nTotal ops:  %lu\n", ops);
    // printf("Throughput: %.3f ops/second\n", (double) ops / total_enclave_time_elapsed);
    // printf("Latency:    %.3f miliseconds\n", (total_enclave_time_elapsed / ops) * 1000);
    // printf("Total time (SGX): %f \n", total_enclave_time_elapsed);           
}
*/

void run_test_time(void (*func_test)(void*), uint8_t *dest, size_t dest_len, uint8_t *str, size_t str_len, uint8_t time_to_run) {
	unsigned int x_seconds=0, x_last_print_s=0, x_milliseconds=0;
	unsigned int count_down_time_in_secs, time_left=0;
	double operation_time=0, total_enclave_time_elapsed=0;
    clock_t x_startTime, x_countTime;
    uint64_t ops = 0;
    int i, s, NTHREADS=4;
    pthread_t tid;

    
    struct thread_args *targs = malloc (sizeof(struct thread_args));
    targs->dest = dest;
    targs->dest_size = dest_len;
    targs->ciphertext = str;
    targs->ciphertext_size = str_len;

    unsigned char *hash = (unsigned char*) malloc (sizeof(unsigned char) * HASH_LEN);

    count_down_time_in_secs = time_to_run * 5;
    x_startTime=clock();  // start clock

    time_left=count_down_time_in_secs-x_seconds;   // update timer
	while (time_left>0) {
        // if ((time_left != x_last_print_s) && (time_left % 10 == 0)) {
        //     zlog_info(c, "ILAT=%f", operation_time); 
        //     x_last_print_s = time_left;
        // }
            
        // call test func
        // operation_time = func_test(dest, dest_len, str, str_len, hash);    
        // total_enclave_time_elapsed += operation_time;
        // ops++;
		
        for(i = 0; i < NTHREADS; i++) {
            struct thread_args *targs = malloc (sizeof(struct thread_args));
            targs->dest = dest;
            targs->dest_size = dest_len;
            targs->ciphertext = str;
            targs->ciphertext_size = str_len;
            targs->threadid = i;
            s = pthread_create(&tid, NULL,
                           func_test, (void*) targs);
            ops++;
            if (s != 0)
                printf("pthread_create: %d\n", s);

            pthread_join(tid,NULL);
            free(targs);
        }

		x_countTime=clock(); 
        x_milliseconds=x_countTime-x_startTime;
        x_seconds=(x_milliseconds/(CLOCKS_PER_SEC));
        time_left=count_down_time_in_secs-x_seconds;
        // printf("%.2d\n", time_left);
	}
    
    // zlog_info(c, "ILAT=%f", operation_time);
    // zlog_info(c, "TETIME=%f", total_enclave_time_elapsed);
    zlog_info(c, "TOPS=%lu", ops);
    free(hash);
    
    // print results
    printf("\n\nTotal ops:  %lu\n", ops);
    // printf("Throughput: %.3f ops/second\n", (double) ops / total_enclave_time_elapsed);
    // printf("Latency:    %.3f miliseconds\n", (total_enclave_time_elapsed / ops) * 1000);
    // printf("Total time (SGX): %f \n", total_enclave_time_elapsed);           
}

void usage(void){
	printf(" Help:\n\n");
    printf(" -r<value> Number of test (1:re-encrypt, 2:decrypt+hash)\n");
	printf(" -b<value> block size (KB) (default=1K)\n");
	printf(" -t<value> or -n<value>\t(Benchmark duration (-t) in Minutes or number of operations to execute (-n))\n");
	exit (8);
}


int check_integrity(uint8_t* plaintext, size_t plaintext_size, uint8_t *ciphertext, size_t ciphertext_size) {

    printf("Check integrity...\n");
    sgx_status_t err;
    unsigned char *aux_plaintext;
    int aux_plaintext_size, integrity = EXIT_FAILURE;

    // *****************************
    // Decode data with server key
    aux_plaintext = (unsigned char*) malloc(sizeof(unsigned char) * plaintext_size);
    err = trusted_decode(eid, &aux_plaintext_size, aux_plaintext, plaintext_size, ciphertext, ciphertext_size);
    if (err != SGX_SUCCESS) print_sgx_error_message(err);

    // *****************************
    // Compare aux_plaintext with plaintext
    if (aux_plaintext_size == plaintext_size && (memcmp(plaintext, aux_plaintext, plaintext_size) == 0))
        integrity = EXIT_SUCCESS;

    free(aux_plaintext);
    return integrity;
}

 
int main(int argc, char const *argv[]) {


    sgx_status_t err;
    int rc, test=1, ciphertext_size, integrity;
    size_t block_size=1024;
    unsigned int time_to_run=0;
    uint64_t n_ops=0;
    char zlog_cat[256];

    
   
    // int rcm = pthread_mutex_init(&eid_mutex, NULL); assert(rcm == 0); // always check success!  


    rc = zlog_init("conf/zlog.conf");
	if (rc) {
		printf("zlog: init failed\n");
		return EXIT_FAILURE;
	}

    while ((argc > 1) && (argv[1][0] == '-')) {
		switch (argv[1][1]) {
			case 'r':
				test=atoi(&argv[1][2]);
				break;
			case 'b':
				block_size=atoi(&argv[1][2])*1024;
				break;
			case 't':
                if (n_ops != 0) { printf("Cannot use both -t and -n\n\n"); usage(); }
				else
                    time_to_run=atoi(&argv[1][2]);
				break;
            case 'n':
                if (time_to_run != 0) { printf("Cannot use both -t and -n\n\n"); usage(); }
				else
                    n_ops=atoi(&argv[1][2]);
				break;
			case 'h':
				usage();
				break;
			default:
				printf("Wrong Argument: %s\n", argv[1]);
				usage();
				exit(0);
				break;
        }

		++argv;
		--argc;
	}

    sprintf(zlog_cat, "t%d_%luk", test, block_size/1024);    
    c = zlog_get_category(zlog_cat);
	if (!c) {
		printf("zlog: get cat fail\n");
		zlog_fini();
		return EXIT_FAILURE;
	}

    unsigned char *randomstr    = (unsigned char*) malloc(sizeof(unsigned char) * block_size);
    unsigned char *ciphertext   = (unsigned char*) malloc(sizeof(unsigned char) * block_size + IV_SIZE + MAC_SIZE);
    unsigned char *dest         = (unsigned char*) malloc(sizeof(unsigned char) * block_size + IV_SIZE + MAC_SIZE);
    unsigned char *mac          = (unsigned char*) malloc(sizeof(unsigned char) * (MAC_SIZE));
    unsigned char *iv           = (unsigned char*) malloc(sizeof(unsigned char) * (IV_SIZE));

    // Generate a random string with size = block_size
    randstring(randomstr, block_size);
    randstring(iv, IV_SIZE);

    // Create enclave
    eid = 0;
    err = sgxCreateEnclave();
    if (err != SGX_SUCCESS) print_sgx_error_message(err);
    
    err = trusted_init_sgx(eid, CLIENT_KEY, KEY_SIZE, IV_SIZE, MAC_SIZE, 1, EPOCH_OPS);
    if (err != SGX_SUCCESS) print_sgx_error_message(err);

    // Encrypt random string
    auth_init(KEY_SIZE, IV_SIZE, MAC_SIZE, 1);
    ciphertext_size = auth_encode(CLIENT_KEY, iv, ciphertext, randomstr, block_size, mac);
    if (ciphertext_size <= 0) { printf("<T> Encode Error -> auth_encode return %d\n", ciphertext_size); exit(-1); }    
    memcpy(&ciphertext[ciphertext_size], iv, IV_SIZE);
    memcpy(&ciphertext[ciphertext_size+IV_SIZE], mac, MAC_SIZE);
    ciphertext_size = block_size + IV_SIZE + MAC_SIZE;

    if (n_ops > 0) printf("SGXSSL | Running test %d with block_size = %ldB and n_ops = %lu\n", test, block_size, n_ops);
    else printf("SGXSSL | Running test %d with block_size = %ldB and time_to_run = %um\n", test, block_size, time_to_run);

    switch(test) {        
        case 1:
            if (n_ops > 0) run_test_ops(func_test1, dest, ciphertext_size, ciphertext, ciphertext_size, n_ops);
            else run_test_time(func_test1, dest, ciphertext_size, ciphertext, ciphertext_size, time_to_run);
            break;
        case 2:         
            if (n_ops > 0) run_test_ops(func_test2, dest, ciphertext_size, ciphertext, ciphertext_size, n_ops);
            else run_test_time(func_test2, dest, ciphertext_size, ciphertext, ciphertext_size, time_to_run);
            break;       
    }

    // Check integrity
    if (test == 1) {
        integrity = check_integrity(randomstr, block_size, dest, ciphertext_size);
        if (integrity == EXIT_SUCCESS) printf("Integrity checked!\n");
        else printf("Integrity test failed!\n");
    }

    // Destroy enclave
    err = sgxDestroyEnclave();
    if (err != SGX_SUCCESS) print_sgx_error_message(err);

    free(randomstr);
    free(ciphertext);
    free(dest);
    free(mac);
    free(iv);

    zlog_fini();

    // pthread_exit(NULL);

    return EXIT_SUCCESS;
}
