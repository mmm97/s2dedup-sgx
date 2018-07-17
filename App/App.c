#include "App.h"

#define EPOCH_OPS -1
// #define EPOCH_OPS 122234797
#define KEY_SIZE 32 
#define IV_SIZE  12
#define MAC_SIZE 16
#define HASH_LEN 32

char CLIENT_KEY[KEY_SIZE]  = "C53C0E2F1B0B19AC53C0E2F1B0B19AA";

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

/* TEST1: Reencrypt data */
double func_test1(uint8_t *dest, size_t dest_len, uint8_t *str, size_t str_len, uint8_t *hash) {
    clock_t enclave_startTime, enclave_endTime;
    
    enclave_startTime = clock();
    reencrypt(dest, dest_len, str, str_len);
    enclave_endTime = clock();
    
    return (double)(enclave_endTime - enclave_startTime) / CLOCKS_PER_SEC;
}

/* TEST2: decrypt data and compute hash */
double func_test2(uint8_t *dest, size_t dest_len, uint8_t *str, size_t str_len, uint8_t *hash) {
    clock_t enclave_startTime, enclave_endTime;
    
    enclave_startTime = clock();
    decrypt_hash_epoch(hash, HASH_LEN, str, str_len);
    enclave_endTime = clock();

    return (double)(enclave_endTime - enclave_startTime) / CLOCKS_PER_SEC;
}

void run_test_ops(double (*func_test)(uint8_t*, size_t, uint8_t*, size_t, uint8_t*), uint8_t *dest, size_t dest_len, uint8_t *str, size_t str_len, uint64_t n_ops) {
    double total_enclave_time_elapsed=0;
    uint64_t ops = 0;

    unsigned char *hash = (unsigned char*) malloc (sizeof(unsigned char) * HASH_LEN);

	while (ops < n_ops) 
	{
		// call test func
        total_enclave_time_elapsed += func_test(dest, dest_len, str, str_len, hash);
        ops++;
	}

    free(hash);
    
    // print results
    printf("\n\nTotal ops:  %lu\n", ops);
    printf("Throughput: %.3f ops/second\n", (double) ops / total_enclave_time_elapsed);
    printf("Latency:    %.3f miliseconds\n", (total_enclave_time_elapsed / ops) * 1000);
    printf("Total time (SGX): %f \n", total_enclave_time_elapsed);           
}

void run_test_time(double (*func_test)(uint8_t*, size_t, uint8_t*, size_t, uint8_t*), uint8_t *dest, size_t dest_len, uint8_t *str, size_t str_len, uint8_t time_to_run) {
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
        if ((time_left != x_last_print_s) && (time_left % 10 == 0)) {
            zlog_info(c, "ILAT=%f", operation_time); 
            x_last_print_s = time_left;
        }
            
        // call test func
        operation_time = func_test(dest, dest_len, str, str_len, hash);    
        total_enclave_time_elapsed += operation_time;
        ops++;
		
		x_countTime=clock(); 
        x_milliseconds=x_countTime-x_startTime;
        x_seconds=(x_milliseconds/(CLOCKS_PER_SEC));
        time_left=count_down_time_in_secs-x_seconds;
	}
    zlog_info(c, "ILAT=%f", operation_time);
    zlog_info(c, "TETIME=%f", total_enclave_time_elapsed);
    zlog_info(c, "TOPS=%lu", ops);
    free(hash);
    
    // print results
    printf("\n\nTotal ops:  %lu\n", ops);
    printf("Throughput: %.3f ops/second\n", (double) ops / total_enclave_time_elapsed);
    printf("Latency:    %.3f miliseconds\n", (total_enclave_time_elapsed / ops) * 1000);
    printf("Total time (SGX): %f \n", total_enclave_time_elapsed);           
}

void usage(void){
	printf(" Help:\n\n");
    printf(" -r<value> Number of test (1:re-encrypt, 2:decrypt+hash)\n");
	printf(" -b<value> block size (KB) (default=1K)\n");
	printf(" -t<value> or -n<value>\t(Benchmark duration (-t) in Minutes or number of operations to execute (-n))\n");
	exit (8);
}

int check_integrity(uint8_t* plaintext, size_t plaintext_size, uint8_t *ciphertext, size_t ciphertext_size) {

    unsigned char *aux_plaintext;
    int aux_plaintext_size, integrity = EXIT_FAILURE;

    // *****************************
    // Decode data with server key
    aux_plaintext = (unsigned char*) malloc(sizeof(unsigned char) * plaintext_size);
    aux_plaintext_size = decode(aux_plaintext, plaintext_size, ciphertext, ciphertext_size);
    // *****************************
    // Compare aux_plaintext with plaintext
    if (aux_plaintext_size == plaintext_size && (memcmp(plaintext, aux_plaintext, plaintext_size) == 0))
        integrity = EXIT_SUCCESS;

    free(aux_plaintext);
    return integrity;
}

int main(int argc, char const *argv[]) {

    int rc, test=1, ciphertext_size, integrity;
    size_t block_size=1024;
    unsigned int time_to_run=1;
    uint64_t n_ops=0;
    char zlog_cat[256];

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

    ciphertext_size = block_size + IV_SIZE + MAC_SIZE;

    unsigned char *randomstr  = (unsigned char*) malloc(sizeof(unsigned char) * block_size);
    unsigned char *ciphertext = (unsigned char*) malloc(sizeof(unsigned char) * ciphertext_size);
    unsigned char *dest = (unsigned char*) malloc(sizeof(unsigned char) * ciphertext_size);
    unsigned char *mac = (unsigned char*) malloc(sizeof(unsigned char) * (MAC_SIZE));

    // Generate a random string with size = block_size
    randstring(randomstr, block_size);

    init_u_openssl(CLIENT_KEY, KEY_SIZE, IV_SIZE, MAC_SIZE, 1, EPOCH_OPS);

    // Encrypt random string
    ciphertext_size = encode(ciphertext, ciphertext_size, randomstr, block_size);

    if (n_ops > 0) printf("OPENSSL | Running test %d with block_size = %ldB and n_ops = %lu\n", test, block_size, n_ops);
    else printf("OPENSSL | Running test %d with block_size = %ldB and time_to_run = %um\n", test, block_size, time_to_run);

    if (n_ops > 0) zlog_info(c, "OPENSSL | Running test %d with block_size = %ldB and n_ops = %lu\n", test, block_size, n_ops);
    else zlog_info(c, "OPENSSL | Running test %d with block_size = %ldB and time_to_run = %um\n", test, block_size, time_to_run);
    
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
    
    free(randomstr);
    free(ciphertext);
    free(dest);
    free(mac);

    zlog_fini();

    return EXIT_SUCCESS;
}
