#include "sgx_utils.h"

/* SGX Function for enclave creation */
int sgxCreateEnclave() {
    char *enclavefilepath = (char*) "Enclave/Enclave.signed.so";
	sgx_status_t ret;
	ret = sgx_create_enclave(enclavefilepath, SGX_DEBUG_FLAG, NULL, NULL, &eid, NULL );
    if (SGX_SUCCESS != ret) printf("sgxCreateEnclave: cant create Enclave (error 0x%x)\n", ret );
    return ret;
}

/* destroy SGX enclave */
int sgxDestroyEnclave() {
	sgx_status_t ret;
    if ((ret = trusted_clear_sgx(eid)) != SGX_SUCCESS) printf("trustedClear: error 0x%x\n", ret);
	if ((ret = sgx_destroy_enclave(eid)) != SGX_SUCCESS) printf("sgxDestroyEnclave: cant destroy Enclave (error 0x%x)\n", ret );
    return ret;
}

void print_sgx_error_message(sgx_status_t err) {
    switch(err) {
        case SGX_ERROR_INVALID_PARAMETER:             
            printf("[%d][%d] SGX_ERROR_INVALID_PARAMETER\n", (int)eid, (int) err);
            break;
        case SGX_ERROR_INVALID_CPUSVN: 
            printf("[%d][%d] SGX_ERROR_INVALID_CPUSVN\n", (int)eid, (int) err);
            break;
        case SGX_ERROR_INVALID_ISVSVN: 
            printf("[%d][%d] SGX_ERROR_INVALID_ISVSVN\n", (int)eid, (int) err);
            break;
        case SGX_ERROR_MAC_MISMATCH: 
            printf("[%d][%d] SGX_ERROR_MAC_MISMATCH\n", (int)eid, (int) err);
            break;
        case SGX_ERROR_OUT_OF_MEMORY: 
            printf("[%d][%d] SGX_ERROR_OUT_OF_MEMORY\n", (int)eid, (int) err);
            break;
        case SGX_ERROR_UNEXPECTED: 
            printf("[%d][%d] SGX_ERROR_UNEXPECTED\n", (int)eid, (int) err);
            break;
        case SGX_ERROR_ENCLAVE_LOST:
            printf("[%d][%d] SGX_ERROR_ENCLAVE_LOST\n", (int)eid, (int) err);
            break;
        case SGX_ERROR_INVALID_STATE:
            printf("[%d][%d] SGX_ERROR_INVALID_STATE\n", (int)eid, (int) err);
            break;
        case SGX_ERROR_INVALID_FUNCTION:
            printf("[%d][%d] SGX_ERROR_INVALID_FUNCTION\n", (int)eid, (int) err);
            break;
        case SGX_ERROR_OUT_OF_TCS:
            printf("[%d][%d] SGX_ERROR_OUT_OF_TCS\n", (int)eid, (int) err);
            break;
        case SGX_ERROR_ENCLAVE_CRASHED:
            printf("[%d][%d] SGX_ERROR_ENCLAVE_CRASHED\n", (int)eid, (int) err);
            break;
        case SGX_ERROR_ECALL_NOT_ALLOWED:
            printf("[%d][%d] SGX_ERROR_ECALL_NOT_ALLOWED\n", (int)eid, (int) err);
            break;
        case SGX_ERROR_OCALL_NOT_ALLOWED:
            printf("[%d][%d] SGX_ERROR_OCALL_NOT_ALLOWED\n", (int)eid, (int) err);
            break;
        case SGX_ERROR_STACK_OVERRUN:
            printf("[%d][%d] SGX_ERROR_STACK_OVERRUN\n", (int)eid, (int) err);
            break;
        case SGX_ERROR_UNDEFINED_SYMBOL:
            printf("[%d][%d] SGX_ERROR_UNDEFINED_SYMBOL\n", (int)eid, (int) err);
            break;
        case SGX_ERROR_INVALID_ENCLAVE:
            printf("[%d][%d] SGX_ERROR_INVALID_ENCLAVE\n", (int)eid, (int) err);
            break;
        case SGX_ERROR_INVALID_ENCLAVE_ID:
            printf("[%d][%d] SGX_ERROR_INVALID_ENCLAVE_ID\n", (int)eid, (int) err);
            break;
        case SGX_ERROR_INVALID_SIGNATURE:
            printf("[%d][%d] SGX_ERROR_INVALID_SIGNATURE\n", (int)eid, (int) err);
            break;
        case SGX_ERROR_NDEBUG_ENCLAVE:
            printf("[%d][%d] SGX_ERROR_NDEBUG_ENCLAVE\n", (int)eid, (int) err);
            break;
        case SGX_ERROR_OUT_OF_EPC:
            printf("[%d][%d] SGX_ERROR_OUT_OF_EPC\n", (int)eid, (int) err);
            break;
        case SGX_ERROR_NO_DEVICE:
            printf("[%d][%d] SGX_ERROR_NO_DEVICE\n", (int)eid, (int) err);
            break;
        case SGX_ERROR_MEMORY_MAP_CONFLICT:
            printf("[%d][%d] SGX_ERROR_MEMORY_MAP_CONFLICT\n", (int)eid, (int) err);
            break;
        case SGX_ERROR_INVALID_METADATA:
            printf("[%d][%d] SGX_ERROR_INVALID_METADATA\n", (int)eid, (int) err);
            break;
        case SGX_ERROR_DEVICE_BUSY:
            printf("[%d][%d] SGX_ERROR_DEVICE_BUSY\n", (int)eid, (int) err);
            break;
        case SGX_ERROR_INVALID_VERSION:
            printf("[%d][%d] SGX_ERROR_INVALID_VERSION\n", (int)eid, (int) err);
            break;
        case SGX_ERROR_MODE_INCOMPATIBLE:
            printf("[%d][%d] SGX_ERROR_MODE_INCOMPATIBLE\n", (int)eid, (int) err);
            break;
        case SGX_ERROR_ENCLAVE_FILE_ACCESS:
            printf("[%d][%d] SGX_ERROR_ENCLAVE_FILE_ACCESS\n", (int)eid, (int) err);
            break;
        case SGX_ERROR_INVALID_MISC:
            printf("[%d][%d] SGX_ERROR_INVALID_MISC\n", (int)eid, (int) err);
            break;
        case SGX_ERROR_INVALID_ATTRIBUTE:
            printf("[%d][%d] SGX_ERROR_INVALID_ATTRIBUTE\n", (int)eid, (int) err);
            break;
        case SGX_ERROR_INVALID_KEYNAME:
            printf("[%d][%d] SGX_ERROR_INVALID_KEYNAME\n", (int)eid, (int) err);
            break;
        case SGX_ERROR_SERVICE_UNAVAILABLE:
            printf("[%d][%d] SGX_ERROR_SERVICE_UNAVAILABLE\n", (int)eid, (int) err);
            break;
        case SGX_ERROR_SERVICE_TIMEOUT:
            printf("[%d][%d] SGX_ERROR_SERVICE_TIMEOUT\n", (int)eid, (int) err);
            break;
        case SGX_ERROR_AE_INVALID_EPIDBLOB:
            printf("[%d][%d] SGX_ERROR_AE_INVALID_EPIDBLOB\n", (int)eid, (int) err);
            break;
        case SGX_ERROR_SERVICE_INVALID_PRIVILEGE:
            printf("[%d][%d] SGX_ERROR_SERVICE_INVALID_PRIVILEGE\n", (int)eid, (int) err);
            break;
        case SGX_ERROR_EPID_MEMBER_REVOKED:
            printf("[%d][%d] SGX_ERROR_EPID_MEMBER_REVOKED\n", (int)eid, (int) err);
            break;
        case SGX_ERROR_UPDATE_NEEDED:
            printf("[%d][%d] SGX_ERROR_UPDATE_NEEDED\n", (int)eid, (int) err);
            break;
        case SGX_ERROR_NETWORK_FAILURE:
            printf("[%d][%d] SGX_ERROR_NETWORK_FAILURE\n", (int)eid, (int) err);
            break;
        case SGX_ERROR_AE_SESSION_INVALID:
            printf("[%d][%d] SGX_ERROR_AE_SESSION_INVALID\n", (int)eid, (int) err);
            break;
        case SGX_ERROR_BUSY:
            printf("[%d][%d] SGX_ERROR_BUSY\n", (int)eid, (int) err);
            break;
        case SGX_ERROR_MC_NOT_FOUND:
            printf("[%d][%d] SGX_ERROR_MC_NOT_FOUND\n", (int)eid, (int) err);
            break;
        case SGX_ERROR_MC_NO_ACCESS_RIGHT:
            printf("[%d][%d] SGX_ERROR_MC_NO_ACCESS_RIGHT\n", (int)eid, (int) err);
            break;
        case SGX_ERROR_MC_USED_UP:
            printf("[%d][%d] SGX_ERROR_MC_USED_UP\n", (int)eid, (int) err);
            break;
        case SGX_ERROR_MC_OVER_QUOTA:
            printf("[%d][%d] SGX_ERROR_MC_OVER_QUOTA\n", (int)eid, (int) err);
            break;
        case SGX_ERROR_KDF_MISMATCH:
            printf("[%d][%d] SGX_ERROR_KDF_MISMATCH\n", (int)eid, (int) err);
            break;
        case SGX_ERROR_UNRECOGNIZED_PLATFORM:
            printf("[%d][%d] SGX_ERROR_UNRECOGNIZED_PLATFORM\n", (int)eid, (int) err);
            break;
        case SGX_ERROR_NO_PRIVILEGE:
            printf("[%d][%d] SGX_ERROR_NO_PRIVILEGE\n", (int)eid, (int) err);
            break;
        case SGX_ERROR_FILE_BAD_STATUS:
            printf("[%d][%d] SGX_ERROR_FILE_BAD_STATUS\n", (int)eid, (int) err);
            break;
        case SGX_ERROR_FILE_NO_KEY_ID:
            printf("[%d][%d] SGX_ERROR_FILE_NO_KEY_ID\n", (int)eid, (int) err);
            break;
        case SGX_ERROR_FILE_NAME_MISMATCH:
            printf("[%d][%d] SGX_ERROR_FILE_NAME_MISMATCH\n", (int)eid, (int) err);
            break;
        case SGX_ERROR_FILE_NOT_SGX_FILE:
            printf("[%d][%d] SGX_ERROR_FILE_NOT_SGX_FILE\n", (int)eid, (int) err);
            break;
        case SGX_ERROR_FILE_CANT_OPEN_RECOVERY_FILE:
            printf("[%d][%d] SGX_ERROR_FILE_CANT_OPEN_RECOVERY_FILE\n", (int)eid, (int) err);
            break;
        case SGX_ERROR_FILE_CANT_WRITE_RECOVERY_FILE:
            printf("[%d][%d] SGX_ERROR_FILE_CANT_WRITE_RECOVERY_FILE\n", (int)eid, (int) err);
            break;
        case SGX_ERROR_FILE_RECOVERY_NEEDED:
            printf("[%d][%d] SGX_ERROR_FILE_RECOVERY_NEEDED\n", (int)eid, (int) err);
            break;
        case SGX_ERROR_FILE_FLUSH_FAILED:
            printf("[%d][%d] SGX_ERROR_FILE_FLUSH_FAILED\n", (int)eid, (int) err);
            break;
        case SGX_ERROR_FILE_CLOSE_FAILED:
            printf("[%d][%d] SGX_ERROR_FILE_CLOSE_FAILED\n", (int)eid, (int) err);
            break;
        case SGX_SUCCESS:
            break;
        default:
            printf("[%d] sgx error\n", err);
            break;
    }
}

/* OCALLS */

void uprint(const char *str) {
    /* Proxy/Bridge will check the length and null-terminate 
     * the input string to prevent buffer overflow. 
     */
    printf("%s", str);
    // fflush(stdout);
}

void usgx_exit_error(const char *error_msg) {
    printf("usgx_exit: %s\n", error_msg);
    exit(EXIT_FAILURE);
}

void usgx_exit(const char *func_name, int err) {
    printf("usgx_exit: %s\n", func_name);
    print_sgx_error_message((sgx_status_t) err);
    exit(EXIT_FAILURE);
}


uint32_t save_sdata(uint8_t *sdata, uint32_t sdata_len) {
    // printf("<U> SAVE KEY!!\n");

    char filename[32] = "/tmp/micro_ekey.priv";
    FILE *fp;

    fp = fopen(filename, "ab");
    if (fp != NULL) {
        // printf("<U> Saving sealed key with size=%d\n", sdata_len);
        fwrite(sdata, 1, sdata_len, fp);
        fclose(fp);        
        return EXIT_SUCCESS;
    }
    printf("<U> Can't open file\n");
    return EXIT_FAILURE;
}

uint32_t load_sdata(uint8_t *sdata, uint32_t sdata_len, uint32_t *sdata_len_out) {
    // printf("<U> LOAD KEY!!\n");

    char filename[32] = "/tmp/micro_ekey.priv";
    FILE *fp;
    uint8_t *buffer;
    size_t nread = 0; 

    // file doesn't exist
    if (access(filename, F_OK) != EXIT_SUCCESS) return EXIT_FAILURE;
    
    errno = 0;
    fp = fopen(filename, "rb");
    if (fp == NULL) {
        printf("Can't open file: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }    
    buffer = (uint8_t*) malloc(sizeof(uint8_t) * sdata_len);
    if (buffer == NULL) return EXIT_FAILURE;
    
    nread = fread(buffer, sizeof(uint8_t), sdata_len, fp);
    if ((nread * sizeof(uint8_t)) != sdata_len) {
        printf("<U> wrong sealed ekey size! -> %lu -> %d\n", nread * sizeof(uint8_t), sdata_len);
        return EXIT_FAILURE;
    }
    fclose(fp);
    memcpy(sdata, buffer, sdata_len);
    *sdata_len_out = sdata_len;
    free(buffer); 

    return EXIT_SUCCESS;
}
