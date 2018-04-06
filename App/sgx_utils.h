#include "Enclave_u.h"
#include "sgx_urts.h"

#include <stdio.h>
#include <unistd.h>
#include <errno.h>

/* Global EID shared by multiple threads */
sgx_enclave_id_t eid;

int sgxCreateEnclave();
int sgxDestroyEnclave();
void recreateEnclave();
void print_sgx_error_message(sgx_status_t err);

void uprint(const char *str);
void usgx_exit(const char *func_name, int err);
void usgx_exit_error(const char *error_msg);
uint32_t save_sdata(uint8_t *sdata, uint32_t sdata_len);
uint32_t load_sdata(uint8_t *sdata, uint32_t sdata_len, uint32_t *sdata_len_out);