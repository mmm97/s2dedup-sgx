#!/bin/bash

gcc -shared -o libenclavas.so ../Openssl/auth_encryption.o sgx_utils.o Enclave_u.o

sudo cp libenclavas.so /usr/local/lib

sudo chmod 0755 /usr/local/lib/libenclavas.so

sudo ldconfig
