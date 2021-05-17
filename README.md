# S2Dedup SGX

This repository is part of the S2Dedup project. Please refer to [S2Dedup repository](https://github.com/mmm97/S2Dedup) for further information. 

S2Dedup leverages Intel Software Guard Extensions to enable cross-user privacy-preserving deduplication at third-party storage infrastructures. Intel SGX provides a secure trusted execution environment to perform critical operations. Therefore, be sure to first follow [SGX installation instructions](https://github.com/intel/linux-sgx).

Afterwards the compilation and the creation of the signed enclave shared object (Enclave.signed.so) can be reproduced as follows:
~~~{.sh}
make SGX_MODE=HW SGX_PRERELEASE=1
cd App/ && ./creator_lib.sh
~~~
