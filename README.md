# S2Dedup SGX

This repository is part of the S2Dedup project. Please refer to [S2Dedup repository](https://github.com/mmm97/S2Dedup) for further information or you may read the paper published in SYSTOR'21:

- "S2Dedup: SGX-enabled Secure Deduplication"

S2Dedup leverages Intel Software Guard Extensions to enable cross-user privacy-preserving deduplication at third-party storage infrastructures. Intel SGX provides a secure trusted execution environment to perform critical operations. Therefore, be sure to first follow [SGX installation instructions](https://github.com/intel/linux-sgx).

Afterwards, the compilation and creation of the signed enclave shared object (Enclave.signed.so) can be reproduced as follows:
~~~{.sh}
make SGX_MODE=HW SGX_PRERELEASE=1
cd App/ && ./creator_lib.sh
~~~
Note: If using this repository in the context of S2Dedup deployment, it is important to copy the signed enclave shared object (*Enclave.signed.so*) to the respective block device directory (e.g., module/bdev/non_persistent_dedup_sgx).

## Contacts
For more information please contact: 

- Mariana Miranda - mariana.m.miranda at inesctec.pt
- João Paulo - joao.t.paulo at inesctec.pt
- Tânia Esteves - tania.c.araujo at inestec.pt
- Bernardo Portela - b.portela at fct.unl.pt
