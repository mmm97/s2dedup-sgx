#!/bin/bash

PREFIX_DIR=/home/gsd
OUT_DIR=$PREFIX_DIR/results_microbenchs
OUTPUT_REPORT=$OUT_DIR/report.txt

mkdir -p $OUT_DIR

run_benchmark() {
    mkdir -p $OUT_DIR/$1
    for b in 4 16 32 64 128
    do
		for r in 1 2
        do
            for ((i=6; i<=10; i++)); do 
                echo -e "$1 | TEST $r | BLOCK_SIZE "$b"k | RUN $i" >> $OUTPUT_REPORT 
                pidstat -C "microbenchmark" 1 -rud -h >> $OUT_DIR'/'$1'/pidstat_report_b'$b'K_r'$r'_'$i'.log' &
                ./microbenchmark -r$r -b$b -t10
                mv results/'results_'$1'_t'$r'_'$b'k.log' $OUT_DIR/$1/'results_'$1'_t'$r'_'$b'k_'$i'.log' 
                sudo pkill pidstat
            done
		done
	done
}

clean() {
    rm results/*
	make clean
	sudo rm /tmp/micro_ekey.priv
}

switch_imp() {
    git checkout $1
	make SGX_DEBUG=1 SGX_PREREALEASE=1
}

clean
switch_imp master
run_benchmark sgxssl

clean
switch_imp sgx_sdk
run_benchmark sgxsdk

clean
switch_imp untrusted_openssl
run_benchmark untrusted_openssl