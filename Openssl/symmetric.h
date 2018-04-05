/*
  SafeFS
  (c) 2016 2016 INESC TEC. Written by J. Paulo and R. Pontes

*/

#ifndef __OPENSSL_SYMMETRIC_H__
#define __OPENSLL_SYMMETRIC_H__


#include <stdio.h>
#include <stdlib.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/conf.h>

#include <string.h>

#define CBC 1
#define CTR 2

int openssl_init(int block_size,  int operation_mode);

int openssl_encode(unsigned char* key, unsigned char* iv, unsigned char* dest, const unsigned char* src, int size);

int openssl_decode(unsigned char* key, unsigned char* iv, unsigned char* dest, const unsigned char* src, int size);

int openssl_clean();

int handleErrors(void);

#endif