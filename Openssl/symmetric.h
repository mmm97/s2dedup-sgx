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

int openssl_init(char* key, int block_size);

int openssl_encode(unsigned char* iv, unsigned char* dest, const unsigned char* src, int size);

int openssl_decode(unsigned char* iv, unsigned char* dest, const unsigned char* src, int size);

int openssl_clean();

int handleErrors(void);

#endif
