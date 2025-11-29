#ifndef TYPES_H
#define TYPES_H

#include <stdio.h>

typedef unsigned int uint32;
typedef unsigned char uint8;
typedef unsigned short uint16;

typedef unsigned char boolean;

#define TRUE	(uint8)0x01u
#define FALSE	(uint8)0x00u

#define BIT128RESULT	16u		//Result Size for AES-128
#define BYTE256RESULT   256u    //Result Size for RSA-2048 Signature Generate


#define BYTE16KEY	16u		//Key for AES-128-CBC
#define BYTE24KEY	24u		//Key for AES-192-CBC
#define BYTE32KEY	32u		//Key for AES-256-CBC

#define RSAPRIVATEKEYLENGTH   1192u   //Private Key for RSA-2048 Signature in der   
#define RSAPUBLICKEYLENGTH    288u    //Public Key for RSA-2048 Signature in der

//from bn_local.h in Openssl
struct bignum_st {
    unsigned long long* d;                /*
                                 * Pointer to an array of 'BN_BITS2' bit
                                 * chunks. These chunks are organised in
                                 * a least significant chunk first order.
                                 */
    int top;                    /* Index of last used d +1. */
    /* The next are internal book keeping for bn_expand. */
    int dmax;                   /* Size of the d array. */
    int neg;                    /* one if the number is negative */
    int flags;
};


//struct bio_st {
//    OSSL_LIB_CTX *libctx;
//    const BIO_METHOD *method;
//    /* bio, mode, argp, argi, argl, ret */
//#ifndef OPENSSL_NO_DEPRECATED_3_0
//    BIO_callback_fn callback;
//#endif
//    BIO_callback_fn_ex callback_ex;
//    char* cb_arg;               /* first argument for the callback */
//    int init;
//    int shutdown;
//    int flags;                  /* extra storage */
//    int retry_reason;
//    int num;
//    void* ptr;
//    struct bio_st* next_bio;    /* used by filter BIOs */
//    struct bio_st* prev_bio;    /* used by filter BIOs */
//    CRYPTO_REF_COUNT references;
//    uint64_t num_read;
//    uint64_t num_write;
//    CRYPTO_EX_DATA ex_data;
//}; 

#endif
