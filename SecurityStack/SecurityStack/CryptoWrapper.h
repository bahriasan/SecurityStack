#ifndef CRYPTOWRAPPER_H
#define CRYPTOWRAPPER_H

/*CryptoWrapper.h*/



#include "Crypto_GeneralTypes.h"
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/cmac.h>
#include <openssl/params.h>
#include <openssl/decoder.h>
#include <openssl/encoder.h>

#define MAXJOBID	10u

typedef enum OpenSSLAlgorithmName
{
	AES128CBC,
	AES192CBC,
	AES256CBC,
	AES128CBCCTS,
	AES192CBCCTS,
	AES256CBCCTS,
	AES128CFB,
	AES192CFB,
	AES256CFB,
	AES128CFB1,
	AES192CFB1,
	AES256CFB1,
	AES128CFB8,
	AES192CFB8,
	AES256CFB8,
	AES128CTR,
	AES192CTR,
	AES256CTR,
	AES128ECB,
	AES192ECB,
	AES256ECB,
	AES192OFB,
	AES128OFB,
	AES256OFB,
	AES128XTS,
	AES256XTS,
	AES128CCM,
	AES192CCM,
	AES256CCM,
	AES128GCM,
	AES192GCM,
	AES256GCM,
	AES128WRAP,
	AES192WRAP,
	AES256WRAP,
	AES128WRAPPAD,
	AES192WRAPPAD,
	AES256WRAPPAD,
	AES128WRAPINV,
	AES192WRAPINV,
	AES256WRAPINV,
	AES128WRAPPADINV,
	AES192WRAPPADINV,
	AES256WRAPPADINV,
	AES128CBCHMACSHA1,
	AES256CBCHMACSHA1,
	AES128CBCHMACSHA256,
	AES256CBCHMACSHA256,
	AES128OCB,
	AES192OCB,
	AES256OCB,
	AES128SIV,
	AES192SIV,
	AES256SIV,
	AES128GCMSIV,
	AES192GCMSIV,
	AES256GCMSIV
}OpenSSLAlgorithmName;

typedef struct
{
	EVP_MAC_CTX* mac_mctx_buffer;
	EVP_MD_CTX* md_mctx_buffer;
}mctx_buffer;

Std_ReturnType Hash(Crypto_JobType* job, uint8* key, size_t keyLength);
Std_ReturnType MacGenerate(Crypto_JobType* job, uint8* key, size_t keyLength);
Std_ReturnType MacVerify(Crypto_JobType* job, uint8* key, size_t keyLength);
Std_ReturnType Random_Generate(Crypto_JobType* job, uint8* key, size_t keyLength);
Std_ReturnType Signature_Generate(Crypto_JobType* job, uint8* key, size_t keyLength);
Std_ReturnType Signature_Verify(Crypto_JobType* job, uint8* key, size_t keyLength);


#endif
