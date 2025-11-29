#ifndef HELPER_RSA_KEYGEN_H
#define HELPER_RSA_KEYGEN_H

/*Helper_RSA_Keygen.h*/

#include <string.h>
#include <stdio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/core_names.h>
#include <openssl/pem.h>
#include "Types.h"
#include <openssl/x509.h>






EVP_PKEY* generate_rsa_key(unsigned int bits);
int dump_key(const EVP_PKEY* pkey);


#endif
