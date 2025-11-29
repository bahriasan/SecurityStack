
#include "Helper_RSA_Keygen.h"

//For "SSL. no OPENSSL_Applink" error
#include <openssl/applink.c>


EVP_PKEY* generate_rsa_key(unsigned int bits)
{
    OSSL_LIB_CTX* libctx = NULL;
    EVP_PKEY_CTX* genctx = NULL;
    EVP_PKEY* pkey = NULL;
    unsigned int primes = 2;
    static const char* propq = NULL;
    int bits_l = 0;

    /* Create context using RSA algorithm. "RSA-PSS" could also be used here. */
    genctx = EVP_PKEY_CTX_new_from_name(libctx, "RSA", propq);
    if (genctx == NULL) {
        fprintf(stderr, "EVP_PKEY_CTX_new_from_name() failed\n");
        goto cleanup;
    }

    /* Initialize context for key generation purposes. */
    if (EVP_PKEY_keygen_init(genctx) <= 0) {
        fprintf(stderr, "EVP_PKEY_keygen_init() failed\n");
        goto cleanup;
    }

    fprintf(stdout, "Generating RSA key, this may take some time...\n");
    if (EVP_PKEY_generate(genctx, &pkey) <= 0) {
        fprintf(stderr, "EVP_PKEY_generate() failed\n");
        goto cleanup;
    }

cleanup:
    EVP_PKEY_CTX_free(genctx);
    OSSL_LIB_CTX_free(libctx);
    return pkey;
}

int dump_key(const EVP_PKEY* pkey)
{
    int ret = 0;
	BIGNUM* n = NULL, * e = NULL, * d = NULL, * p = NULL, * q = NULL, * f3 = NULL, * dp = NULL, * dq = NULL, * e3 = NULL, * qinv = NULL, * c2 = NULL;

	if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_N, &n) == 0) {
		fprintf(stderr, "Failed to retrieve n\n");
		goto cleanup;
	}
       
    printf("n: \n");
    char* arr_n = BN_bn2hex(n);
    printf("%s\n", arr_n);

	if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_E, &e) == 0) {
		fprintf(stderr, "Failed to retrieve e\n");
		goto cleanup;
	}

    //printf("e: \n");
    //char* arr_e = BN_bn2hex(e);
    //printf("%s\n", arr_e);

	if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_D, &d) == 0) {
		fprintf(stderr, "Failed to retrieve d\n");
		goto cleanup;
	}
    
    //printf("d: \n");
    //char* arr_d = BN_bn2hex(d);
    //printf("%s\n", arr_d);

	if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_FACTOR1, &p) == 0) {
		fprintf(stderr, "Failed to retrieve p\n");
		goto cleanup;
	}
    
    //printf("p: \n");
    //char* arr_p = BN_bn2hex(p);
    //printf("%s\n", arr_p);

	if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_FACTOR2, &q) == 0) {
		fprintf(stderr, "Failed to retrieve q\n");
		goto cleanup;
	}
    
    //printf("q: \n");
    //char* arr_q = BN_bn2hex(q);
    //printf("%s\n", arr_q);

    if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_EXPONENT1, &dp) == 0) {
        fprintf(stderr, "Failed to retrieve dp\n");
        goto cleanup;
    }

    //printf("dp: \n");
    //char* arr_dp = BN_bn2hex(dp);
    //printf("%s", arr_dp);

    if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_EXPONENT2, &dq) == 0) {
        fprintf(stderr, "Failed to retrieve dq\n");
        goto cleanup;
    }

    //printf("dq: \n");
    //char* arr_dq = BN_bn2hex(dq);
    //printf("%s\n", arr_dq);


    if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_COEFFICIENT1, &qinv) == 0) {
        fprintf(stderr, "Failed to retrieve qinv\n");
        goto cleanup;
    }

    //printf("qinv: \n");
    //char* arr_qinv = BN_bn2hex(qinv);
    //printf("%s\n", arr_qinv);

    /* Output a PEM encoding of the public key. */
    if (PEM_write_PUBKEY(stdout, pkey) == 0) {
        fprintf(stderr, "Failed to output PEM-encoded public key\n");
        goto cleanup;
    }

    if (PEM_write_PrivateKey(stdout, pkey, NULL, NULL, 0, NULL, NULL) == 0) {
        fprintf(stderr, "Failed to output PEM-encoded private key\n");
        goto cleanup;
    }

    /*Private and Public Key in Hex*/
    size_t byte_no1, byte_no2;
    char data1[2000], data2[300];
    BIO* mem1 = BIO_new(BIO_s_mem());
    i2d_PrivateKey_bio(mem1, pkey);
    BIO_read_ex(mem1, data1, sizeof(data1), &byte_no1);

    BIO* mem2 = BIO_new(BIO_s_mem());
    i2d_PUBKEY_bio(mem2, pkey);     //Pubkey yazılımında hata var, fazladan 24 byte yazıyor der formatına uygun
    BIO_read_ex(mem2, data2, sizeof(data2), &byte_no2);


    BIO_free(mem1);
    BIO_free(mem2);

    printf("Private Key size:%d\n", byte_no1);
    for (int i = 0; i != byte_no1; ++i)
    {
        printf("0x%02hhx ", data1[i]);
    }

    printf("\n(i2d_PUBKEY_bio)Public Key size:%d\n", byte_no2);
    for (int i = 0; i != byte_no2; ++i)
    {
        printf("0x%02hhx ", data2[i]);
    }






    ret = 1;

cleanup:
    return ret;
}

/*
Private Key: der Format(with Headers)
1. n(256)
2. d(256)
3. p(128)
4. q(128)
5. dp(128)
6. dq(128)
7. qinv(128)

Public Key: der Format(with Headers)
1. n
2. e
*/

