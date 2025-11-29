#include <stdint.h>
#include <stdio.h>
#include <stddef.h>

#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/decoder.h>
#include <openssl/encoder.h>
#include <openssl/params.h>


static uint8_t ec_privkey_pkcs8_der[] = {
  0x30, 0x81, 0xee, 0x02, 0x01, 0x00, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86,
  0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23,
  0x04, 0x81, 0xd6, 0x30, 0x81, 0xd3, 0x02, 0x01, 0x01, 0x04, 0x42, 0x01,
  0x9f, 0xb0, 0x80, 0x57, 0xfb, 0x00, 0xf0, 0x27, 0x97, 0xcb, 0x90, 0x0c,
  0x5f, 0x09, 0x92, 0xba, 0x18, 0xfb, 0x56, 0x5c, 0x3b, 0xd3, 0x3e, 0x97,
  0x7d, 0x04, 0xf5, 0x23, 0xed, 0xe2, 0xd5, 0x12, 0x07, 0xbe, 0x51, 0x6d,
  0x52, 0x6b, 0xb5, 0xd9, 0x0a, 0x5d, 0x87, 0xb4, 0x2c, 0x9f, 0xab, 0x83,
  0x18, 0x69, 0x71, 0xa9, 0x89, 0x12, 0xdc, 0x7a, 0xc7, 0x47, 0xfa, 0xca,
  0x9b, 0xa6, 0xd2, 0xdb, 0xfc, 0xa1, 0x81, 0x89, 0x03, 0x81, 0x86, 0x00,
  0x04, 0x00, 0xfe, 0xc9, 0xbb, 0xa3, 0x5c, 0x64, 0x80, 0xab, 0xd2, 0x3d,
  0x59, 0xd9, 0x22, 0x39, 0xef, 0xe2, 0x0e, 0x5a, 0x59, 0x4a, 0xc9, 0x12,
  0x31, 0x81, 0xd8, 0x25, 0x2c, 0x6a, 0x23, 0x99, 0xe5, 0x07, 0xb4, 0x35,
  0x00, 0x74, 0xa6, 0x4e, 0x72, 0xf5, 0xe4, 0xd1, 0xd6, 0x3a, 0x35, 0xc3,
  0x0e, 0x04, 0x07, 0x61, 0x11, 0xa4, 0x1c, 0xf4, 0x6d, 0x9e, 0xa4, 0x5e,
  0xc7, 0x32, 0x15, 0xeb, 0x37, 0xb8, 0x59, 0x01, 0x90, 0x00, 0x8b, 0xd8,
  0xb7, 0xad, 0xb6, 0xb0, 0x55, 0xb6, 0xe6, 0x0c, 0xb3, 0x5e, 0x92, 0xb5,
  0x46, 0x67, 0x67, 0x1e, 0x53, 0x29, 0xad, 0x8f, 0x62, 0x66, 0x5b, 0x2d,
  0xca, 0x0c, 0x23, 0x35, 0x58, 0x6a, 0xd2, 0x00, 0xc1, 0x4f, 0x81, 0xe5,
  0xfb, 0x09, 0x6c, 0x61, 0x7f, 0x16, 0xb4, 0x83, 0x30, 0x1f, 0xd3, 0x64,
  0x82, 0x69, 0x32, 0x0f, 0x4c, 0x1f, 0xa9, 0x3b, 0x2e, 0x77, 0xf4, 0xcc,
  0x6b
};

static uint8_t ec_pubkey_x509_der[] = {
  0x30, 0x81, 0x9b, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d,
  0x02, 0x01, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23, 0x03, 0x81, 0x86,
  0x00, 0x04, 0x00, 0xfe, 0xc9, 0xbb, 0xa3, 0x5c, 0x64, 0x80, 0xab, 0xd2,
  0x3d, 0x59, 0xd9, 0x22, 0x39, 0xef, 0xe2, 0x0e, 0x5a, 0x59, 0x4a, 0xc9,
  0x12, 0x31, 0x81, 0xd8, 0x25, 0x2c, 0x6a, 0x23, 0x99, 0xe5, 0x07, 0xb4,
  0x35, 0x00, 0x74, 0xa6, 0x4e, 0x72, 0xf5, 0xe4, 0xd1, 0xd6, 0x3a, 0x35,
  0xc3, 0x0e, 0x04, 0x07, 0x61, 0x11, 0xa4, 0x1c, 0xf4, 0x6d, 0x9e, 0xa4,
  0x5e, 0xc7, 0x32, 0x15, 0xeb, 0x37, 0xb8, 0x59, 0x01, 0x90, 0x00, 0x8b,
  0xd8, 0xb7, 0xad, 0xb6, 0xb0, 0x55, 0xb6, 0xe6, 0x0c, 0xb3, 0x5e, 0x92,
  0xb5, 0x46, 0x67, 0x67, 0x1e, 0x53, 0x29, 0xad, 0x8f, 0x62, 0x66, 0x5b,
  0x2d, 0xca, 0x0c, 0x23, 0x35, 0x58, 0x6a, 0xd2, 0x00, 0xc1, 0x4f, 0x81,
  0xe5, 0xfb, 0x09, 0x6c, 0x61, 0x7f, 0x16, 0xb4, 0x83, 0x30, 0x1f, 0xd3,
  0x64, 0x82, 0x69, 0x32, 0x0f, 0x4c, 0x1f, 0xa9, 0x3b, 0x2e, 0x77, 0xf4,
  0xcc, 0x6b
};

static uint8_t s_sig[256];
static size_t s_sigsize = sizeof(s_sig);
static uint8_t s_digest[32] = { 0 };
static size_t s_digestsize = sizeof(s_digest);

static inline void ossl_print_error(void)
{
	char err[256];
	unsigned long e = ERR_get_error();

	ERR_error_string_n(e, err, sizeof(err));
	fprintf(stderr, "%s\n", err);
}

static int openssl_key_from_raw(const uint8_t* buf, size_t keysize, EVP_PKEY** pkey, int keytype, const char* keyalg,
	const char* fmt, const char* objfmt)
{
	int ret = 0;
	OSSL_DECODER_CTX* ctx;

	ctx = OSSL_DECODER_CTX_new_for_pkey(pkey, fmt, objfmt, keyalg, keytype, NULL, NULL);
	if (ctx == NULL) {
		ret = 1;
		goto done;
	}

	if (OSSL_DECODER_from_data(ctx, &buf, &keysize) <= 0) {
		ret = 1;
	}

done:
	OSSL_DECODER_CTX_free(ctx);
	return ret;
}

static int openssl_manual_pub_key(EVP_PKEY* orig, EVP_PKEY** new)
{
	int ret;
	uint8_t pubkey[256];
	size_t pubkeysize = 0;
	char group[128];
	EVP_PKEY_CTX* ctx;
	OSSL_PARAM ossl_params[3];

	ret = EVP_PKEY_get_utf8_string_param(orig, OSSL_PKEY_PARAM_GROUP_NAME, group, sizeof(group), NULL);
	if (ret <= 0) {
		ossl_print_error();
		fprintf(stderr, "failed to extract group name\n");
		goto done;
	}
	else {
		printf("group name '%s'\n", group);
	}

	ret = EVP_PKEY_get_octet_string_param(orig, OSSL_PKEY_PARAM_PUB_KEY, pubkey, sizeof(pubkey), &pubkeysize);
	if (ret <= 0) {
		ossl_print_error();
		fprintf(stderr, "failed to extract pubkey\n");
		goto done;
	}
	else {
		printf("pubkey extracted\n");
	}

	ossl_params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, group, 0);
	ossl_params[1] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, pubkey, pubkeysize);
	ossl_params[2] = OSSL_PARAM_construct_end();

	ctx = EVP_PKEY_CTX_new_from_name(NULL, "ec", NULL);
	if (ctx == NULL) {
		fprintf(stderr, "unable to allocate context memory");
		ret = -1;
		goto done;
	}

	ret = EVP_PKEY_fromdata_init(ctx);
	if (ret <= 0) {
		fprintf(stderr, "unable to initialize context");
		goto done;
	}

	ret = EVP_PKEY_fromdata(ctx, new, OSSL_KEYMGMT_SELECT_ALL_PARAMETERS | OSSL_KEYMGMT_SELECT_PUBLIC_KEY, ossl_params);
	if (ret <= 0) {
		fprintf(stderr, "unable to convert public key");
	}

done:
	return ret;
}

static int openssl_manual_priv_key(EVP_PKEY* orig, EVP_PKEY** new)
{
	int ret;
	uint8_t privkey[256];
	size_t privkeysize = 0;
	char group[128];
	EVP_PKEY_CTX* ctx;
	OSSL_PARAM ossl_params[3];
	BIGNUM* bn_priv = NULL;

	ret = EVP_PKEY_get_utf8_string_param(orig, OSSL_PKEY_PARAM_GROUP_NAME, group, sizeof(group), NULL);
	if (ret <= 0) {
		ossl_print_error();
		fprintf(stderr, "failed to extract group name\n");
		goto done;
	}
	else {
		printf("group name '%s'\n", group);
	}

	ret = EVP_PKEY_get_bn_param(orig, OSSL_PKEY_PARAM_PRIV_KEY, &bn_priv);
	if (ret <= 0) {
		ossl_print_error();
		fprintf(stderr, "failed to extract privkey\n");
		goto done;
	}
	else {
		printf("privkey extracted\n");
	}

	privkeysize = BN_num_bytes(bn_priv);
	BN_bn2bin(bn_priv, privkey);

	ossl_params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, group, 0);
	ossl_params[1] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_PRIV_KEY, privkey, privkeysize);
	ossl_params[2] = OSSL_PARAM_construct_end();

	ctx = EVP_PKEY_CTX_new_from_name(NULL, "ec", NULL);
	if (ctx == NULL) {
		fprintf(stderr, "unable to allocate context memory\n");
		ret = -1;
		goto done;
	}

	ret = EVP_PKEY_fromdata_init(ctx);
	if (ret <= 0) {
		fprintf(stderr, "unable to initialize context\n");
		goto done;
	}

	ret = EVP_PKEY_fromdata(ctx, new, OSSL_KEYMGMT_SELECT_ALL_PARAMETERS | OSSL_KEYMGMT_SELECT_KEYPAIR, ossl_params);
	if (ret <= 0) {
		fprintf(stderr, "unable to convert private key\n");
	}

done:
	return ret;
}

static int openssl_sign(EVP_PKEY* privkey, uint8_t* sig, size_t* sigsize)
{
	int ret;
	EVP_PKEY_CTX* pkey_ctx;

	pkey_ctx = EVP_PKEY_CTX_new(privkey, NULL);
	if (pkey_ctx == NULL) {
		ret = -1;
		goto done;
	}
	ret = EVP_PKEY_sign_init(pkey_ctx);
	if (ret <= 0) {
		ossl_print_error();
		fprintf(stderr, "sign init failed\n");
		goto done;
	}

	ret = EVP_PKEY_private_check(pkey_ctx);
	if (ret <= 0) {
		ossl_print_error();
		fprintf(stderr, "invalid private key\n");
		goto done;
	}

	ret = EVP_PKEY_CTX_set_signature_md(pkey_ctx, EVP_sha256());
	if (ret <= 0) {
		ossl_print_error();
		fprintf(stderr, "signature md failed\n");
		goto done;
	}

	ret = EVP_PKEY_sign(pkey_ctx, sig, sigsize, s_digest, s_digestsize);
	if (ret <= 0) {
		ossl_print_error();
	}

done:
	EVP_PKEY_CTX_free(pkey_ctx);
	return ret;
}

static int openssl_verify(EVP_PKEY* pubkey, uint8_t* sig, size_t sigsize)
{
	int ret;
	EVP_PKEY_CTX* pkey_ctx;

	pkey_ctx = EVP_PKEY_CTX_new(pubkey, NULL);
	if (pkey_ctx == NULL) {
		ret = -1;
		goto done;
	}

	ret = EVP_PKEY_verify_init(pkey_ctx);
	if (ret <= 0) {
		ossl_print_error();
		fprintf(stderr, "verify init failed\n");
		goto done;
	}

	ret = EVP_PKEY_public_check(pkey_ctx);
	if (ret <= 0) {
		ossl_print_error();
		fprintf(stderr, "invalid public key\n");
		goto done;
	}

	ret = EVP_PKEY_CTX_set_signature_md(pkey_ctx, EVP_sha256());
	if (ret <= 0) {
		ossl_print_error();
		fprintf(stderr, "signature md failed\n");
		goto done;
	}

	ret = EVP_PKEY_verify(pkey_ctx, sig, sigsize, s_digest, s_digestsize);
	if (ret <= 0) {
		ossl_print_error();
	}

done:
	EVP_PKEY_CTX_free(pkey_ctx);
	return ret;
}

int demo(void)
{
	int ret;
	EVP_PKEY* privkey = NULL;
	EVP_PKEY* pubkey = NULL;
	EVP_PKEY* alt_pubkey = NULL;
	EVP_PKEY* alt_privkey = NULL;

	ret = openssl_key_from_raw(ec_privkey_pkcs8_der, sizeof(ec_privkey_pkcs8_der),
		&privkey, EVP_PKEY_PRIVATE_KEY, "EC", "DER", "PrivateKeyInfo");

	if (ret != 0) {
		fprintf(stderr, "failed decoding private key\n");
		goto done;
	}
	else {
		printf("decoded private key\n");
	}

	if (PEM_write_PrivateKey(stdout, privkey, NULL, NULL, 0, NULL, NULL) == 0) {
		fprintf(stderr, "Failed to output PEM-encoded private key\n");
		goto done;
	}

	ret = openssl_key_from_raw(ec_pubkey_x509_der, sizeof(ec_pubkey_x509_der),
		&pubkey, EVP_PKEY_PUBLIC_KEY, "EC", "DER", "SubjectPublicKeyInfo");

	if (ret != 0) {
		fprintf(stderr, "failed decoding public key\n");
		goto done;
	}
	else {
		printf("decoded public key\n");
	}

	if (PEM_write_PUBKEY(stdout, pubkey) == 0) {
		fprintf(stderr, "Failed to output PEM-encoded public key\n");
		goto done;
	}

	//ret = openssl_sign(privkey, s_sig, &s_sigsize);
	//if (ret <= 0) {
	//	fprintf(stderr, "failed generating signature ret = %d\n", ret);
	//	goto done;
	//}
	//else {
	//	printf("signature generated\n");
	//}

	//ret = openssl_verify(pubkey, s_sig, s_sigsize);
	//if (ret <= 0) {
	//	fprintf(stderr, "signature verification failed ret = %d\n", ret);
	//	goto done;
	//}
	//else {
	//	printf("signature OK!\n");
	//}

	//ret = openssl_manual_pub_key(pubkey, &alt_pubkey);
	//if (ret <= 0) {
	//	fprintf(stderr, "failed to create manual public key\n");
	//}
	//else {
	//	printf("created manual public key\n");
	//}

	//ret = openssl_verify(alt_pubkey, s_sig, s_sigsize);
	//if (ret <= 0) {
	//	fprintf(stderr, "signature verification failed ret = %d\n", ret);
	//	goto done;
	//}
	//else {
	//	printf("signature OK!\n");
	//}

	//ret = openssl_manual_priv_key(privkey, &alt_privkey);
	//if (ret <= 0) {
	//	fprintf(stderr, "failed to create manual private key\n");
	//}
	//else {
	//	printf("created manual private key\n");
	//}

	//s_sigsize = sizeof(s_sig);

	//ret = openssl_sign(alt_privkey, s_sig, &s_sigsize);
	//if (ret <= 0) {
	//	fprintf(stderr, "failed generating signature ret = %d\n", ret);
	//	goto done;
	//}
	//else {
	//	printf("signature generated\n");
	//}

	//ret = openssl_verify(pubkey, s_sig, s_sigsize);
	//if (ret <= 0) {
	//	fprintf(stderr, "signature verification failed ret = %d\n", ret);
	//	goto done;
	//}
	//else {
	//	printf("signature OK!\n");
	//}

done:
	return ret;
}
