
#include "CryptoWrapper.h"

static Std_ReturnType MacGenerate_Init(Crypto_JobType* job, uint8* key, size_t keyLength);
static Std_ReturnType MacGenerate_Update(Crypto_JobType* job);
static Std_ReturnType MacGenerate_Finish(Crypto_JobType* job);

//This array was sized genericly, should be in the same size of MaxJobId
static mctx_buffer ctx_buffer[MAXJOBID] = { 0 };

static char* getCipherNameStr(Crypto_JobType* job, uint32 keySize, uint8* cipher_size)
{
	Crypto_AlgorithmFamilyType algoFam = job->jobPrimitiveInfoRef->primitiveInfo->algorithm.family;
	Crypto_AlgorithmModeType algoMode = job->jobPrimitiveInfoRef->primitiveInfo->algorithm.mode;
	char name_AES128CBC[] = "AES-128-CBC", name_AES192CBC[] = "AES-192-CBC", name_AES256CBC[] = "AES-256-CBC";
	

	if (CRYPTO_ALGOFAM_AES == algoFam && CRYPTO_ALGOMODE_CBC == algoMode && BYTE16KEY == keySize)
	{
		*cipher_size = sizeof(name_AES128CBC);
		char* name = malloc(*cipher_size);
		if (name)	//if not nullptr
			memcpy(name, name_AES128CBC, *cipher_size);
		return name;
	}
	else if (CRYPTO_ALGOFAM_AES == algoFam && CRYPTO_ALGOMODE_CBC == algoMode && BYTE24KEY == keySize)
	{
		*cipher_size = sizeof(name_AES192CBC);
		char* name = malloc(*cipher_size);
		if (name)	//if not nullptr
			memcpy(name, name_AES192CBC, *cipher_size);
		return name;
	}
	else if (CRYPTO_ALGOFAM_AES == algoFam && CRYPTO_ALGOMODE_CBC == algoMode && BYTE32KEY == keySize)
	{
		*cipher_size = sizeof(name_AES256CBC);
		char* name = malloc(*cipher_size);
		if (name)	//if not nullptr
			memcpy(name, name_AES256CBC, *cipher_size);
		return name;
	}
	else
	{
		//Rest TBD
	}
}

static Std_ReturnType MacGenerate_Init(Crypto_JobType* job, uint8* key, size_t keyLength)
{
	static const char* propq = NULL;
	OSSL_LIB_CTX* library_context = NULL;
	EVP_MAC* mac = NULL;
	EVP_MAC_CTX* mctx = NULL;
	OSSL_PARAM params[4], * p = params;
	uint8 cipher_size = 0;
	int retval = 0;
	Std_ReturnType ret = E_NOT_OK;

	/* Previously stored data for this job should be reset first if another instance is ongoing */
	/* [SWS_Crypto_00020] */
	if (ctx_buffer[job->jobId].mac_mctx_buffer != NULL)
	{
		EVP_MAC_CTX_free(ctx_buffer[job->jobId].mac_mctx_buffer);
		ctx_buffer[job->jobId].mac_mctx_buffer = NULL;
	}

	char* cipher_name = getCipherNameStr(job, keyLength, &cipher_size);

	library_context = OSSL_LIB_CTX_new();
	mac = EVP_MAC_fetch(library_context, "CMAC", propq);
	mctx = EVP_MAC_CTX_new(mac);
	*p++ = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_CIPHER, cipher_name, sizeof(cipher_name));
	*p = OSSL_PARAM_construct_end();

	retval = EVP_MAC_init(mctx, key, keyLength, params);

	//if op. is successfull make state active
	if (retval)
	{
		job->jobState = CRYPTO_JOBSTATE_ACTIVE;
		//store mctx address
		ctx_buffer[job->jobId].mac_mctx_buffer = mctx;
		ret = E_OK;
	}
	else
	{
		//[SWS_Crypto_00025]
		EVP_MAC_CTX_free(mctx);
	}
		
	free(cipher_name);		//Should be freed by caller
	EVP_MAC_free(mac);
	OSSL_LIB_CTX_free(library_context);

	return ret;
}

static Std_ReturnType MacGenerate_Update(Crypto_JobType* job)
{
	Std_ReturnType ret = E_NOT_OK;
	int retval = 0;

	uint8* data = job->jobPrimitiveInputOutput.inputPtr;
	uint32 inputLength = job->jobPrimitiveInputOutput.inputLength;
	EVP_MAC_CTX* mctx = ctx_buffer[job->jobId].mac_mctx_buffer;

	retval = EVP_MAC_update(mctx, data, inputLength);

	if (retval)
	{
		ret = E_OK;
	}
	else
	{
		//[SWS_Crypto_00025]
		//Free mctx
		EVP_MAC_CTX_free(mctx);
		ctx_buffer[job->jobId].mac_mctx_buffer = NULL;
		job->jobState = CRYPTO_JOBSTATE_IDLE;
		ret = E_NOT_OK;
	}
		
	return ret;
}

static Std_ReturnType MacGenerate_Finish(Crypto_JobType* job)
{
	size_t out_len = 0;
	uint8* outputPtr = job->jobPrimitiveInputOutput.outputPtr;
	uint32* outputLengthPtr = job->jobPrimitiveInputOutput.outputLengthPtr;
	EVP_MAC_CTX* mctx = ctx_buffer[job->jobId].mac_mctx_buffer;
	int retval = 0;
	Std_ReturnType ret = E_NOT_OK;

	retval = EVP_MAC_final(mctx, NULL, &out_len, 0);

	if (retval)
	{
		//[SWS_Crypto_00065]
		//if Output is larger than ExpectedOutputLength 
		if (*outputLengthPtr < out_len)
		{
			retval = EVP_MAC_final(mctx, outputPtr, &out_len, *outputLengthPtr);
		}
		else //if Output is equal or less than ExpectedOutputLength 
		{
			retval = EVP_MAC_final(mctx, outputPtr, &out_len, out_len);
		}
	}

	if (retval)
	{
		*outputLengthPtr = out_len;
		ret = E_OK;
	}
	else
	{
		ret = E_NOT_OK;
	}

	//[SWS_Crypto_00025]
	//Free mctx
	EVP_MAC_CTX_free(mctx);
	ctx_buffer[job->jobId].mac_mctx_buffer = NULL;
	job->jobState = CRYPTO_JOBSTATE_IDLE;

	return ret;
}

static Std_ReturnType MacVerify_Init(Crypto_JobType* job, uint8* key, size_t keyLength)
{
	return MacGenerate_Init(job, key, keyLength);
}

static Std_ReturnType MacVerify_Update(Crypto_JobType* job)
{
	return MacGenerate_Update(job);
}

static Std_ReturnType MacVerify_Finish(Crypto_JobType* job)
{
	size_t out_len = 0;
	uint8* macPtr = job->jobPrimitiveInputOutput.secondaryInputPtr;
	uint32 macLength = job->jobPrimitiveInputOutput.secondaryInputLength;
	Crypto_VerifyResultType* verify = job->jobPrimitiveInputOutput.verifyPtr;
	EVP_MAC_CTX* mctx = ctx_buffer[job->jobId].mac_mctx_buffer;
	int retval = 0;
	Std_ReturnType ret = E_NOT_OK;

	retval = EVP_MAC_final(mctx, NULL, &out_len, 0);

	if (retval)
	{
		//if output size doesn't match 
		if (out_len != macLength)
		{
			ret = E_NOT_OK;
		}
		else
		{
			uint8* outputPtr = malloc(out_len);
			retval = EVP_MAC_final(mctx, outputPtr, &out_len, out_len);

			if (retval)
			{
				if (outputPtr)
				{
					if (!memcmp(outputPtr, macPtr, out_len))
					{
						*verify = CRYPTO_E_VER_OK;
					}
					else
					{
						*verify = CRYPTO_E_VER_NOT_OK;
					}
					ret = E_OK;
				}
			}
			free(outputPtr);
		}
	}

	//[SWS_Crypto_00025]
	//Free mctx
	EVP_MAC_CTX_free(mctx);
	ctx_buffer[job->jobId].mac_mctx_buffer = NULL;
	job->jobState = CRYPTO_JOBSTATE_IDLE;
	return ret;
}

static Std_ReturnType Signature_Generate_Init(Crypto_JobType* job, uint8* key, size_t keyLength)
{
	int ret = 0;
	EVP_PKEY* pkey = NULL;
	EVP_MD_CTX* mctx = NULL;
	OSSL_LIB_CTX* libctx = NULL;
	OSSL_PARAM params[2], * p = params;
	const unsigned char* ppriv_key = NULL;

	/* A property query used for selecting algorithm implementations. */
	const char* propq = NULL;

	/* Previously stored data for this job should be reset first if another instance is ongoing */
	/* [SWS_Crypto_00020] */
	if (ctx_buffer[job->jobId].md_mctx_buffer != NULL)
	{
		EVP_MD_CTX_free(ctx_buffer[job->jobId].md_mctx_buffer);
		ctx_buffer[job->jobId].md_mctx_buffer = NULL;
	}

	/* Load DER-encoded RSA private key. */
	ppriv_key = key;
	pkey = d2i_PrivateKey_ex(EVP_PKEY_RSA, NULL, &ppriv_key, keyLength, libctx, propq);
	if (pkey == NULL) {
		fprintf(stderr, "Failed to load private key\n");
		ret = 1;
		goto end;
	}

	printf("\nSignature Generated with RSA2048 Private Key:\n");
	if (PEM_write_PrivateKey(stdout, pkey, NULL, NULL, 0, NULL, NULL) == 0) {
		fprintf(stderr, "Failed to output PEM-encoded private key\n");
	}

	/* Create MD context used for signing. */
	mctx = EVP_MD_CTX_new();
	if (mctx == NULL) {
		fprintf(stderr, "Failed to create MD context\n");
		ret = 1;
		goto end;
	}

	/* Initialize MD context for signing. */
	*p++ = OSSL_PARAM_construct_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE,
		OSSL_PKEY_RSA_PAD_MODE_PSS, 0);
	*p = OSSL_PARAM_construct_end();

	if (EVP_DigestSignInit_ex(mctx, NULL, "SHA256", libctx, propq, pkey, params) == 0) {
		fprintf(stderr, "Failed to initialize signing context\n");
		goto end;
	}

	ret = 2;

end:
	EVP_PKEY_free(pkey);
	OSSL_LIB_CTX_free(libctx);

	if (ret == 1)	//no mctx allocated yet
	{
		fprintf(stderr, "failed generating signature ret = %d\n", ret);
		return E_NOT_OK;
	}
	else
	{
		if (ret == 0)
		{
			//[SWS_Crypto_00025]
			fprintf(stderr, "failed generating signature ret = %d\n", ret);
			EVP_MD_CTX_free(mctx);
			return E_NOT_OK;
		}
		else if (ret == 2)
		{
			job->jobState = CRYPTO_JOBSTATE_ACTIVE;
			ctx_buffer[job->jobId].md_mctx_buffer = mctx;
			return E_OK;
		}
	}
}

static Std_ReturnType Signature_Generate_Update(Crypto_JobType* job)
{
	/*
	 * Feed data to be signed into the algorithm. This may
	 * be called multiple times.
	 */

	EVP_MD_CTX* mctx = ctx_buffer[job->jobId].md_mctx_buffer;

	if (EVP_DigestSignUpdate(mctx, job->jobPrimitiveInputOutput.inputPtr, job->jobPrimitiveInputOutput.inputLength) == 0) {
		fprintf(stderr, "Failed to hash message into signing context\n");

		//[SWS_Crypto_00025]
		EVP_MD_CTX_free(mctx);
		ctx_buffer[job->jobId].md_mctx_buffer = NULL;
		job->jobState = CRYPTO_JOBSTATE_IDLE;
		return E_NOT_OK;
	}

	return E_OK;
}

static Std_ReturnType Signature_Generate_Finish(Crypto_JobType* job)
{
	int ret = 0;
	size_t sig_len;
	EVP_MD_CTX* mctx = ctx_buffer[job->jobId].md_mctx_buffer;

	/* Determine signature length. */
	if (EVP_DigestSignFinal(mctx, NULL, &sig_len) == 0) {
		fprintf(stderr, "Failed to get signature length\n");
		goto end;
	}

	if (sig_len > *(job->jobPrimitiveInputOutput.outputLengthPtr))
	{
		fprintf(stderr, "Fatal signature length\n");
		goto end;
	}

	/* In case signature is shorter than the expected signature size */
	memset(job->jobPrimitiveInputOutput.outputPtr, 0u, *(job->jobPrimitiveInputOutput.outputLengthPtr));

	/* Generate signature. */
	if (EVP_DigestSignFinal(mctx, job->jobPrimitiveInputOutput.outputPtr, &sig_len) == 0) {
		fprintf(stderr, "Failed to sign\n");
		goto end;
	}

	ret = 1;
end:

	if (ret == 0)
	{
		fprintf(stderr, "failed generating signature ret = %d\n", ret);
		ret =  E_NOT_OK;
	}
	else
	{
		ret = E_OK;
	}

	//[SWS_Crypto_00025]
	EVP_MD_CTX_free(mctx);
	ctx_buffer[job->jobId].md_mctx_buffer = NULL;
	job->jobState = CRYPTO_JOBSTATE_IDLE;

	return ret;
}

static Std_ReturnType Signature_Verify_Init(Crypto_JobType* job, uint8* key, size_t keyLength)
{
	int ret = 0;
	EVP_PKEY* pkey = NULL;
	EVP_MD_CTX* mctx = NULL;
	OSSL_PARAM params[2], * p = params;
	const unsigned char* ppub_key = NULL;
	OSSL_LIB_CTX* libctx = NULL;

	/* A property query used for selecting algorithm implementations. */
	const char* propq = NULL;

	/* Previously stored data for this job should be reset first if another instance is ongoing */
	/* [SWS_Crypto_00020] */
	if (ctx_buffer[job->jobId].md_mctx_buffer != NULL)
	{
		EVP_MD_CTX_free(ctx_buffer[job->jobId].md_mctx_buffer);
		ctx_buffer[job->jobId].md_mctx_buffer = NULL;
	}

	/* Load DER-encoded RSA public key. */
	ppub_key = key;
	pkey = d2i_PublicKey(EVP_PKEY_RSA, NULL, &ppub_key, keyLength);
	if (pkey == NULL) {
		fprintf(stderr, "Failed to load public key\n");
		ret = 1;
		goto end;
	}

	printf("\nSignature Verified with RSA2048 Public Key:\n");
	if (PEM_write_PUBKEY(stdout, pkey) == 0) {
		fprintf(stderr, "Failed to output PEM-encoded public key\n");
	}

	/* Create MD context used for verification. */
	mctx = EVP_MD_CTX_new();
	if (mctx == NULL) {
		fprintf(stderr, "Failed to create MD context\n");
		ret = 1;
		goto end;
	}

	/* Initialize MD context for verification. */
	*p++ = OSSL_PARAM_construct_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE,
		OSSL_PKEY_RSA_PAD_MODE_PSS, 0);
	*p = OSSL_PARAM_construct_end();

	if (EVP_DigestVerifyInit_ex(mctx, NULL, "SHA256", libctx, propq, pkey, params) == 0) {
		fprintf(stderr, "Failed to initialize signing context\n");
		goto end;
	}

	ret = 2;
end:

	if (ret == 1)	//no mctx allocated yet
	{
		//[SWS_Crypto_00025]
		fprintf(stderr, "failed verifying signature ret = %d\n", ret);
		return E_NOT_OK;
	}
	else
	{
		if (ret == 0)
		{	//[SWS_Crypto_00025]
			fprintf(stderr, "failed verifying signature ret = %d\n", ret);
			EVP_MD_CTX_free(mctx);
			return E_NOT_OK;
		}
		else if (ret == 2)
		{
			job->jobState = CRYPTO_JOBSTATE_ACTIVE;
			ctx_buffer[job->jobId].md_mctx_buffer = mctx;
			return E_OK;
		}
	}
}

static Std_ReturnType Signature_Verify_Update(Crypto_JobType* job)
{
	/*
	 * Feed data to be signed into the algorithm. This may
	 * be called multiple times.
	 */

	EVP_MD_CTX* mctx = ctx_buffer[job->jobId].md_mctx_buffer;

	if (EVP_DigestVerifyUpdate(mctx, job->jobPrimitiveInputOutput.inputPtr, job->jobPrimitiveInputOutput.inputLength) == 0) {
		fprintf(stderr, "Failed to hash message into signing context\n");
		//[SWS_Crypto_00025]
		//Free mctx
		EVP_MD_CTX_free(mctx);
		ctx_buffer[job->jobId].md_mctx_buffer = NULL;
		job->jobState = CRYPTO_JOBSTATE_IDLE;
		return E_NOT_OK;
	}

	return E_OK;
}

static Std_ReturnType Signature_Verify_Finish(Crypto_JobType* job)
{
	Std_ReturnType ret = E_NOT_OK;
	EVP_MD_CTX* mctx = ctx_buffer[job->jobId].md_mctx_buffer;

	/* Verify signature. */
	if (EVP_DigestVerifyFinal(mctx, job->jobPrimitiveInputOutput.secondaryInputPtr, job->jobPrimitiveInputOutput.secondaryInputLength) == 0) {
		fprintf(stderr, "Failed to verify signature: Invalid Signature\n");
		*(job->jobPrimitiveInputOutput.verifyPtr) = CRYPTO_E_VER_NOT_OK;
		ret = E_NOT_OK;
	}
	else
	{
		*(job->jobPrimitiveInputOutput.verifyPtr) = CRYPTO_E_VER_OK;
		ret = E_OK;
	}

	//[SWS_Crypto_00025]
	//Free mctx
	EVP_MD_CTX_free(mctx);
	ctx_buffer[job->jobId].md_mctx_buffer = NULL;
	job->jobState = CRYPTO_JOBSTATE_IDLE;
	return ret;
}


Std_ReturnType MacGenerate(Crypto_JobType* job, uint8* key, size_t keyLength)
{
	if (CRYPTO_OPERATIONMODE_START == job->jobPrimitiveInputOutput.mode)
	{
		return MacGenerate_Init(job, key, keyLength);
	}
	else if (CRYPTO_OPERATIONMODE_UPDATE == job->jobPrimitiveInputOutput.mode)
	{
		return MacGenerate_Update(job);
	}
	else if (CRYPTO_OPERATIONMODE_FINISH == job->jobPrimitiveInputOutput.mode)
	{
		return MacGenerate_Finish(job);
	}
	else if (CRYPTO_OPERATIONMODE_SINGLECALL == job->jobPrimitiveInputOutput.mode)
	{
		if (E_OK == MacGenerate_Init(job, key, keyLength))
		{
			if (E_OK == MacGenerate_Update(job))
			{
				return MacGenerate_Finish(job);
			}
			else
			{
				return E_NOT_OK;
			}
		}
		else
		{
			return E_NOT_OK;
		}
	}
	else
	{
		//TBD
		//CRYPTO_OPERATIONMODE_STREAMSTART, CRYPTO_OPERATIONMODE_SAVE_CONTEXT, CRYPTO_OPERATIONMODE_RESTORE_CONTEXT
		return E_NOT_OK;
	}
}

Std_ReturnType MacVerify(Crypto_JobType* job, uint8* key, size_t keyLength)
{
	if (CRYPTO_OPERATIONMODE_START == job->jobPrimitiveInputOutput.mode)
	{
		return MacVerify_Init(job, key, keyLength);
	}
	else if (CRYPTO_OPERATIONMODE_UPDATE == job->jobPrimitiveInputOutput.mode)
	{
		return MacVerify_Update(job);
	}
	else if (CRYPTO_OPERATIONMODE_FINISH == job->jobPrimitiveInputOutput.mode)
	{
		return MacVerify_Finish(job);
	}
	else if (CRYPTO_OPERATIONMODE_SINGLECALL == job->jobPrimitiveInputOutput.mode)
	{
		if (E_OK == MacVerify_Init(job, key, keyLength))
		{
			if (E_OK == MacVerify_Update(job))
			{
				return MacVerify_Finish(job);
			}
			else
			{
				return E_NOT_OK;
			}
		}
		else
		{
			return E_NOT_OK;
		}
	}
	else
	{
		//TBD
		//CRYPTO_OPERATIONMODE_STREAMSTART, CRYPTO_OPERATIONMODE_SAVE_CONTEXT, CRYPTO_OPERATIONMODE_RESTORE_CONTEXT
		return E_NOT_OK;
	}
}

Std_ReturnType Random_Generate(Crypto_JobType* job, uint8* key, size_t keyLength)
{
	int retval;
	retval = RAND_bytes(job->jobPrimitiveInputOutput.outputPtr, *(job->jobPrimitiveInputOutput.outputLengthPtr));

	if (retval)
		return E_OK;
	else
		return E_NOT_OK;
}

Std_ReturnType Signature_Generate(Crypto_JobType* job, uint8* key, size_t keyLength)
{
	switch (job->jobPrimitiveInputOutput.mode)
	{
		case CRYPTO_OPERATIONMODE_START:
			return Signature_Generate_Init(job, key, keyLength);
		case CRYPTO_OPERATIONMODE_UPDATE:
			return Signature_Generate_Update(job);
		case CRYPTO_OPERATIONMODE_FINISH:
			return Signature_Generate_Finish(job);
		case CRYPTO_OPERATIONMODE_SINGLECALL:
			if (E_OK == Signature_Generate_Init(job, key, keyLength))
			{
				if (E_OK == Signature_Generate_Update(job))
				{
					return Signature_Generate_Finish(job);
				}
				else
				{
					return E_NOT_OK;
				}
			}
			else
			{
				return E_NOT_OK;
			}
		default:
			//TBD
			//CRYPTO_OPERATIONMODE_STREAMSTART, CRYPTO_OPERATIONMODE_SAVE_CONTEXT, CRYPTO_OPERATIONMODE_RESTORE_CONTEXT
			return E_NOT_OK;
	}
}

Std_ReturnType Signature_Verify(Crypto_JobType* job, uint8* key, size_t keyLength)
{
	switch (job->jobPrimitiveInputOutput.mode)
	{
		case CRYPTO_OPERATIONMODE_START:
			return Signature_Verify_Init(job, key, keyLength);
		case CRYPTO_OPERATIONMODE_UPDATE:
			return Signature_Verify_Update(job);
		case CRYPTO_OPERATIONMODE_FINISH:
			return Signature_Verify_Finish(job);
		case CRYPTO_OPERATIONMODE_SINGLECALL:
			if (E_OK == Signature_Verify_Init(job, key, keyLength))
			{
				if (E_OK == Signature_Verify_Update(job))
				{
					return Signature_Verify_Finish(job);
				}
				else
				{
					return E_NOT_OK;
				}
			}
			else
			{
				return E_NOT_OK;
			}
		default:
			//TBD
			//CRYPTO_OPERATIONMODE_STREAMSTART, CRYPTO_OPERATIONMODE_SAVE_CONTEXT, CRYPTO_OPERATIONMODE_RESTORE_CONTEXT
			return E_NOT_OK;
	}
}
