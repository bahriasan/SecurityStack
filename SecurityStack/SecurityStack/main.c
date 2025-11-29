
/* 1. Security Access
*
* Level 1-3-5
* 27-01/03/05: GENERATE SEED: Returns 4 Byte Long Seed
* 27-02/04/06-KEY: VERIFY KEY: Returns Verification Result
* 31-01/03/05: MAC GENERATE: Returns Generated Key using stored KEYS
*
* SYMMETRIC CRYPTO
* 4 BYTE LONG SEED
* 128 BIT AES CBC
*
*/

/* 2. RSA Authenticate
*
* Authentication with Challenge-Response Asymmetric Cryptography
* RSA2048(256 Byte Signature)
*
*/


/*
* TEST CASES:
*
* SecAccess-1:
* SecurityStack 0x02 0x27 0x01
* SecurityStack 0x02 0x31 0x01
* SecurityStack 0x10 0x12 0x27 0x02 MAC
*
* SecAccess-3:
* SecurityStack 0x02 0x27 0x03
* SecurityStack 0x02 0x31 0x03
* SecurityStack 0x10 0x12 0x27 0x04 MAC
*
* SecAccess-5:
* SecurityStack 0x02 0x27 0x05
* SecurityStack 0x02 0x31 0x05
* SecurityStack 0x10 0x12 0x27 0x06 MAC
*
* Authentication:
* SecurityStack 0x02 0x29 0x05
* SecurityStack 0x02 0x31 0x06
* SecurityStack 0x11 0x02 0x29 0x06 SIGNATURE
*/


#include <stdio.h>
#include <stdlib.h>
#include "Csm.h"
#include "Helper_RSA_Keygen.h"
#include "uds.h"

static void Printer(const char* const str, const uint32 length)
{
	for(int i = 0; i!=length; ++i)
	{
		printf("0x%02hhx ", str[i]);
	}
}

static Std_ReturnType SeedRequest(char* seed, uint32 size)		//UDS 27-01
{
	Std_ReturnType retval = Csm_RandomGenerate(JOBID_SEEDGENERATE, seed, &size);

	if (E_OK == retval)
	{
		printf("Generating Seed(%d Bytes in Hex)\n", size);
		Printer(seed, size);
		printf("\n\n");
	}
	else
	{
		printf("Seed Generation Failed\n\n");
	}

	return retval;
}

static Std_ReturnType SecLevel1_MacGenerate(char* seed, uint32 seedLength)
{
	char mac[16] = { 0 };
	uint32 macLength = sizeof(mac);
	Std_ReturnType retval = Csm_MacGenerate(JOBID_SECLEVEL1_MACGENERATE, CRYPTO_OPERATIONMODE_SINGLECALL, seed, seedLength, mac, &macLength);

	if (E_OK == retval)
	{
		printf("\nGenerating MAC(%d Bytes in Hex)\n", macLength);
		Printer(mac, macLength);
		printf("\n\n");

		printf("MAC Generated with Sec-Level1 AES128 CBC MAC Key:\n");
		uint8* key = Csm_config.CsmJobs[JOBID_SECLEVEL1_MACGENERATE].CsmJobKeyRef->CsmKeyRef->CryIfKeyRef->CryptoKeyNvBlockRef->CryptoNvBlockDescriptorRef->AES128KEY;
		uint32 keyLength = Csm_config.CsmJobs[JOBID_SECLEVEL1_MACGENERATE].CsmJobKeyRef->CsmKeyRef->CryIfKeyRef->CryptoKeyTypeRef->CryptoKeyElementRef->CryptoKeyElementSize;
		Printer(key, keyLength);
		printf("\n\n");
	}
	else
	{
		printf("MAC Generation Failed\n\n");
	}

	return retval;
}

static Std_ReturnType SecLevel1_VerifyKey(char* seed, uint32 seedLength, char* mac, uint32 macLength)		//UDS 27-02
{
	Crypto_VerifyResultType verifyMAC = CRYPTO_E_VER_NOT_OK;
	Std_ReturnType retval = Csm_MacVerify(JOBID_SECLEVEL1_MACVERIFY, CRYPTO_OPERATIONMODE_SINGLECALL, seed, seedLength, mac, macLength, &verifyMAC);

	if (E_OK == retval)
	{
		if (verifyMAC == CRYPTO_E_VER_OK)
		{
			printf("MAC Verified\n");
			printf("SecLevel-1 Granted\n\n");
		}
		else
		{
			printf("MAC NOT Verified\n\n");
		}
	}
	else
	{
		printf("MAC Verification Failed\n\n");
	}

	return retval;
}

static Std_ReturnType SecLevel3_MacGenerate(char* seed, uint32 seedLength)
{
	char mac[16] = { 0 };
	uint32 macLength = sizeof(mac);
	Std_ReturnType retval = Csm_MacGenerate(JOBID_SECLEVEL3_MACGENERATE, CRYPTO_OPERATIONMODE_SINGLECALL, seed, seedLength, mac, &macLength);

	if (E_OK == retval)
	{
		printf("\nGenerating MAC(%d Bytes in Hex)\n", macLength);
		Printer(mac, macLength);
		printf("\n\n");

		printf("MAC Generated with Sec-Level3 AES128 CBC MAC Key:\n");
		uint8* key = Csm_config.CsmJobs[JOBID_SECLEVEL3_MACGENERATE].CsmJobKeyRef->CsmKeyRef->CryIfKeyRef->CryptoKeyNvBlockRef->CryptoNvBlockDescriptorRef->AES128KEY;
		uint32 keyLength = Csm_config.CsmJobs[JOBID_SECLEVEL3_MACGENERATE].CsmJobKeyRef->CsmKeyRef->CryIfKeyRef->CryptoKeyTypeRef->CryptoKeyElementRef->CryptoKeyElementSize;
		Printer(key, keyLength);
		printf("\n\n");
	}
	else
	{
		printf("MAC Generation Failed\n\n");
	}

	return retval;
}

static Std_ReturnType SecLevel3_VerifyKey(char* seed, uint32 seedLength, char* mac, uint32 macLength)		//UDS 27-04
{
	Crypto_VerifyResultType verifyMAC = CRYPTO_E_VER_NOT_OK;
	Std_ReturnType retval = Csm_MacVerify(JOBID_SECLEVEL3_MACVERIFY, CRYPTO_OPERATIONMODE_SINGLECALL, seed, seedLength, mac, macLength, &verifyMAC);

	if (E_OK == retval)
	{
		if (verifyMAC == CRYPTO_E_VER_OK)
		{
			printf("MAC Verified\n");
			printf("SecLevel-3 Granted\n\n");
		}
		else
		{
			printf("MAC NOT Verified\n\n");
		}
	}
	else
	{
		printf("MAC Verification Failed\n\n");
	}

	return retval;
}

static Std_ReturnType SecLevel5_MacGenerate(char* seed, uint32 seedLength)
{
	char mac[16] = { 0 };
	uint32 macLength = sizeof(mac);
	Std_ReturnType retval = Csm_MacGenerate(JOBID_SECLEVEL5_MACGENERATE, CRYPTO_OPERATIONMODE_SINGLECALL, seed, seedLength, mac, &macLength);

	if (E_OK == retval)
	{
		printf("\nGenerating MAC(%d Bytes in Hex)\n", macLength);
		Printer(mac, macLength);
		printf("\n\n");

		printf("MAC Generated with Sec-Level5 AES128 CBC MAC Key:\n");
		uint8* key = Csm_config.CsmJobs[JOBID_SECLEVEL5_MACGENERATE].CsmJobKeyRef->CsmKeyRef->CryIfKeyRef->CryptoKeyNvBlockRef->CryptoNvBlockDescriptorRef->AES128KEY;
		uint32 keyLength = Csm_config.CsmJobs[JOBID_SECLEVEL5_MACGENERATE].CsmJobKeyRef->CsmKeyRef->CryIfKeyRef->CryptoKeyTypeRef->CryptoKeyElementRef->CryptoKeyElementSize;
		Printer(key, keyLength);
		printf("\n\n");
	}
	else
	{
		printf("MAC Generation Failed\n\n");
	}

	return retval;
}

static Std_ReturnType SecLevel5_VerifyKey(char* seed, uint32 seedLength, char* mac, uint32 macLength)		//UDS 27-06
{
	Crypto_VerifyResultType verifyMAC = CRYPTO_E_VER_NOT_OK;
	Std_ReturnType retval = Csm_MacVerify(JOBID_SECLEVEL5_MACVERIFY, CRYPTO_OPERATIONMODE_SINGLECALL, seed, seedLength, mac, macLength, &verifyMAC);

	if (E_OK == retval)
	{
		if (verifyMAC == CRYPTO_E_VER_OK)
		{
			printf("MAC Verified\n");
			printf("SecLevel-5 Granted\n\n");
		}
		else
		{
			printf("MAC NOT Verified\n\n");
		}
	}
	else
	{
		printf("MAC Verification Failed\n\n");
	}

	return retval;
}

static Std_ReturnType VerifySignature(char* seed, uint32 seedLength, char* signature, uint32 signatureLength)
{
	Crypto_VerifyResultType verifySign = CRYPTO_E_VER_NOT_OK;

	Std_ReturnType retval = Csm_SignatureVerify(JOBID_SIGNATUREVERIFY, CRYPTO_OPERATIONMODE_SINGLECALL, seed, seedLength, signature, signatureLength, &verifySign);

	if ( E_OK == retval)
	{
		if (verifySign == CRYPTO_E_VER_OK)		//This check is not necessary
		{
			printf("\nSignature Verified\n");
			printf("User Authenticated\n\n");
		}
	}//else case is not necessary here since error message is printed by Driver itself

	return retval;
}

static Std_ReturnType GenerateSignature(char* seed, uint32 seedLength)
{
	char signature[256] = { 0 };
	uint32 signatureLength = sizeof(signature);
	Std_ReturnType retval = Csm_SignatureGenerate(JOBID_SIGNATUREGENERATE, CRYPTO_OPERATIONMODE_SINGLECALL, seed, seedLength, signature, &signatureLength);

	if (E_OK == retval)
	{
		printf("\nGenerating Signature(%d Bytes in Hex)\n", signatureLength);
		Printer(signature, signatureLength);
		printf("\n\n");
	}
	else
	{
		printf("\nSignature Generation Failed\n\n");
	}

	return retval;
}


static uint8 isSeedGenerated(char* str)
{
	uint8 arr[4] = { 0, 0, 0, 0 };
	return (memcmp(str, arr, sizeof(arr)) == 0) ? 0 : 1;
}

static void deserializeInput(const char* str, int size, char*** argv_local, int* argc_local)
{
	int index = 0, arg_count = 0, arg_index = 0;

	for (int i = 0; i != size; ++i)
	{
		if (' ' == str[i]) 
		{
			//printf("bosluk= %d\n", i);
			arg_count++;
		}
	}
	//printf("arg_count = %d\n", arg_count);
	*argc_local = arg_count + 1;


	*argv_local = malloc(sizeof(char*) * (arg_count+1));
	for (int i = 0; i != size; ++i)
	{
		if (' ' == str[i])
		{
			(*argv_local)[arg_index] = malloc(i - index + 1);;
			memcpy((*argv_local)[arg_index], &str[index], i - index);
			(*argv_local)[arg_index][i - index] = '\0';		//Last element is added to simulate string
			index = i + 1;
			arg_index++;
		}
	}

	//Copy Last Element
	(*argv_local)[arg_index] = malloc(size - index + 1);
	memcpy((*argv_local)[arg_index], &str[index], size - index);
	(*argv_local)[arg_index][size - index] = '\0';		//Last element is added to simulate string
}

static void createLocalInputs(const char** argv, int argc, char*** argv_local, int* argc_local)
{
	*argv_local = malloc(sizeof(char*)*argc);
	*argc_local = argc;

	for (int i = 0; i != argc; ++i)
	{
		(*argv_local)[i] = malloc(strlen(argv[i])+1);
		strcpy((*argv_local)[i], argv[i]);
	}
}

static void initLocalInputs(char*** argv_local, int* argc_local)
{
	for (int i = 0; i != *argc_local; ++i)
	{
		free((*argv_local)[i]);
	}
	free(*argv_local);

	*argv_local = NULL;
	*argc_local = 0;
}

static void PrintError(errorType err, int ret) 
{
	switch (err)
	{
	case INTERR_SEEDGENERATE:
		printf("Error Code: INTERR_SEEDGENERATE-%d\n", ret);
		break;
	case INTERR_KEYVERIFY:
		printf("Error Code: INTERR_KEYVERIFY-%d\n", ret);
		break;
	case INTERR_MACGENERATE:
		printf("Error Code: INTERR_MACGENERATE-%d\n", ret);
		break;
	case INTERR_REQUEST_CHALLENGE:
		printf("Error Code: INTERR_REQUEST_CHALLENGE-%d\n", ret);
		break;
	case INTERR_VERIFY_POWN:
		printf("Error Code: INTERR_VERIFY_POWN-%d\n", ret);
		break;
	case INTERR_SIGNGENERATE:
		printf("Error Code: INTERR_SIGNGENERATE-%d\n", ret);
		break;
	case GENERALREJECT:
		printf("Error Code: GENERALREJECT-%d\n", ret);
		break;
	case NOTSUPPORTEDFUNCTION:
		printf("Error Code: NOTSUPPORTEDFUNCTION-%d\n", ret);
		break;
	case NOTSUPPORTEDSUBFUNCTION:
		printf("Error Code: NOTSUPPORTEDSUBFUNCTION-%d\n", ret);
		break;
	case INVALIDFORMAT:
		printf("Error Code: INVALIDFORMAT-%d\n", ret);
		break;
	case CONDITIONSNOTCORRECT:
		printf("Error Code: CONDITIONSNOTCORRECT-%d\n", ret);
		break;
	case REQUESTSEQERROR:
		printf("Error Code: REQUESTSEQERROR-%d\n", ret);
		break;
	case REQUESTOUTOFRANGE:
		printf("Error Code: REQUESTOUTOFRANGE-%d\n", ret);
		break;
	case SECURITYACCESSDENIED:
		printf("Error Code: SECURITYACCESSDENIED-%d\n", ret);
		break;
	case INVALIDKEY:
		printf("Error Code: INVALIDKEY-%d\n", ret);
		break;
	case EXCEEDEDNOOFATTEMPTS:
		printf("Error Code: EXCEEDEDNOOFATTEMPTS-%d\n", ret);
		break;
	case TIMEDELAYNOTEXPIRED:
		printf("Error Code: TIMEDELAYNOTEXPIRED-%d\n", ret);
		break;
	}
}

static void Test(void)
{
	//1. RandomGenerate TestCode
	uint8 resultPtr[4] = { 0 };

	uint32 resultLength = sizeof(resultPtr);
	Std_ReturnType retval;


	retval = Csm_RandomGenerate(
		JOBID_SEEDGENERATE,
		resultPtr, 
		&resultLength
	);

	uint8* ptr = resultPtr;
	uint32 resLen = resultLength;

	printf("Random Generate:\n");

	while (resLen--)
	{
		printf(" % x", *(ptr++));
	}

	printf("\n");

	uint8 dummy[4] = { 0xaa, 0xbb, 0xcc, 0xdd };
	memcpy(resultPtr, dummy, resultLength);


	//2. MacGenerate TestCode
	uint8 mac[16];
	uint32 macLength = sizeof(mac);

	/*bc 84 39 42 56 cd e7 7b d6 80 1f ec e1 53 4c 5c*/

	/*
	Csm_MacGenerate(
		JOBID_MACGENERATE,
		CRYPTO_OPERATIONMODE_SINGLECALL,
		resultPtr,
		resultLength,
		mac,
		&macLength
	);
	*/

	Csm_MacGenerate(
		JOBID_SECLEVEL1_MACGENERATE,
		CRYPTO_OPERATIONMODE_START,
		resultPtr,
		resultLength,
		mac,
		&macLength
	);
	Csm_MacGenerate(
		JOBID_SECLEVEL1_MACGENERATE,
		CRYPTO_OPERATIONMODE_UPDATE,
		resultPtr,
		resultLength,
		mac,
		&macLength
	);
	Csm_MacGenerate(
		JOBID_SECLEVEL1_MACGENERATE,
		CRYPTO_OPERATIONMODE_FINISH,
		resultPtr,
		resultLength,
		mac,
		&macLength
	);

	uint8* ptrMacGen = mac;
	uint32 macLen = macLength;

	printf("Mac Generate:\n");

	while (macLen--)
	{
		printf(" % x", *(ptrMacGen++));
	}

	printf("\n");



	//3. MacVerify TestCode
	Crypto_VerifyResultType verifyMAC;

	//Wrong mac Test
	char imac[16] = { 0xbc, 0x84, 0x39, 0x42, 0x56, 0xcd, 0xe7, 0x7b, 0xd6, 0x80, 0x1f, 0xec, 0xe1, 0x53, 0x4c, 0x5c };
	memcpy(mac, imac, sizeof(mac));


	//Csm_MacVerify(
	//	JOBID_MACVERIFY,
	//	CRYPTO_OPERATIONMODE_SINGLECALL,
	//	resultPtr,
	//	resultLength,
	//	mac,
	//	macLength,
	//	&verify
	//);

	Csm_MacVerify(
		JOBID_SECLEVEL1_MACVERIFY,
		CRYPTO_OPERATIONMODE_START,
		resultPtr,
		resultLength,
		mac,
		macLength,
		&verifyMAC
	);
	Csm_MacVerify(
		JOBID_SECLEVEL1_MACVERIFY,
		CRYPTO_OPERATIONMODE_UPDATE,
		resultPtr,
		resultLength,
		mac,
		macLength,
		&verifyMAC
	);
	Csm_MacVerify(
		JOBID_SECLEVEL1_MACVERIFY,
		CRYPTO_OPERATIONMODE_FINISH,
		resultPtr,
		resultLength,
		mac,
		macLength,
		&verifyMAC
	);

	printf("Mac Verify Result:\n");
	printf("%d\n", verifyMAC == CRYPTO_E_VER_OK ? 0 : 1);


	//4. Generate RSA KeyPair
	int ret_key = 0;
	EVP_PKEY* pkey = NULL;
	printf("RSA Key Pair Generated:\n");
	pkey = generate_rsa_key(2048);
	//ret_key = dump_key(pkey);

	//5. Sign with Private Key 
	const char dataToSign[32] = { "SECURITY STACK EXAMPLES TO SIGN" };
	char signature[256] = { 0 };
	size_t sigLength = sizeof(signature);	//Check if size_t is ok???????????

	//Csm_SignatureGenerate(
	//	JOBID_SIGNATUREGENERATE,
	//	CRYPTO_OPERATIONMODE_SINGLECALL,
	//	dataToSign,
	//	sizeof(dataToSign),
	//	signature,
	//	&sigLength
	//);

	Csm_SignatureGenerate(
		JOBID_SIGNATUREGENERATE,
		CRYPTO_OPERATIONMODE_START,
		dataToSign,
		sizeof(dataToSign),
		signature,
		&sigLength
	);

	Csm_SignatureGenerate(
		JOBID_SIGNATUREGENERATE,
		CRYPTO_OPERATIONMODE_UPDATE,
		dataToSign,
		sizeof(dataToSign),
		signature,
		&sigLength
	);

	Csm_SignatureGenerate(
		JOBID_SIGNATUREGENERATE,
		CRYPTO_OPERATIONMODE_FINISH,
		dataToSign,
		sizeof(dataToSign),
		signature,
		&sigLength
	);


	//6. and Verify with Public Key
	Crypto_VerifyResultType verifyRSA = CRYPTO_E_VER_NOT_OK;
	Std_ReturnType retVerify = E_NOT_OK;

	//Csm_SignatureVerify(
	//	JOBID_SIGNATUREVERIFY,
	//	CRYPTO_OPERATIONMODE_SINGLECALL,
	//	dataToSign,
	//	sizeof(dataToSign),
	//	signature,
	//	sigLength,
	//	&verifyRSA
	//);

	retVerify = Csm_SignatureVerify(
		JOBID_SIGNATUREVERIFY,
		CRYPTO_OPERATIONMODE_START,
		dataToSign,
		sizeof(dataToSign),
		signature,
		sigLength,
		&verifyRSA
	);

	retVerify = Csm_SignatureVerify(
		JOBID_SIGNATUREVERIFY,
		CRYPTO_OPERATIONMODE_UPDATE,
		dataToSign,
		sizeof(dataToSign),
		signature,
		sigLength,
		&verifyRSA
	);

	retVerify = Csm_SignatureVerify(
		JOBID_SIGNATUREVERIFY,
		CRYPTO_OPERATIONMODE_FINISH,
		dataToSign,
		sizeof(dataToSign),
		signature,
		sigLength,
		&verifyRSA
	);


	printf("RSA Verify Operation Result:\n");
	printf("%d\n", retVerify == E_OK ? 0 : 1);

	printf("RSA Verify Result:\n");
	printf("%d\n", verifyRSA == CRYPTO_E_VER_OK ? 0 : 1);
}


int main(int argc, char** argv)
{
	int service = 0, subService = 0, secLevel = 0;
	uint8 seed_Sec1[4] = { 0 }, seed_Sec3[4] = { 0 }, seed_Sec5[4] = { 0 }, seed_Auth[4] = { 0 };
	errorType err = ERROR_NO;
	int ret = 0;
	int wait = 0;
	char obj[] = "SecurityStack";
	uint32 numOfBytes = 0;
	uint8 multiframe = FALSE;

	Csm_Init(&Csm_config);

	int argc_local = 0;
	char** argv_local = NULL;
	createLocalInputs(argv, argc, &argv_local, &argc_local);
	

	while (1)
	{
		if (wait == 1)
		{
			char dt[2000] = { 0 };

			printf("Pass the Service Code\n");
			scanf("%[^\n]", dt);
			getchar();

			int sz = strlen(dt);
			deserializeInput(dt, sz, &argv_local, &argc_local);
		}

/*1. DO THE CHECKS*/
		//Check if first argument is name of the object
		if (strcmp(obj, argv_local[0]))
		{
			err = INVALIDFORMAT;
			ret = 1;
			goto end;
		}

		//Check if no arguments passed
		if (argc_local < 3)
		{
			err = INVALIDFORMAT;
			ret = 2;
			goto end;
		}

		/*
		* Check if PCI uses more than 1 Bytes (PCI: 2 Bytes up to 4095)
		* ISO15765-2: For segmented messages with a message length <= 4095, the lower nibble of the first PCI byte (Byte #1) and the second PCI byte (Byte #2) includes the message length.
		* for >8Byte data, high nibble of the 1st PCI Byte is 1.
		*/
		if (argc_local > 10)	
		{
			if ((strtoul(argv_local[1], NULL, 16) < 16) || ((strtoul(argv_local[1], NULL, 16) == 16) && (strtoul(argv_local[2], NULL, 16) < 9)))
			{
				err = INVALIDFORMAT;
				ret = 3;
				goto end;
			}
			numOfBytes = ((strtoul(argv_local[1], NULL, 16) - 0x10) * 0x100) + strtoul(argv_local[2], NULL, 16);
			multiframe = TRUE;
		}
		else
		{
			if (strtoul(argv_local[1], NULL, 16) > 8)
			{
				err = INVALIDFORMAT;
				ret = 4;
				goto end;
			}
			numOfBytes = strtoul(argv_local[1], NULL, 16);
			multiframe = FALSE;
		}

		//Check if we have at least PCI number arguments
		if (argc_local < numOfBytes + 2)
		{
			err = INVALIDFORMAT;
			ret = 5;
			goto end;
		}

		//Check if PCI is at least 2, this is valid for UDS 27 Services
		if (numOfBytes < 2)
		{
			err = INVALIDFORMAT;
			ret = 6;
			goto end;
		}

/*2.DO DECRYPTION*/
		//Decrypt Service & SubService
		if (FALSE == multiframe)
		{
			service = strtoul(argv_local[2], NULL, 16);
			subService = strtoul(argv_local[3], NULL, 16);
		}
		else
		{
			service = strtoul(argv_local[3], NULL, 16);
			subService = strtoul(argv_local[4], NULL, 16);
		}

		switch (service)
		{
		case SECURITY_ACCESS:	//0x27

			switch (subService)
			{
			case 1:			//0x27 0x01
				secLevel = SECLEVEL_1;
				subService = REQUEST_SEED;
				break;
			case 2:			//0x27 0x02
				secLevel = SECLEVEL_1;
				subService = VERIFY_KEY;
				break;
			case 3:			//0x27 0x03
				secLevel = SECLEVEL_3;
				subService = REQUEST_SEED;
				break;
			case 4:			//0x27 0x04
				secLevel = SECLEVEL_3;
				subService = VERIFY_KEY;
				break;
			case 5:			//0x27 0x05
				secLevel = SECLEVEL_5;
				subService = REQUEST_SEED;
				break;
			case 6:			//0x27 0x06
				secLevel = SECLEVEL_5;
				subService = VERIFY_KEY;
				break;
			default:
				err = NOTSUPPORTEDSUBFUNCTION;
				ret = 7;
				goto end;
			}

			break;
		case AUTHENTICATION:	//0x29
			switch (subService)
			{
			case 5:		//0x29 0x05
				subService = REQUEST_CHALLENGE;
				break;
			case 6:		//0x29 0x06
				subService = VERIFY_POWN;
				break;
			default:
				err = NOTSUPPORTEDSUBFUNCTION;
				ret = 8;
				goto end;
			}

			break;
		case ROUTINE_CONTROL:	//0x31

			switch (subService)
			{
			case 1:			//0x31 0x01
				secLevel = SECLEVEL_1;
				subService = MAC_GENERATE;
				break;
			case 3:			//0x31 0x03
				secLevel = SECLEVEL_3;
				subService = MAC_GENERATE;
				break;
			case 5:			//0x31 0x05
				secLevel = SECLEVEL_5;
				subService = MAC_GENERATE;
				break;
			case 6:			//0x31 0x06
				subService = SIGN_GENERATE;
				break;
			default:
				err = NOTSUPPORTEDSUBFUNCTION;
				ret = 9;
				goto end;
			}

			break;

		default:	//Other Services TBD
			err = NOTSUPPORTEDFUNCTION;
			ret = 10;
			goto end;
		}

/*3.CALL RELEVANT SERVICE*/
		if (REQUEST_SEED == subService)
		{
			if (SECLEVEL_1 == secLevel)
			{
				if (E_NOT_OK == SeedRequest(seed_Sec1, sizeof(seed_Sec1)))
				{
					err = INTERR_SEEDGENERATE;
					ret = 11;
					goto end;
				}
				wait = 1;
			}
			else if (SECLEVEL_3 == secLevel)
			{
				if (E_NOT_OK == SeedRequest(&seed_Sec3, sizeof(seed_Sec3)))
				{
					err = INTERR_SEEDGENERATE;
					ret = 12;
					goto end;
				}
				wait = 1;
			}
			else if (SECLEVEL_5 == secLevel)
			{
				if (E_NOT_OK == SeedRequest(&seed_Sec5, sizeof(seed_Sec5)))
				{
					err = INTERR_SEEDGENERATE;
					ret = 13;
					goto end;
				}
				wait = 1;
			}
			else
			{
				//this is unreachable
			}

		}
		else if (VERIFY_KEY == subService)
		{
			if (numOfBytes > 2)
			{
				uint32 dataSize = numOfBytes - 2;
				uint8* data = malloc(dataSize);
				
				uint8 startPoint = (FALSE == multiframe) ? 4 : 5;

				for (int i = 0; i != numOfBytes-2; ++i)
				{
					int dt = strtoul(argv_local[i + startPoint], NULL, 16);

					if (0 > dt || 255 < dt)
					{
						err = INVALIDFORMAT;
						free(data);
						ret = 14;
						goto end;
					}
					data[i] = dt;
				}
				
				if (SECLEVEL_1 == secLevel && isSeedGenerated(seed_Sec1))
				{
					if (E_NOT_OK == SecLevel1_VerifyKey(seed_Sec1, sizeof(seed_Sec1), data, dataSize))
					{
						err = INTERR_KEYVERIFY;
						free(data);
						ret = 15;
						goto end;
					}
					wait = 0;
				}
				else if (SECLEVEL_3 == secLevel && isSeedGenerated(seed_Sec3))
				{
					if (E_NOT_OK == SecLevel3_VerifyKey(seed_Sec3, sizeof(seed_Sec3), data, dataSize))
					{
						err = INTERR_KEYVERIFY;
						free(data);
						ret = 16;
						goto end;
					}
					wait = 0;
				}
				else if (SECLEVEL_5 == secLevel && isSeedGenerated(seed_Sec5))
				{
					if (E_NOT_OK == SecLevel5_VerifyKey(seed_Sec5, sizeof(seed_Sec5), data, dataSize))
					{
						err = INTERR_KEYVERIFY;
						free(data);
						ret = 17;
						goto end;
					}
					wait = 0;
				}
				else
				{
					err = REQUESTSEQERROR;
					ret = 18;
					free(data);
					goto end;
				}

				free(data);
			}
			else
			{
				err = INVALIDFORMAT;
				ret = 19;
				goto end;
			}
		}
		else if (MAC_GENERATE == subService)
		{
			if (SECLEVEL_1 == secLevel && isSeedGenerated(seed_Sec1))
			{
				if (E_NOT_OK == SecLevel1_MacGenerate(seed_Sec1, sizeof(seed_Sec1)))
				{
					err = INTERR_MACGENERATE;
					ret = 20;
					goto end;
				}
			}
			else if (SECLEVEL_3 == secLevel && isSeedGenerated(seed_Sec3))
			{
				if (E_NOT_OK == SecLevel3_MacGenerate(seed_Sec3, sizeof(seed_Sec3)))
				{
					err = INTERR_MACGENERATE;
					ret = 21;
					goto end;
				}
			}
			else if (SECLEVEL_5 == secLevel && isSeedGenerated(seed_Sec5))
			{
				if (E_NOT_OK == SecLevel5_MacGenerate(seed_Sec5, sizeof(seed_Sec5)))
				{
					err = INTERR_MACGENERATE;
					ret = 22;
					goto end;
				}
			}
			else
			{
				err = REQUESTSEQERROR;
				ret = 23;
				goto end;
			}
		}
		else if (REQUEST_CHALLENGE == subService)
		{
			if (E_NOT_OK == SeedRequest(seed_Auth, sizeof(seed_Auth)))
			{
				err = INTERR_REQUEST_CHALLENGE;
				ret = 24;
				goto end;
			}
			wait = 1;
		}
		else if (VERIFY_POWN == subService)
		{
			if (numOfBytes > 2)
			{
				uint32 dataSize = numOfBytes - 2;
				uint8* data = malloc(dataSize);
				uint8 startPoint = (FALSE == multiframe) ? 4 : 5;

				for (int i = 0; i != numOfBytes - 2; ++i)
				{
					int dt = strtoul(argv_local[i + startPoint], NULL, 16);

					if (0 > dt || 255 < dt)
					{
						err = INVALIDFORMAT;
						free(data);
						ret = 25;
						goto end;
					}
					data[i] = dt;
				}

				if (isSeedGenerated(seed_Auth))
				{
					int retval = VerifySignature(seed_Auth, sizeof(seed_Auth), data, dataSize);
					if (E_NOT_OK == retval)
					{
						err = INTERR_VERIFY_POWN;
						ret = 26;
						free(data);
						goto end;
					}
					wait = 0;
				}
				free(data);
			}
			else
			{
				err = INVALIDFORMAT;
				ret = 27;
				goto end;
			}
		}
		else if (SIGN_GENERATE == subService)
		{
			if (isSeedGenerated(seed_Auth))
			{
				if (E_NOT_OK == GenerateSignature(seed_Auth, sizeof(seed_Auth)))
				{
					err = INTERR_SIGNGENERATE;
					ret = 28;
					goto end;
				}
			}
		}
		else
		{
			//other services TBD
		}

/*4.FREE ARGS*/
	end:
		initLocalInputs(&argv_local, &argc_local);

		if (ret)
			break;

		if (!wait)
			break;
	}

	if (ERROR_NO != err)
	{
		PrintError(err, ret);
	}
	return 1;
}
