#ifndef CRYPTO_GENERALTYPES_H
#define CRYPTO_GENERALTYPES_H

/*Crypto_GeneralTypes.h*/

#include "Std_Types.h"
#include "Rte_Csm_Type.h"

/*[SWS_Csm_91043] Definition of Std_ReturnType-extension for module Csm*/
#define CRYPTO_E_BUSY					(0x02u)
#define CRYPTO_E_ENTROPY_EXHAUSTED		(0x04u)
#define CRYPTO_E_KEY_READ_FAIL			(0x06u)
#define CRYPTO_E_KEY_WRITE_FAIL			(0x07u)
#define CRYPTO_E_KEY_NOT_AVAILABLE		(0x08u)
#define CRYPTO_E_KEY_NOT_VALID			(0x09u)
#define CRYPTO_E_KEY_SIZE_MISMATCH		(0x0Au)
#define CRYPTO_E_JOB_CANCELED			(0x0Cu)
#define CRYPTO_E_KEY_EMPTY				(0x0Du)
#define CRYPTO_E_CUSTOM_ERROR			(0x0Eu)


/*[SWS_Csm_01047] Definition of datatype Crypto_AlgorithmFamilyType*/
typedef enum Crypto_AlgorithmFamilyType
{
	CRYPTO_ALGOFAM_NOT_SET,
	CRYPTO_ALGOFAM_SHA1,
	CRYPTO_ALGOFAM_SHA2_224,
	CRYPTO_ALGOFAM_SHA2_256,
	CRYPTO_ALGOFAM_SHA2_384,
	CRYPTO_ALGOFAM_SHA2_512,
	CRYPTO_ALGOFAM_SHA2_512_224,
	CRYPTO_ALGOFAM_SHA2_512_256,
	CRYPTO_ALGOFAM_SHA3_224,
	CRYPTO_ALGOFAM_SHA3_256,
	CRYPTO_ALGOFAM_SHA3_384,
	CRYPTO_ALGOFAM_SHA3_512,
	CRYPTO_ALGOFAM_SHAKE128,
	CRYPTO_ALGOFAM_SHAKE256,
	CRYPTO_ALGOFAM_RIPEMD160,
	CRYPTO_ALGOFAM_BLAKE_1_256,
	CRYPTO_ALGOFAM_BLAKE_1_512,
	CRYPTO_ALGOFAM_BLAKE_2s_256,
	CRYPTO_ALGOFAM_BLAKE_2s_512,
	CRYPTO_ALGOFAM_3DES,
	CRYPTO_ALGOFAM_AES,
	CRYPTO_ALGOFAM_CHACHA,
	CRYPTO_ALGOFAM_RSA,
	CRYPTO_ALGOFAM_ED25519,
	CRYPTO_ALGOFAM_BRAINPOOL,
	CRYPTO_ALGOFAM_ECCNIST,
	CRYPTO_ALGOFAM_RNG,
	CRYPTO_ALGOFAM_SIPHASH,
	CRYPTO_ALGOFAM_ECCANSI,
	CRYPTO_ALGOFAM_ECCSEC,
	CRYPTO_ALGOFAM_DRBG,
	CRYPTO_ALGOFAM_FIPS186,
	CRYPTO_ALGOFAM_PADDING_PKCS7,
	CRYPTO_ALGOFAM_PADDING_ONEWITHZEROS,
	CRYPTO_ALGOFAM_PBKDF2,
	CRYPTO_ALGOFAM_KDFX963,
	CRYPTO_ALGOFAM_DH,
	CRYPTO_ALGOFAM_SM2,
	CRYPTO_ALGOFAM_EEA3,
	CRYPTO_ALGOFAM_SM3,
	CRYPTO_ALGOFAM_EIA3,
	CRYPTO_ALGOFAM_HKDF,
	CRYPTO_ALGOFAM_ECDSA,
	CRYPTO_ALGOFAM_POLY1305,
	CRYPTO_ALGOFAM_X25519,
	CRYPTO_ALGOFAM_ECDH,
	CRYPTO_ALGOFAM_CUSTOM = 0xFFu
}Crypto_AlgorithmFamilyType;


/*[SWS_Csm_01048] Definition of datatype Crypto_AlgorithmModeType*/
typedef enum Crypto_AlgorithmModeType
{
	CRYPTO_ALGOMODE_NOT_SET,
	CRYPTO_ALGOMODE_ECB,
	CRYPTO_ALGOMODE_CBC,
	CRYPTO_ALGOMODE_CFB,
	CRYPTO_ALGOMODE_OFB,
	CRYPTO_ALGOMODE_CTR,
	CRYPTO_ALGOMODE_GCM,
	CRYPTO_ALGOMODE_XTS,
	CRYPTO_ALGOMODE_RSAES_OAEP,
	CRYPTO_ALGOMODE_RSAES_PKCS1_v1_5,
	CRYPTO_ALGOMODE_RSASSA_PSS,
	CRYPTO_ALGOMODE_RSASSA_PKCS1_v1_5,
	CRYPTO_ALGOMODE_8ROUNDS,
	CRYPTO_ALGOMODE_12ROUNDS,
	CRYPTO_ALGOMODE_20ROUNDS,
	CRYPTO_ALGOMODE_HMAC,
	CRYPTO_ALGOMODE_CMAC,
	CRYPTO_ALGOMODE_GMAC,
	CRYPTO_ALGOMODE_CTRDRBG,
	CRYPTO_ALGOMODE_SIPHASH_2_4,
	CRYPTO_ALGOMODE_SIPHASH_4_8,
	CRYPTO_ALGOMODE_PXXXR1,
	CRYPTO_ALGOMODE_AESKEYWRAP,
	CRYPTO_ALGOMODE_CUSTOM = 0xFFu
}Crypto_AlgorithmModeType;


/*[SWS_Csm_91024] Definition of datatype Crypto_InputOutputRedirectionConfigType*/
typedef enum Crypto_InputOutputRedirectionConfigType
{
	CRYPTO_REDIRECT_CONFIG_PRIMARY_INPUT = 0x01u,
	CRYPTO_REDIRECT_CONFIG_SECONDARY_INPUT = 0x02u,
	CRYPTO_REDIRECT_CONFIG_TERTIARY_INPUT = 0x04u,
	CRYPTO_REDIRECT_CONFIG_PRIMARY_OUTPUT = 0x10u,
	CRYPTO_REDIRECT_CONFIG_SECONDARY_OUTPUT = 0x20u
}Crypto_InputOutputRedirectionConfigType;


/*[SWS_Csm_01028] Definition of datatype Crypto_JobStateType*/
typedef enum Crypto_JobStateType
{
	CRYPTO_JOBSTATE_IDLE,
	CRYPTO_JOBSTATE_ACTIVE
}Crypto_JobStateType;


/*[SWS_Csm_01031] Definition of datatype Crypto_ServiceInfoType*/
typedef enum Crypto_ServiceInfoType
{
	CRYPTO_HASH,
	CRYPTO_MACGENERATE,
	CRYPTO_MACVERIFY,
	CRYPTO_ENCRYPT,
	CRYPTO_DECRYPT,
	CRYPTO_AEADENCRYPT,
	CRYPTO_AEADDECRYPT,
	CRYPTO_SIGNATUREGENERATE,
	CRYPTO_SIGNATUREVERIFY,
	CRYPTO_RANDOMGENERATE = 0x0Bu,
	CRYPTO_RANDOMSEED,
	CRYPTO_KEYGENERATE,
	CRYPTO_KEYDERIVE,
	CRYPTO_KEYEXCHANGECALCPUBVAL,
	CRYPTO_KEYEXCHANGECALCSECRET,
	CRYPTO_KEYSETVALID = 0x13u,
	CRYPTO_KEYSETINVALID,
	CRYPTO_CUSTOM_SERVICE,
	CRYPTO_KEYWRAP,
	CRYPTO_KEYUNWRAP
}Crypto_ServiceInfoType;


/*[SWS_Csm_01049] Definition of datatype Crypto_ProcessingType*/
typedef enum Crypto_ProcessingType
{
	CRYPTO_PROCESSING_ASYNC,
	CRYPTO_PROCESSING_SYNC
}Crypto_ProcessingType;


/*[SWS_Csm_01009] Definition of datatype Crypto_JobPrimitiveInputOutputType*/
typedef struct Crypto_JobPrimitiveInputOutputType
{
	const uint8* inputPtr;
	uint32 inputLength;
	const uint8* secondaryInputPtr;
	uint32 secondaryInputLength;
	const uint8* tertiaryInputPtr;
	uint32 tertiaryInputLength;
	uint8* outputPtr;
	uint32* outputLengthPtr;
	uint8* secondaryOutputPtr;
	uint32* secondaryOutputLengthPtr;
	Crypto_VerifyResultType* verifyPtr;
	Crypto_OperationModeType mode;
	uint32 cryIfKeyId;
	uint32 targetCryIfKeyId;
}Crypto_JobPrimitiveInputOutputType;


/*[SWS_Csm_01008] Definition of datatype Crypto_AlgorithmInfoType*/
typedef struct Crypto_AlgorithmInfoType
{
	Crypto_AlgorithmFamilyType family;
	Crypto_AlgorithmFamilyType secondaryFamily;
	uint32 keyLength;
	Crypto_AlgorithmModeType mode;
}Crypto_AlgorithmInfoType;


/*[SWS_Csm_01011] Definition of datatype Crypto_PrimitiveInfoType*/
typedef struct Crypto_PrimitiveInfoType
{
	const Crypto_ServiceInfoType service;
	const Crypto_AlgorithmInfoType algorithm;
}Crypto_PrimitiveInfoType;


/*[SWS_Csm_01012] Definition of datatype Crypto_JobPrimitiveInfoType*/
typedef struct Crypto_JobPrimitiveInfoType
{
	uint32 callbackId;
	const Crypto_PrimitiveInfoType* primitiveInfo;
	uint32 cryIfKeyId;
	Crypto_ProcessingType processingType;
}Crypto_JobPrimitiveInfoType;


/*[SWS_Csm_91026] Definition of datatype Crypto_JobRedirectionInfoType*/
typedef struct Crypto_JobRedirectionInfoType
{
	uint8 redirectionConfig;
	uint32 inputKeyId;
	uint32 inputKeyElementId;
	uint32 secondaryInputKeyId;
	uint32 secondaryInputKeyElementId;
	uint32 tertiaryInputKeyId;
	uint32 tertiaryInputKeyElementId;
	uint32 outputKeyId;
	uint32 outputKeyElementId;
	uint32 secondaryOutputKeyId;
	uint32 secondaryOutputKeyElementId;
}Crypto_JobRedirectionInfoType;


/*[SWS_Csm_01013] Definition of datatype Crypto_JobType*/
typedef struct Crypto_JobType
{
	uint32 jobId;
	Crypto_JobStateType jobState;
	Crypto_JobPrimitiveInputOutputType jobPrimitiveInputOutput;
	const Crypto_JobPrimitiveInfoType* jobPrimitiveInfoRef;
	Crypto_JobRedirectionInfoType* jobRedirectionInfoRef;
	uint32 cryptoKeyId;
	uint32 targetCryptoKeyId;
	const uint32 jobPriority;
}Crypto_JobType;




#endif
