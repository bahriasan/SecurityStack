#ifndef CRYPTODRIVER_CFG_H
#define CRYPTODRIVER_CFG_H

/*CryptoDriver_Cfg.h*/

#include "Std_Types.h"
#include "Ecuc.h"
#include "Crypto_GeneralTypes.h"
#include "Nvm.h"



typedef enum CryptoInstanceIds
{
	CRYPTO_INSTANCE_ID0
}CryptoInstanceIds;

/*[ECUC_Crypto_00002] Definition of EcucParamConfContainerDef CryptoGeneral*/
/*[ECUC_Crypto_00006] Definition of EcucBooleanParamDef CryptoDevErrorDetect*/
/*[ECUC_Crypto_00040] Definition of EcucIntegerParamDef CryptoInstanceId*/
/*[ECUC_Crypto_00038] Definition of EcucFloatParamDef CryptoMainFunctionPeriod*/
/*[ECUC_Crypto_00007] Definition of EcucBooleanParamDef CryptoVersionInfoApi*/
/*[ECUC_Crypto_00042] Definition of EcucReferenceDef CryptoEcucPartitionRef*/
typedef struct CryptoGeneral
{
	boolean CryptoDevErrorDetect;
	boolean CryptoVersionInfoApi;
	float CryptoMainFunctionPeriod;
	uint8 CryptoInstanceId;
	EcucPartition* CryptoEcucPartitionRef;
}CryptoGeneral;

typedef struct CryptoPrimitive
{
	Crypto_ServiceInfoType CryptoPrimitiveService;
	Crypto_AlgorithmFamilyType CryptoPrimitiveAlgorithmFamily;
	Crypto_AlgorithmModeType CryptoPrimitiveAlgorithmMode;
	Crypto_AlgorithmFamilyType CryptoPrimitiveAlgorithmSecondaryFamily;
	boolean CryptoPrimitiveSupportContext;
	Crypto_AlgorithmFamilyType* CryptoPrimitiveAlgorithmFamilyCustomRef;
	Crypto_AlgorithmFamilyType* CryptoPrimitiveAlgorithmSecondaryFamilyCustomRef;
	Crypto_AlgorithmModeType* CryptoPrimitiveAlgorithmModeCustomRef;
}CryptoPrimitive;

typedef enum CryptoKeyElementReadAccess
{
	CRYPTO_RA_ALLOWED,
	CRYPTO_RA_ENCRYPTED,
	CRYPTO_RA_INTERNAL_COPY,
	CRYPTO_RA_DENIED
}CryptoKeyElementReadAccess;

typedef enum CryptoKeyElementFormat
{
	CRYPTO_KE_FORMAT_BIN_OCTET = 0x01u,
	CRYPTO_KE_FORMAT_BIN_SHEKEYS,
	CRYPTO_KE_FORMAT_BIN_IDENT_PRIVATEKEY_PKCS8,
	CRYPTO_KE_FORMAT_BIN_IDENT_PUBLICKEY,
	CRYPTO_KE_FORMAT_BIN_RSA_PRIVATEKEY,
	CRYPTO_KE_FORMAT_BIN_RSA_PUBLICKEY
}CryptoKeyElementFormat;

typedef enum CryptoKeyElementWriteAccess
{
	CRYPTO_WA_ALLOWED,
	CRYPTO_WA_ENCRYPTED,
	CRYPTO_WA_INTERNAL_COPY,
	CRYPTO_WA_DENIED
}CryptoKeyElementWriteAccess;

typedef enum CryptoKeyElementIds
{
	CRYPTO_KEYELEMENT_MAC_SECLEVEL1,
	CRYPTO_KEYELEMENT_MAC_SECLEVEL3,
	CRYPTO_KEYELEMENT_MAC_SECLEVEL5,
	CRYPTO_KEYELEMENT_SIGNATUREGENERATE,
	CRYPTO_KEYELEMENT_SIGNATUREVERIFY,
	CRYPTO_MAXLIMIT_KEYELEMENT
}CryptoKeyElementIds;

typedef struct CryptoKeyElement
{
	boolean CryptoKeyElementAllowPartialAccess;
	CryptoKeyElementFormat CryptoKeyElementFormat_;
	uint32 CryptoKeyElementId;
	const char* CryptoKeyElementInitValue;
	boolean CryptoKeyElementPersist;
	CryptoKeyElementReadAccess CryptoKeyElementReadAccess_;
	uint32 CryptoKeyElementSize;
	CryptoKeyElementWriteAccess CryptoKeyElementWriteAccess_;
}CryptoKeyElement;

typedef struct CryptoKeyType
{
	CryptoKeyElement* CryptoKeyElementRef;
}CryptoKeyType;

typedef enum
{
	CRYPTO_KEYTYPE_MAC_SECLEVEL1,
	CRYPTO_KEYTYPE_MAC_SECLEVEL3,
	CRYPTO_KEYTYPE_MAC_SECLEVEL5,
	CRYPTO_KEYTYPE_SIGNATUREGENERATE,
	CRYPTO_KEYTYPE_SIGNATUREVERIFY,
	CRYPTO_MAXLIMIT_KEYTYPE
}Crypto_KeyType_Ids;

typedef enum CryptoNvBlockProcessing
{
	CRYPTO_NV_BLOCK_DEFERRED = 0x01u,
	CRYPTO_NV_BLOCK_IMMEDIATE
}CryptoNvBlockProcessing;

typedef struct CryptoNvBlock
{
	uint16 CryptoNvBlockFailedRetries;
	NvMBlockDescriptor* CryptoNvBlockDescriptorRef;
	CryptoNvBlockProcessing CryptoNvBlockProcessing_;
}CryptoNvBlock;

typedef enum
{
	CRYPTO_KEY_MAC_SECLEVEL1,
	CRYPTO_KEY_MAC_SECLEVEL3,
	CRYPTO_KEY_MAC_SECLEVEL5,
	CRYPTO_KEY_RSA2048PRIVATE,
	CRYPTO_KEY_RSA2048PUBLIC,
	CRYPTO_MAXLIMIT_KEYS
}Crypto_Key_Ids;

typedef struct CryptoKey
{
	uint32 CryptoKeyId;
	CryptoKeyType* CryptoKeyTypeRef;
	CryptoNvBlock* CryptoKeyNvBlockRef;
}CryptoKey;

typedef enum CryptoDriverObjectIds
{
	CRYPTO_DRIVER_OBJECT_ID0
}CryptoDriverObjectIds;

/*[ECUC_Crypto_00003] Definition of EcucParamConfContainerDef CryptoDriverObjects*/
typedef struct CryptoDriverObject
{
	uint32 CryptoDriverObjectId;
	CryptoPrimitive* CryptoPrimitiveRef[9];
	CryptoPrimitive* CryptoDefaultRandomPrimitiveRef;
	uint32 CryptoQueueSize;
	EcucPartition* CryptoDriverObjectEcucPartitionRef;
	CryptoKey* CryptoDefaultRandomKeyRef;
}CryptoDriverObject;

typedef struct Crypto_ConfigType
{
	CryptoGeneral CryptoGeneral_;
	CryptoPrimitive CryptoPrimitives[9];
	CryptoKeyElement CryptoKeyElements[5];
	CryptoKeyType CryptoKeyTypes[5];
	CryptoKey CryptoKeys[5];
	CryptoDriverObject CryptoDriverObjects[1];
	CryptoNvBlock CryptoNvStorage[5];
}Crypto_ConfigType;


extern Crypto_ConfigType CryptoDriver_config;


#endif
