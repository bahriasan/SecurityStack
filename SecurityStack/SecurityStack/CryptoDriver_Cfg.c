
#include "CryptoDriver_Cfg.h"

/*SignatureGenerate Key Settings*/
const char CryptoKeyElementSignatureGenerateInitValue[1192] = { 0 };
CryptoKeyElement CryptoKeyElement_SignatureGenerate = { FALSE, CRYPTO_KE_FORMAT_BIN_RSA_PRIVATEKEY , CRYPTO_KEYELEMENT_SIGNATUREGENERATE , CryptoKeyElementSignatureGenerateInitValue , FALSE, CRYPTO_RA_ALLOWED , RSAPRIVATEKEYLENGTH , CRYPTO_WA_ALLOWED };
CryptoKeyType CryptoKeyType_SignatureGenerate = { &CryptoKeyElement_SignatureGenerate };
CryptoNvBlock CryptoNvBlock_SignatureGenerate = { (uint16)0, &NVM_Block3 ,CRYPTO_NV_BLOCK_IMMEDIATE };
CryptoKey CryptoKey_SignatureGenerate = { CRYPTO_KEY_RSA2048PRIVATE , &CryptoKeyType_SignatureGenerate , &CryptoNvBlock_SignatureGenerate };

/*SignatureVerify Key Settings*/
const char CryptoKeyElementSignatureVerifyInitValue[294] = { 0 };
CryptoKeyElement CryptoKeyElement_SignatureVerify = { FALSE, CRYPTO_KE_FORMAT_BIN_RSA_PUBLICKEY , CRYPTO_KEYELEMENT_SIGNATUREVERIFY , CryptoKeyElementSignatureVerifyInitValue , FALSE, CRYPTO_RA_ALLOWED , RSAPUBLICKEYLENGTH , CRYPTO_WA_ALLOWED };
CryptoKeyType CryptoKeyType_SignatureVerify = { &CryptoKeyElement_SignatureVerify };
CryptoNvBlock CryptoNvBlock_SignatureVerify = { (uint16)0, &NVM_Block4 ,CRYPTO_NV_BLOCK_IMMEDIATE };
CryptoKey CryptoKey_SignatureVerify = { CRYPTO_KEY_RSA2048PUBLIC , &CryptoKeyType_SignatureVerify , &CryptoNvBlock_SignatureVerify };

/*SecLevel1 Key Settings*/
const char CryptoKeyElementSecLevel1InitValue[16] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
CryptoKeyElement CryptoKeyElement_Mac_SecLevel1 = { FALSE, CRYPTO_KE_FORMAT_BIN_OCTET , CRYPTO_KEYELEMENT_MAC_SECLEVEL1 , CryptoKeyElementSecLevel1InitValue , FALSE, CRYPTO_RA_ALLOWED , BYTE16KEY , CRYPTO_WA_ALLOWED };
CryptoKeyType CryptoKeyType_Mac_SecLevel1 = { &CryptoKeyElement_Mac_SecLevel1 };
CryptoNvBlock CryptoNvBlock_SecLevel1 = { (uint16)0, &NVM_Block0 ,CRYPTO_NV_BLOCK_IMMEDIATE };
CryptoKey CryptoKey_SecLevel1 = { CRYPTO_KEY_MAC_SECLEVEL1 , &CryptoKeyType_Mac_SecLevel1 , &CryptoNvBlock_SecLevel1 };

/*SecLevel3 Key Settings*/
const char CryptoKeyElementSecLevel3InitValue[16] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
CryptoKeyElement CryptoKeyElement_Mac_SecLevel3 = { FALSE, CRYPTO_KE_FORMAT_BIN_OCTET , CRYPTO_KEYELEMENT_MAC_SECLEVEL1 , CryptoKeyElementSecLevel3InitValue , FALSE, CRYPTO_RA_ALLOWED , BYTE16KEY , CRYPTO_WA_ALLOWED };
CryptoKeyType CryptoKeyType_Mac_SecLevel3 = { &CryptoKeyElement_Mac_SecLevel3 };
CryptoNvBlock CryptoNvBlock_SecLevel3 = { (uint16)0, &NVM_Block1 ,CRYPTO_NV_BLOCK_IMMEDIATE };
CryptoKey CryptoKey_SecLevel3 = { CRYPTO_KEY_MAC_SECLEVEL3 , &CryptoKeyType_Mac_SecLevel3 , &CryptoNvBlock_SecLevel3 };

/*SecLevel5 Key Settings*/
const char CryptoKeyElementSecLevel5InitValue[16] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
CryptoKeyElement CryptoKeyElement_Mac_SecLevel5 = { FALSE, CRYPTO_KE_FORMAT_BIN_OCTET , CRYPTO_KEYELEMENT_MAC_SECLEVEL1 , CryptoKeyElementSecLevel5InitValue , FALSE, CRYPTO_RA_ALLOWED , BYTE16KEY , CRYPTO_WA_ALLOWED };
CryptoKeyType CryptoKeyType_Mac_SecLevel5 = { &CryptoKeyElement_Mac_SecLevel5 };
CryptoNvBlock CryptoNvBlock_SecLevel5 = { (uint16)0, &NVM_Block2 ,CRYPTO_NV_BLOCK_IMMEDIATE };
CryptoKey CryptoKey_SecLevel5 = { CRYPTO_KEY_MAC_SECLEVEL5 , &CryptoKeyType_Mac_SecLevel5 , &CryptoNvBlock_SecLevel5 };

Crypto_AlgorithmFamilyType CryptoPrimitiveAlgorithmFamilyCustom = CRYPTO_ALGOFAM_CUSTOM;
Crypto_AlgorithmModeType CryptoPrimitiveAlgorithmModeCustom = CRYPTO_ALGOMODE_CUSTOM;

CryptoPrimitive CryptoPrimitive_Hash = { CRYPTO_HASH , CRYPTO_ALGOFAM_SHA2_256 , CRYPTO_ALGOMODE_CMAC, CRYPTO_ALGOFAM_SHA2_256 , FALSE, &CryptoPrimitiveAlgorithmFamilyCustom , &CryptoPrimitiveAlgorithmFamilyCustom , &CryptoPrimitiveAlgorithmModeCustom };
CryptoPrimitive CryptoPrimitive_MacGenerate_SecLevel1 = { CRYPTO_MACGENERATE , CRYPTO_ALGOFAM_AES , CRYPTO_ALGOMODE_CMAC, CRYPTO_ALGOFAM_AES , FALSE, &CryptoPrimitiveAlgorithmFamilyCustom , &CryptoPrimitiveAlgorithmFamilyCustom , &CryptoPrimitiveAlgorithmModeCustom };
CryptoPrimitive CryptoPrimitive_MacVerify_SecLevel1 = { CRYPTO_MACVERIFY , CRYPTO_ALGOFAM_AES , CRYPTO_ALGOMODE_CMAC, CRYPTO_ALGOFAM_AES , FALSE, &CryptoPrimitiveAlgorithmFamilyCustom , &CryptoPrimitiveAlgorithmFamilyCustom , &CryptoPrimitiveAlgorithmModeCustom };
CryptoPrimitive CryptoPrimitive_MacGenerate_SecLevel3 = { CRYPTO_MACGENERATE , CRYPTO_ALGOFAM_AES , CRYPTO_ALGOMODE_CMAC, CRYPTO_ALGOFAM_AES , FALSE, &CryptoPrimitiveAlgorithmFamilyCustom , &CryptoPrimitiveAlgorithmFamilyCustom , &CryptoPrimitiveAlgorithmModeCustom };
CryptoPrimitive CryptoPrimitive_MacVerify_SecLevel3 = { CRYPTO_MACVERIFY , CRYPTO_ALGOFAM_AES , CRYPTO_ALGOMODE_CMAC, CRYPTO_ALGOFAM_AES , FALSE, &CryptoPrimitiveAlgorithmFamilyCustom , &CryptoPrimitiveAlgorithmFamilyCustom , &CryptoPrimitiveAlgorithmModeCustom };
CryptoPrimitive CryptoPrimitive_MacGenerate_SecLevel5 = { CRYPTO_MACGENERATE , CRYPTO_ALGOFAM_AES , CRYPTO_ALGOMODE_CMAC, CRYPTO_ALGOFAM_AES , FALSE, &CryptoPrimitiveAlgorithmFamilyCustom , &CryptoPrimitiveAlgorithmFamilyCustom , &CryptoPrimitiveAlgorithmModeCustom };
CryptoPrimitive CryptoPrimitive_MacVerify_SecLevel5 = { CRYPTO_MACVERIFY , CRYPTO_ALGOFAM_AES , CRYPTO_ALGOMODE_CMAC, CRYPTO_ALGOFAM_AES , FALSE, &CryptoPrimitiveAlgorithmFamilyCustom , &CryptoPrimitiveAlgorithmFamilyCustom , &CryptoPrimitiveAlgorithmModeCustom };
CryptoPrimitive CryptoPrimitive_SeedGenerate = { CRYPTO_RANDOMGENERATE , CRYPTO_ALGOFAM_SHA2_256 , CRYPTO_ALGOMODE_CMAC, CRYPTO_ALGOFAM_SHA2_256 , FALSE, &CryptoPrimitiveAlgorithmFamilyCustom , &CryptoPrimitiveAlgorithmFamilyCustom , &CryptoPrimitiveAlgorithmModeCustom };
CryptoPrimitive CryptoPrimitive_SignatureGenerate = { CRYPTO_SIGNATUREGENERATE , CRYPTO_ALGOFAM_RSA , CRYPTO_ALGOMODE_RSASSA_PKCS1_v1_5, CRYPTO_ALGOFAM_NOT_SET , FALSE, &CryptoPrimitiveAlgorithmFamilyCustom , &CryptoPrimitiveAlgorithmFamilyCustom , &CryptoPrimitiveAlgorithmModeCustom };
CryptoPrimitive CryptoPrimitive_SignatureVerify = { CRYPTO_SIGNATUREVERIFY , CRYPTO_ALGOFAM_RSA , CRYPTO_ALGOMODE_RSASSA_PKCS1_v1_5, CRYPTO_ALGOFAM_NOT_SET , FALSE, &CryptoPrimitiveAlgorithmFamilyCustom , &CryptoPrimitiveAlgorithmFamilyCustom , &CryptoPrimitiveAlgorithmModeCustom };

Crypto_ConfigType CryptoDriver_config = 
{
	{TRUE, TRUE, 1.f, CRYPTO_INSTANCE_ID0, &EcucPartition_0},	//CryptoGeneral
	{	//CryptoPrimitive
		{ CRYPTO_HASH, CRYPTO_ALGOFAM_SHA2_256, CRYPTO_ALGOMODE_CMAC, CRYPTO_ALGOFAM_SHA2_256, TRUE, &CryptoPrimitiveAlgorithmFamilyCustom, &CryptoPrimitiveAlgorithmFamilyCustom, &CryptoPrimitiveAlgorithmModeCustom },						//CryptoPrimitive_Hash
		{ CRYPTO_MACGENERATE, CRYPTO_ALGOFAM_SHA2_256, CRYPTO_ALGOMODE_CMAC, CRYPTO_ALGOFAM_SHA2_256, TRUE, &CryptoPrimitiveAlgorithmFamilyCustom, &CryptoPrimitiveAlgorithmFamilyCustom, &CryptoPrimitiveAlgorithmModeCustom },				//CryptoPrimitive_MacGenerate_SecLevel1
		{ CRYPTO_MACVERIFY, CRYPTO_ALGOFAM_SHA2_256, CRYPTO_ALGOMODE_CMAC, CRYPTO_ALGOFAM_SHA2_256, TRUE, &CryptoPrimitiveAlgorithmFamilyCustom, &CryptoPrimitiveAlgorithmFamilyCustom, &CryptoPrimitiveAlgorithmModeCustom },					//CryptoPrimitive_MacVerify_SecLevel1
		{ CRYPTO_MACGENERATE, CRYPTO_ALGOFAM_SHA2_256, CRYPTO_ALGOMODE_CMAC, CRYPTO_ALGOFAM_SHA2_256, TRUE, &CryptoPrimitiveAlgorithmFamilyCustom, &CryptoPrimitiveAlgorithmFamilyCustom, &CryptoPrimitiveAlgorithmModeCustom },				//CryptoPrimitive_MacGenerate_SecLevel3
		{ CRYPTO_MACVERIFY, CRYPTO_ALGOFAM_SHA2_256, CRYPTO_ALGOMODE_CMAC, CRYPTO_ALGOFAM_SHA2_256, TRUE, &CryptoPrimitiveAlgorithmFamilyCustom, &CryptoPrimitiveAlgorithmFamilyCustom, &CryptoPrimitiveAlgorithmModeCustom },					//CryptoPrimitive_MacVerify_SecLevel3
		{ CRYPTO_MACGENERATE, CRYPTO_ALGOFAM_SHA2_256, CRYPTO_ALGOMODE_CMAC, CRYPTO_ALGOFAM_SHA2_256, TRUE, &CryptoPrimitiveAlgorithmFamilyCustom, &CryptoPrimitiveAlgorithmFamilyCustom, &CryptoPrimitiveAlgorithmModeCustom },				//CryptoPrimitive_MacGenerate_SecLevel5
		{ CRYPTO_MACVERIFY, CRYPTO_ALGOFAM_SHA2_256, CRYPTO_ALGOMODE_CMAC, CRYPTO_ALGOFAM_SHA2_256, TRUE, &CryptoPrimitiveAlgorithmFamilyCustom, &CryptoPrimitiveAlgorithmFamilyCustom, &CryptoPrimitiveAlgorithmModeCustom },					//CryptoPrimitive_MacVerify_SecLevel5
		{ CRYPTO_RANDOMGENERATE, CRYPTO_ALGOFAM_SHA2_256, CRYPTO_ALGOMODE_CMAC, CRYPTO_ALGOFAM_SHA2_256, TRUE, &CryptoPrimitiveAlgorithmFamilyCustom, &CryptoPrimitiveAlgorithmFamilyCustom, &CryptoPrimitiveAlgorithmModeCustom },				//CryptoPrimitive_SeedGenerate
		{ CRYPTO_SIGNATUREGENERATE, CRYPTO_ALGOFAM_RSA, CRYPTO_ALGOMODE_RSASSA_PKCS1_v1_5, CRYPTO_ALGOFAM_NOT_SET, TRUE, &CryptoPrimitiveAlgorithmFamilyCustom, &CryptoPrimitiveAlgorithmFamilyCustom, &CryptoPrimitiveAlgorithmModeCustom },	//CryptoPrimitive_SignatureGenerate
		{ CRYPTO_SIGNATUREVERIFY, CRYPTO_ALGOFAM_RSA, CRYPTO_ALGOMODE_RSASSA_PKCS1_v1_5, CRYPTO_ALGOFAM_NOT_SET, TRUE, &CryptoPrimitiveAlgorithmFamilyCustom, &CryptoPrimitiveAlgorithmFamilyCustom, &CryptoPrimitiveAlgorithmModeCustom }		//CryptoPrimitive_SignatureVerify
	},	
	{	//CryptoKeyElements
		{ FALSE, CRYPTO_KE_FORMAT_BIN_OCTET , CRYPTO_KEYELEMENT_MAC_SECLEVEL1 , CryptoKeyElementSecLevel1InitValue , FALSE, CRYPTO_RA_ALLOWED , BYTE16KEY , CRYPTO_WA_ALLOWED },
		{ FALSE, CRYPTO_KE_FORMAT_BIN_OCTET , CRYPTO_KEYELEMENT_MAC_SECLEVEL3 , CryptoKeyElementSecLevel3InitValue , FALSE, CRYPTO_RA_ALLOWED , BYTE16KEY , CRYPTO_WA_ALLOWED },
		{ FALSE, CRYPTO_KE_FORMAT_BIN_OCTET , CRYPTO_KEYELEMENT_MAC_SECLEVEL5 , CryptoKeyElementSecLevel5InitValue , FALSE, CRYPTO_RA_ALLOWED , BYTE16KEY , CRYPTO_WA_ALLOWED },
		{ FALSE, CRYPTO_KE_FORMAT_BIN_RSA_PRIVATEKEY , CRYPTO_KEYELEMENT_SIGNATUREGENERATE , CryptoKeyElementSignatureGenerateInitValue , FALSE, CRYPTO_RA_ALLOWED , RSAPRIVATEKEYLENGTH , CRYPTO_WA_ALLOWED },
		{ FALSE, CRYPTO_KE_FORMAT_BIN_RSA_PUBLICKEY , CRYPTO_KEYELEMENT_SIGNATUREVERIFY , CryptoKeyElementSignatureVerifyInitValue , FALSE, CRYPTO_RA_ALLOWED , RSAPUBLICKEYLENGTH , CRYPTO_WA_ALLOWED }
	},
	{	//CryptoKeyTypes
		{ &CryptoKeyElement_Mac_SecLevel1 },
		{ &CryptoKeyElement_Mac_SecLevel3 },
		{ &CryptoKeyElement_Mac_SecLevel5 },
		{ &CryptoKeyElement_SignatureGenerate },
		{ &CryptoKeyElement_SignatureVerify }
	},	
	{	//CryptoKey
		{ CRYPTO_KEY_MAC_SECLEVEL1 , &CryptoKeyType_Mac_SecLevel1 , &CryptoNvBlock_SecLevel1 },
		{ CRYPTO_KEY_MAC_SECLEVEL3 , &CryptoKeyType_Mac_SecLevel3 , &CryptoNvBlock_SecLevel3 },
		{ CRYPTO_KEY_MAC_SECLEVEL5 , &CryptoKeyType_Mac_SecLevel5 , &CryptoNvBlock_SecLevel5 },
		{ CRYPTO_KEY_RSA2048PRIVATE ,& CryptoKeyType_SignatureGenerate ,& CryptoNvBlock_SignatureGenerate },
		{ CRYPTO_KEY_RSA2048PUBLIC , &CryptoKeyType_SignatureVerify , &CryptoNvBlock_SignatureVerify }
	},
	{	//CryptoDriverObject
		{CRYPTO_DRIVER_OBJECT_ID0, {&CryptoPrimitive_Hash, &CryptoPrimitive_MacGenerate_SecLevel1, &CryptoPrimitive_MacVerify_SecLevel1, &CryptoPrimitive_MacGenerate_SecLevel3, &CryptoPrimitive_MacVerify_SecLevel3, &CryptoPrimitive_MacGenerate_SecLevel5, &CryptoPrimitive_MacVerify_SecLevel5,&CryptoPrimitive_SeedGenerate, &CryptoPrimitive_SignatureGenerate, &CryptoPrimitive_SignatureVerify }, NULL, 1u, &EcucPartition_0, NULL}
	},
	{
		{ (uint16)0, &NVM_Block0 ,CRYPTO_NV_BLOCK_IMMEDIATE },
		{ (uint16)0, &NVM_Block1 ,CRYPTO_NV_BLOCK_IMMEDIATE },
		{ (uint16)0, &NVM_Block2 ,CRYPTO_NV_BLOCK_IMMEDIATE },
		{ (uint16)0, &NVM_Block3 ,CRYPTO_NV_BLOCK_IMMEDIATE },
		{ (uint16)0, &NVM_Block4 ,CRYPTO_NV_BLOCK_IMMEDIATE }
	}
};

