
#include "Csm_Cfg.h"


void Notification_SeedGenerate(void) {/*TBD*/ }
void Notification_SecLevel1_MacGenerate(void) {/*TBD*/ }
void Notification_SecLevel1_MacVerify(void) {/*TBD*/ }
void Notification_SecLevel3_MacGenerate(void) {/*TBD*/ }
void Notification_SecLevel3_MacVerify(void) {/*TBD*/ }
void Notification_SecLevel5_MacGenerate(void) {/*TBD*/ }
void Notification_SecLevel5_MacVerify(void) {/*TBD*/ }
void Notification_SignatureGenerate(void) {/*TBD*/ }
void Notification_SignatureVerify(void) {/*TBD*/ }


Crypto_AlgorithmFamilyType CsmAlgorithmFamilyCustom = CRYPTO_ALGOFAM_CUSTOM;

Crypto_AlgorithmModeType CsmAlgorithmModeCustom = CRYPTO_ALGOMODE_CUSTOM;


CsmPrimitives CsmPrimitives_SecLevel1_MacGenerate = { 
	{ CRYPTO_ALGOFAM_AES, CRYPTO_ALGOFAM_AES, &CsmAlgorithmFamilyCustom, &CsmAlgorithmFamilyCustom, CRYPTO_ALGOMODE_CBC , &CsmAlgorithmModeCustom, BYTE16KEY, 32u, BIT128RESULT },
	{0}, {0}, {0}, {0} };

CsmPrimitives CsmPrimitives_SecLevel1_MacVerify = { 
	{0},
	{ CRYPTO_ALGOFAM_AES, CRYPTO_ALGOFAM_AES, &CsmAlgorithmFamilyCustom, &CsmAlgorithmFamilyCustom, CRYPTO_ALGOMODE_CBC , &CsmAlgorithmModeCustom, BYTE16KEY, 32u, 32u },
	{0}, {0}, {0} };

CsmPrimitives CsmPrimitives_SecLevel3_MacGenerate = {
	{ CRYPTO_ALGOFAM_AES, CRYPTO_ALGOFAM_AES, &CsmAlgorithmFamilyCustom, &CsmAlgorithmFamilyCustom, CRYPTO_ALGOMODE_CBC , &CsmAlgorithmModeCustom, BYTE16KEY, 32u, BIT128RESULT },
	{0}, {0}, {0}, {0} };

CsmPrimitives CsmPrimitives_SecLevel3_MacVerify = {
	{0},
	{ CRYPTO_ALGOFAM_AES, CRYPTO_ALGOFAM_AES, &CsmAlgorithmFamilyCustom, &CsmAlgorithmFamilyCustom, CRYPTO_ALGOMODE_CBC , &CsmAlgorithmModeCustom, BYTE16KEY, 32u, 32u },
	{0}, {0}, {0} };

CsmPrimitives CsmPrimitives_SecLevel5_MacGenerate = {
	{ CRYPTO_ALGOFAM_AES, CRYPTO_ALGOFAM_AES, &CsmAlgorithmFamilyCustom, &CsmAlgorithmFamilyCustom, CRYPTO_ALGOMODE_CBC , &CsmAlgorithmModeCustom, BYTE16KEY, 32u, BIT128RESULT },
	{0}, {0}, {0}, {0} };

CsmPrimitives CsmPrimitives_SecLevel5_MacVerify = {
	{0}, 
	{ CRYPTO_ALGOFAM_AES, CRYPTO_ALGOFAM_AES, &CsmAlgorithmFamilyCustom, &CsmAlgorithmFamilyCustom, CRYPTO_ALGOMODE_CBC , &CsmAlgorithmModeCustom, BYTE16KEY, 32u, 32u },
	{0}, {0}, {0} };

CsmPrimitives CsmPrimitives_SeedGenerate = { 
	{0}, {0},
	{ CRYPTO_ALGOFAM_RNG, CRYPTO_ALGOFAM_NOT_SET, &CsmAlgorithmFamilyCustom, &CsmAlgorithmFamilyCustom, CRYPTO_ALGOMODE_CTRDRBG , &CsmAlgorithmModeCustom, 32u }, 
	{0} , {0} };

CsmPrimitives CsmPrimitives_SignatureGenerate = { 
	{0}, {0}, {0},
	{ CRYPTO_ALGOFAM_RSA, CRYPTO_ALGOFAM_NOT_SET, &CsmAlgorithmFamilyCustom, &CsmAlgorithmFamilyCustom, CRYPTO_ALGOMODE_RSASSA_PKCS1_v1_5 , &CsmAlgorithmModeCustom, 32u, RSAPRIVATEKEYLENGTH, BYTE256RESULT },
	{0} };

CsmPrimitives CsmPrimitives_SignatureVerify = { 
	{0}, {0}, {0}, {0},
	{ CRYPTO_ALGOFAM_RSA, CRYPTO_ALGOFAM_NOT_SET, &CsmAlgorithmFamilyCustom, &CsmAlgorithmFamilyCustom, CRYPTO_ALGOMODE_RSASSA_PKCS1_v1_5 , &CsmAlgorithmModeCustom, 32u, RSAPUBLICKEYLENGTH, 32u } };


CsmMainFunction Csm_MainFunction = { 0u, &EcucPartition_0 };

CsmQueue CsmQueue_0 = { &(CryIf_config.CryIfChannels[0]) , 1u, &Csm_MainFunction };


//Mac Key Settings
CsmKey CsmKey_Mac_SecLevel1 = { CSM_KEY_MAC_SECLEVEL1 , &(CryIf_config.CryIfKeys[0]) , FALSE};

//Mac Key Settings
CsmKey CsmKey_Mac_SecLevel3 = { CSM_KEY_MAC_SECLEVEL1 , &(CryIf_config.CryIfKeys[1]) , FALSE };

//Mac Key Settings
CsmKey CsmKey_Mac_SecLevel5 = { CSM_KEY_MAC_SECLEVEL1 , &(CryIf_config.CryIfKeys[2]) , FALSE };

//SignatureGenerate Key Settings
CsmKey CsmKey_SignatureGenerate = { CSM_KEY_RSA_PRIVATE , &(CryIf_config.CryIfKeys[3]) , FALSE };

//RandomGenerate Key Settings
CsmKey CsmKey_SignatureVerify = { CSM_KEY_RSA_PUBLIC , &(CryIf_config.CryIfKeys[4]) , FALSE };


//Initial Configuration
const Csm_ConfigType Csm_config =
{
	{TRUE, TRUE},	//CsmGeneral
	{	//CsmJobs
		{JOBID_SEEDGENERATE, JOBPRIO_SEEDGENERATE, CRYPTO_USE_FNC , &Notification_SeedGenerate, &CsmPrimitives_SeedGenerate, &CsmQueue_0, NULL, CRYPTO_PROCESSING_SYNC, CRYPTO_USE_FNC },//CsmJob_SecLevel1_SeedGenerate
		{JOBID_SECLEVEL1_MACGENERATE, JOBPRIO_SECLEVEL1_MACGENERATE, CRYPTO_USE_FNC , &Notification_SecLevel1_MacGenerate, &CsmPrimitives_SecLevel1_MacGenerate, &CsmQueue_0, &CsmKey_Mac_SecLevel1, CRYPTO_PROCESSING_SYNC, CRYPTO_USE_FNC },//CsmJob_SecLevel1_MacGenerate
		{JOBID_SECLEVEL1_MACVERIFY, JOBPRIO_SECLEVEL1_MACVERIFY, CRYPTO_USE_FNC , &Notification_SecLevel1_MacVerify, &CsmPrimitives_SecLevel1_MacVerify, &CsmQueue_0, &CsmKey_Mac_SecLevel1, CRYPTO_PROCESSING_SYNC, CRYPTO_USE_FNC },//CsmJob_SecLevel1_MacVerify
		{JOBID_SECLEVEL3_MACGENERATE, JOBPRIO_SECLEVEL3_MACGENERATE, CRYPTO_USE_FNC , &Notification_SecLevel3_MacGenerate, &CsmPrimitives_SecLevel3_MacGenerate, &CsmQueue_0, &CsmKey_Mac_SecLevel3, CRYPTO_PROCESSING_SYNC, CRYPTO_USE_FNC },//CsmJob_SecLevel3_MacGenerate
		{JOBID_SECLEVEL3_MACVERIFY, JOBPRIO_SECLEVEL3_MACVERIFY, CRYPTO_USE_FNC , &Notification_SecLevel3_MacVerify, &CsmPrimitives_SecLevel3_MacVerify, &CsmQueue_0, &CsmKey_Mac_SecLevel3, CRYPTO_PROCESSING_SYNC, CRYPTO_USE_FNC },//CsmJob_SecLevel3_MacVerify
		{JOBID_SECLEVEL5_MACGENERATE, JOBPRIO_SECLEVEL5_MACGENERATE, CRYPTO_USE_FNC , &Notification_SecLevel5_MacGenerate, &CsmPrimitives_SecLevel5_MacGenerate, &CsmQueue_0, &CsmKey_Mac_SecLevel5, CRYPTO_PROCESSING_SYNC, CRYPTO_USE_FNC },//CsmJob_SecLevel5_MacGenerate
		{JOBID_SECLEVEL5_MACVERIFY, JOBPRIO_SECLEVEL5_MACVERIFY, CRYPTO_USE_FNC , &Notification_SecLevel5_MacVerify, &CsmPrimitives_SecLevel5_MacVerify, &CsmQueue_0, &CsmKey_Mac_SecLevel5, CRYPTO_PROCESSING_SYNC, CRYPTO_USE_FNC },//CsmJob_SecLevel5_MacVerify
		{JOBID_SIGNATUREGENERATE, JOBPRIO_SIGNATUREGENERATE, CRYPTO_USE_FNC, &Notification_SignatureGenerate, &CsmPrimitives_SignatureGenerate, &CsmQueue_0, &CsmKey_SignatureGenerate, CRYPTO_PROCESSING_SYNC, CRYPTO_USE_FNC},		//CsmJob_SignatureGenerate
		{JOBID_SIGNATUREVERIFY, JOBPRIO_SIGNATUREVERIFY, CRYPTO_USE_FNC,&Notification_SignatureVerify,&CsmPrimitives_SignatureVerify,&CsmQueue_0,&CsmKey_SignatureVerify, CRYPTO_PROCESSING_SYNC, CRYPTO_USE_FNC}		//CsmJob_SignatureVerify
	},
	{	//CsmKeys
		{ CSM_KEY_MAC_SECLEVEL1 , &(CryIf_config.CryIfKeys[0]) , TRUE},				//CsmKey_SecLevel1Mac
		{ CSM_KEY_MAC_SECLEVEL3 , &(CryIf_config.CryIfKeys[1]) , TRUE},				//CsmKey_SecLevel3Mac
		{ CSM_KEY_MAC_SECLEVEL5 , &(CryIf_config.CryIfKeys[2]) , TRUE},				//CsmKey_SecLevel5Mac
		{ CSM_KEY_RSA_PRIVATE ,& (CryIf_config.CryIfKeys[3]) , TRUE },				//CsmKey_RSA_Private
		{ CSM_KEY_RSA_PUBLIC , &(CryIf_config.CryIfKeys[4]) , TRUE}					//CsmKey_RSA_Public
	},
	{ {CRYPTO_ALGOFAM_AES, CRYPTO_ALGOFAM_AES, &CsmAlgorithmFamilyCustom, &CsmAlgorithmFamilyCustom, CRYPTO_ALGOMODE_CBC , &CsmAlgorithmModeCustom, BYTE16KEY, 32u, BIT128RESULT }, {0}, {0}, {0}, {0} },	//CsmPrimitives_SecLevel1_MacGenerate
	{ {0}, {CRYPTO_ALGOFAM_AES, CRYPTO_ALGOFAM_AES, &CsmAlgorithmFamilyCustom, &CsmAlgorithmFamilyCustom, CRYPTO_ALGOMODE_CBC , &CsmAlgorithmModeCustom, BYTE16KEY, 32u, 32u }, {0}, {0}, {0} },			//CsmPrimitives_SecLevel1_MacVerify
	{ {CRYPTO_ALGOFAM_AES, CRYPTO_ALGOFAM_AES, &CsmAlgorithmFamilyCustom, &CsmAlgorithmFamilyCustom, CRYPTO_ALGOMODE_CBC , &CsmAlgorithmModeCustom, BYTE16KEY, 32u, BIT128RESULT }, {0}, {0}, {0}, {0} },	//CsmPrimitives_SecLevel3_MacGenerate
	{ {0}, {CRYPTO_ALGOFAM_AES, CRYPTO_ALGOFAM_AES, &CsmAlgorithmFamilyCustom, &CsmAlgorithmFamilyCustom, CRYPTO_ALGOMODE_CBC , &CsmAlgorithmModeCustom, BYTE16KEY, 32u, 32u }, {0}, {0}, {0} },			//CsmPrimitives_SecLevel3_MacVerify
	{ {CRYPTO_ALGOFAM_AES, CRYPTO_ALGOFAM_AES, &CsmAlgorithmFamilyCustom, &CsmAlgorithmFamilyCustom, CRYPTO_ALGOMODE_CBC , &CsmAlgorithmModeCustom, BYTE16KEY, 32u, BIT128RESULT }, {0}, {0}, {0}, {0} },	//CsmPrimitives_SecLevel5_MacGenerate
	{ {0}, {CRYPTO_ALGOFAM_AES, CRYPTO_ALGOFAM_AES, &CsmAlgorithmFamilyCustom, &CsmAlgorithmFamilyCustom, CRYPTO_ALGOMODE_CBC , &CsmAlgorithmModeCustom, BYTE16KEY, 32u, 32u }, {0}, {0}, {0} },			//CsmPrimitives_SecLevel5_MacVerify
	{ {0}, {0}, {CRYPTO_ALGOFAM_NOT_SET, CRYPTO_ALGOFAM_NOT_SET, &CsmAlgorithmFamilyCustom, &CsmAlgorithmFamilyCustom, CRYPTO_ALGOMODE_NOT_SET , &CsmAlgorithmModeCustom, 32u }, {0}, {0} },				//CsmPrimitives_SeedGenerate
	{ {0}, {0}, {0}, {CRYPTO_ALGOFAM_RSA, CRYPTO_ALGOFAM_NOT_SET, &CsmAlgorithmFamilyCustom, &CsmAlgorithmFamilyCustom, CRYPTO_ALGOMODE_RSASSA_PKCS1_v1_5 , &CsmAlgorithmModeCustom, 32u, RSAPRIVATEKEYLENGTH, BYTE256RESULT }, {0} },	//CsmPrimitives_SignatureGenerate
	{ {0}, {0}, {0}, {0}, {CRYPTO_ALGOFAM_RSA, CRYPTO_ALGOFAM_NOT_SET, &CsmAlgorithmFamilyCustom, &CsmAlgorithmFamilyCustom, CRYPTO_ALGOMODE_RSASSA_PKCS1_v1_5 , &CsmAlgorithmModeCustom, 32u, RSAPUBLICKEYLENGTH, 32u } },	//CsmPrimitives_SignatureVerify
	{	//CsmQueues
		{&(CryIf_config.CryIfChannels[0]), 1u, &Csm_MainFunction}
	},
	{	//CsmCallbacks
		{&Notification_SeedGenerate},
		{&Notification_SecLevel1_MacGenerate},
		{&Notification_SecLevel1_MacVerify},
		{&Notification_SecLevel3_MacGenerate},
		{&Notification_SecLevel3_MacVerify},
		{&Notification_SecLevel5_MacGenerate},
		{&Notification_SecLevel5_MacVerify},
		{&Notification_SignatureGenerate},
		{&Notification_SignatureVerify}
	},
	{ 0u, &EcucPartition_0 }	//MainFunction
};


//RunTime Configuration

Crypto_PrimitiveInfoType Crypto_PrimitiveInfo_SeedGenerate = { CRYPTO_RANDOMGENERATE, CRYPTO_ALGOFAM_RNG, CRYPTO_ALGOFAM_NOT_SET, 0u, CRYPTO_ALGOMODE_CTRDRBG };
const Crypto_JobPrimitiveInfoType Crypto_JobPrimitiveInfo_SeedGenerate = { CALLBACK_ID_SEEDGENERATE, &Crypto_PrimitiveInfo_SeedGenerate, 0u, CRYPTO_PROCESSING_SYNC };

Crypto_PrimitiveInfoType Crypto_PrimitiveInfo_SecLevel1_MacGenerate = { CRYPTO_MACGENERATE, CRYPTO_ALGOFAM_AES, CRYPTO_ALGOFAM_NOT_SET, BYTE16KEY, CRYPTO_ALGOMODE_CBC };
const Crypto_JobPrimitiveInfoType Crypto_JobPrimitiveInfo_SecLevel1_MacGenerate = { CALLBACK_ID_SECLEVEL1_MACGENERATE, &Crypto_PrimitiveInfo_SecLevel1_MacGenerate, CRYIF_KEY_MAC_SECLEVEL1, CRYPTO_PROCESSING_SYNC };

Crypto_PrimitiveInfoType Crypto_PrimitiveInfo_SecLevel1_MacVerify = { CRYPTO_MACVERIFY, CRYPTO_ALGOFAM_AES, CRYPTO_ALGOFAM_NOT_SET, BYTE16KEY, CRYPTO_ALGOMODE_CBC };
const Crypto_JobPrimitiveInfoType Crypto_JobPrimitiveInfo_SecLevel1_MacVerify = { CALLBACK_ID_SECLEVEL1_MACVERIFY, &Crypto_PrimitiveInfo_SecLevel1_MacVerify, CRYIF_KEY_MAC_SECLEVEL1, CRYPTO_PROCESSING_SYNC };

Crypto_PrimitiveInfoType Crypto_PrimitiveInfo_SecLevel3_MacGenerate = { CRYPTO_MACGENERATE, CRYPTO_ALGOFAM_AES, CRYPTO_ALGOFAM_NOT_SET, BYTE16KEY, CRYPTO_ALGOMODE_CBC };
const Crypto_JobPrimitiveInfoType Crypto_JobPrimitiveInfo_SecLevel3_MacGenerate = { CALLBACK_ID_SECLEVEL3_MACGENERATE, &Crypto_PrimitiveInfo_SecLevel3_MacGenerate, CRYIF_KEY_MAC_SECLEVEL3, CRYPTO_PROCESSING_SYNC };

Crypto_PrimitiveInfoType Crypto_PrimitiveInfo_SecLevel3_MacVerify = { CRYPTO_MACVERIFY, CRYPTO_ALGOFAM_AES, CRYPTO_ALGOFAM_NOT_SET, BYTE16KEY, CRYPTO_ALGOMODE_CBC };
const Crypto_JobPrimitiveInfoType Crypto_JobPrimitiveInfo_SecLevel3_MacVerify = { CALLBACK_ID_SECLEVEL3_MACVERIFY, &Crypto_PrimitiveInfo_SecLevel3_MacVerify, CRYIF_KEY_MAC_SECLEVEL3, CRYPTO_PROCESSING_SYNC };

Crypto_PrimitiveInfoType Crypto_PrimitiveInfo_SecLevel5_MacGenerate = { CRYPTO_MACGENERATE, CRYPTO_ALGOFAM_AES, CRYPTO_ALGOFAM_NOT_SET, BYTE16KEY, CRYPTO_ALGOMODE_CBC };
const Crypto_JobPrimitiveInfoType Crypto_JobPrimitiveInfo_SecLevel5_MacGenerate = { CALLBACK_ID_SECLEVEL5_MACGENERATE, &Crypto_PrimitiveInfo_SecLevel5_MacGenerate, CRYIF_KEY_MAC_SECLEVEL5, CRYPTO_PROCESSING_SYNC };

Crypto_PrimitiveInfoType Crypto_PrimitiveInfo_SecLevel5_MacVerify = { CRYPTO_MACVERIFY, CRYPTO_ALGOFAM_AES, CRYPTO_ALGOFAM_NOT_SET, BYTE16KEY, CRYPTO_ALGOMODE_CBC };
const Crypto_JobPrimitiveInfoType Crypto_JobPrimitiveInfo_SecLevel5_MacVerify = { CALLBACK_ID_SECLEVEL5_MACVERIFY, &Crypto_PrimitiveInfo_SecLevel5_MacVerify, CRYIF_KEY_MAC_SECLEVEL5, CRYPTO_PROCESSING_SYNC };


Crypto_PrimitiveInfoType Crypto_PrimitiveInfo_SignatureGenerate = { CRYPTO_SIGNATUREGENERATE, CRYPTO_ALGOFAM_RSA, CRYPTO_ALGOFAM_NOT_SET, RSAPRIVATEKEYLENGTH, CRYPTO_ALGOMODE_RSASSA_PKCS1_v1_5 };
const Crypto_JobPrimitiveInfoType Crypto_JobPrimitiveInfo_SignatureGenerate = { CALLBACK_ID_SIGNATUREGENERATE, &Crypto_PrimitiveInfo_SignatureGenerate, CRYIF_KEY_SIGNATUREGENERATE, CRYPTO_PROCESSING_SYNC };

Crypto_PrimitiveInfoType Crypto_PrimitiveInfo_SignatureVerify = { CRYPTO_SIGNATUREVERIFY, CRYPTO_ALGOFAM_RSA, CRYPTO_ALGOFAM_NOT_SET, RSAPUBLICKEYLENGTH, CRYPTO_ALGOMODE_RSASSA_PKCS1_v1_5 };
const Crypto_JobPrimitiveInfoType Crypto_JobPrimitiveInfo_SignatureVerify = { CALLBACK_ID_SIGNATUREVERIFY, &Crypto_PrimitiveInfo_SignatureVerify, CRYIF_KEY_SIGNATUREVERIFY, CRYPTO_PROCESSING_SYNC };




rnt_cfg rnt =
{
	{	//Crypto_JobType Jobs[MAX_JOBID]
		{ JOBID_SEEDGENERATE, {0}, {0}, &Crypto_JobPrimitiveInfo_SeedGenerate, {0}, 0u, 0u, JOBPRIO_SEEDGENERATE },
		{ JOBID_SECLEVEL1_MACGENERATE, {0}, {0}, &Crypto_JobPrimitiveInfo_SecLevel1_MacGenerate, {0}, 0u, 0u, JOBPRIO_SECLEVEL1_MACGENERATE },
		{ JOBID_SECLEVEL1_MACVERIFY, {0}, {0}, &Crypto_JobPrimitiveInfo_SecLevel1_MacVerify, {0}, 0u, 0u, JOBPRIO_SECLEVEL1_MACVERIFY },
		{ JOBID_SECLEVEL3_MACGENERATE, {0}, {0}, &Crypto_JobPrimitiveInfo_SecLevel3_MacGenerate, {0}, 0u, 0u, JOBPRIO_SECLEVEL3_MACGENERATE },
		{ JOBID_SECLEVEL3_MACVERIFY, {0}, {0}, &Crypto_JobPrimitiveInfo_SecLevel3_MacVerify, {0}, 0u, 0u, JOBPRIO_SECLEVEL3_MACVERIFY },
		{ JOBID_SECLEVEL5_MACGENERATE, {0}, {0}, &Crypto_JobPrimitiveInfo_SecLevel5_MacGenerate, {0}, 0u, 0u, JOBPRIO_SECLEVEL5_MACGENERATE },
		{ JOBID_SECLEVEL5_MACVERIFY, {0}, {0}, &Crypto_JobPrimitiveInfo_SecLevel5_MacVerify, {0}, 0u, 0u, JOBPRIO_SECLEVEL5_MACVERIFY },
		{ JOBID_SIGNATUREGENERATE, {0}, {0}, &Crypto_JobPrimitiveInfo_SignatureGenerate, {0}, 0u, 0u, JOBPRIO_SIGNATUREGENERATE },
		{ JOBID_SIGNATUREVERIFY, {0}, {0}, &Crypto_JobPrimitiveInfo_SignatureVerify, {0}, 0u, 0u, JOBPRIO_SIGNATUREVERIFY }
	}
};
