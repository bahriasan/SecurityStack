#ifndef CSM_CFG_H
#define CSM_CFG_H

/*Csm_Cfg.h*/

#include "Types.h"
#include "Crypto_GeneralTypes.h"
#include "CryIf.h"
#include "Ecuc.h"


void Notification_SeedGenerate(void);
void Notification_SecLevel1_MacGenerate(void);
void Notification_SecLevel1_MacVerify(void);
void Notification_SecLevel3_MacGenerate(void);
void Notification_SecLevel3_MacVerify(void);
void Notification_SecLevel5_MacGenerate(void);
void Notification_SecLevel5_MacVerify(void);
void Notification_SignatureGenerate(void);
void Notification_SignatureVerify(void);

typedef enum
{
	JOBPRIO_SEEDGENERATE,
	JOBPRIO_SECLEVEL1_MACGENERATE,
	JOBPRIO_SECLEVEL1_MACVERIFY,
	JOBPRIO_SECLEVEL3_MACGENERATE,
	JOBPRIO_SECLEVEL3_MACVERIFY,
	JOBPRIO_SECLEVEL5_MACGENERATE,
	JOBPRIO_SECLEVEL5_MACVERIFY,
	JOBPRIO_SIGNATUREGENERATE,
	JOBPRIO_SIGNATUREVERIFY,
}JobPrioritys;

typedef enum
{
	CALLBACK_ID_SEEDGENERATE, 
	CALLBACK_ID_SECLEVEL1_MACGENERATE,
	CALLBACK_ID_SECLEVEL1_MACVERIFY,
	CALLBACK_ID_SECLEVEL3_MACGENERATE,
	CALLBACK_ID_SECLEVEL3_MACVERIFY,
	CALLBACK_ID_SECLEVEL5_MACGENERATE,
	CALLBACK_ID_SECLEVEL5_MACVERIFY,
	CALLBACK_ID_SIGNATUREGENERATE,
	CALLBACK_ID_SIGNATUREVERIFY
}Callback_Ids;

typedef enum
{
	CRYPTO_USE_PORT_OPTIMIZED,
	CRYPTO_USE_FNC,
	CRYPTO_USE_PORT
}CsmJobInterfaceUsePort_t;

/****************************************************************************/
//Csm_ConfigType Definitions

typedef struct CsmGeneral
{
	boolean CsmDevErrorDetect;
	boolean CsmVersionInfoApi;
}CsmGeneral;

/****************************************************************************/


/****************************************************************************/
//Csm MainFunction Definitions

typedef struct CsmMainFunction
{
	double CsmMainFunctionPeriod;
	EcucPartition* CsmMainFunctionPartitionRef;
}CsmMainFunction;

/****************************************************************************/


/****************************************************************************/
//Csm Queue Definitions

typedef struct CsmQueue
{
	CryIfChannel* CsmChannelRef;
	uint32 CsmQueueSize;
	CsmMainFunction* CsmQueueMainFunctionRef;
}CsmQueue;

/****************************************************************************/


/****************************************************************************/
//Csm Key Definitions

typedef enum
{
	CSM_KEY_MAC_SECLEVEL1,
	CSM_KEY_MAC_SECLEVEL3,
	CSM_KEY_MAC_SECLEVEL5,
	CSM_KEY_RSA_PRIVATE,
	CSM_KEY_RSA_PUBLIC,
	CSM_MAXLIMIT_KEYS
}Csm_KeyIds;


typedef struct CsmKey
{
	uint32 CsmKeyId;
	CryIfKey* CsmKeyRef;
	boolean CsmKeyUsePort;
}CsmKey;

/****************************************************************************/


/****************************************************************************/
//CsmCallbacks Definitions

typedef void (*CsmCallFunc_t)(void);

typedef struct CsmCallback
{
	CsmCallFunc_t CsmCallbackFunc;
}CsmCallback;

/****************************************************************************/


/****************************************************************************/
//CsmInOutRedirection Definitions

typedef struct CsmInOutRedirection
{
	CsmKey* CsmInputKeyRef;
	CsmKey* CsmSecondaryInputKeyRef;
	CsmKey* CsmTertiaryInputKeyRef;
	CsmKey* CsmOutputKeyRef;
	CsmKey* CsmSecondaryOutputKeyRef;
	uint32 CsmInputKeyElementId;
	uint32 CsmSecondaryInputKeyElementId;
	uint32 CsmTertiaryInputKeyElementId;
	uint32 CsmOutputKeyElementId;
	uint32 CsmSecondaryOutputKeyElementId;
}CsmInOutRedirection;

typedef struct CsmInOutRedirections
{
	CsmInOutRedirection CsmInOutRedirection_;
}CsmInOutRedirections;

/****************************************************************************/


/****************************************************************************/
/*Csm_Primitives Definitions*/


//typedef struct CsmHashConfig
//{
//	Crypto_AlgorithmFamilyType CsmHashAlgorithmFamily;
//	Crypto_AlgorithmFamilyType CsmHashAlgorithmSecondaryFamily;
//	Crypto_AlgorithmFamilyType* CsmHashAlgorithmFamilyCustomRef;
//	Crypto_AlgorithmFamilyType* CsmHashAlgorithmSecondaryFamilyCustomRef;
//	Crypto_AlgorithmModeType CsmHashAlgorithmMode;
//	Crypto_AlgorithmModeType* CsmHashAlgorithmModeCustomRef;
//	uint32 CsmHashDataMaxLength;
//	uint32 CsmHashResultLength;
//}CsmHashConfig;
//
//typedef struct CsmHash
//{
//	CsmHashConfig CsmHashConfig_;
//}CsmHash;
//
//
//typedef struct CsmMacGenerateConfig
//{
//	Crypto_AlgorithmFamilyType CsmMacGenerateAlgorithmFamily;
//	Crypto_AlgorithmFamilyType CsmMacGenerateAlgorithmSecondaryFamily;
//	Crypto_AlgorithmFamilyType* CsmMacGenerateAlgorithmFamilyCustomRef;
//	Crypto_AlgorithmFamilyType* CsmMacGenerateAlgorithmSecondaryFamilyCustomRef;
//	Crypto_AlgorithmModeType CsmMacGenerateAlgorithmMode;
//	Crypto_AlgorithmModeType* CsmMacGenerateAlgorithmModeCustomRef;
//	uint32 CsmMacGenerateAlgorithmKeyLength;
//	uint32 CsmMacGenerateDataMaxLength;
//	uint32 CsmMacGenerateResultLength;
//}CsmMacGenerateConfig;
//
//typedef struct CsmMacGenerate
//{
//	CsmMacGenerateConfig CsmMacGenerateConfig_;
//}CsmMacGenerate;
//
//
//typedef struct CsmMacVerifyConfig
//{
//	Crypto_AlgorithmFamilyType CsmMacVerifyAlgorithmFamily;
//	Crypto_AlgorithmFamilyType CsmMacVerifyAlgorithmSecondaryFamily;
//	Crypto_AlgorithmFamilyType* CsmMacVerifyAlgorithmFamilyCustomRef;
//	Crypto_AlgorithmFamilyType* CsmMacVerifyAlgorithmSecondaryFamilyCustomRef;
//	Crypto_AlgorithmModeType CsmMacVerifyAlgorithmMode;
//	Crypto_AlgorithmModeType* CsmMacVerifyAlgorithmModeCustomRef;
//	uint32 CsmMacVerifyAlgorithmKeyLength;
//	uint32 CsmMacVerifyDataMaxLength;
//	uint32 CsmMacVerifyCompareLength;
//}CsmMacVerifyConfig;
//
//typedef struct CsmMacVerify
//{
//	CsmMacVerifyConfig CsmMacVerifyConfig_;
//}CsmMacVerify;
//
//
//typedef struct CsmRandomGenerateConfig
//{
//	Crypto_AlgorithmFamilyType CsmRandomGenerateAlgorithmFamily;
//	Crypto_AlgorithmFamilyType CsmRandomGenerateAlgorithmSecondaryFamily;
//	Crypto_AlgorithmFamilyType* CsmRandomGenerateAlgorithmFamilyCustomRef;
//	Crypto_AlgorithmFamilyType* CsmRandomGenerateAlgorithmSecondaryFamilyCustomRef;
//	Crypto_AlgorithmModeType CsmRandomGenerateAlgorithmMode;
//	Crypto_AlgorithmModeType* CsmRandomGenerateAlgorithmModeCustomRef;
//	uint32 CsmRandomGenerateResultLength;
//}CsmRandomGenerateConfig;
//
//typedef struct CsmRandomGenerate
//{
//	CsmRandomGenerateConfig CsmRandomGenerateConfig_;
//}CsmRandomGenerate;

typedef struct CsmPrimitives
{
	struct CsmMacGenerate
	{
		struct CsmMacGenerateConfig
		{
			Crypto_AlgorithmFamilyType CsmMacGenerateAlgorithmFamily;
			Crypto_AlgorithmFamilyType CsmMacGenerateAlgorithmSecondaryFamily;
			Crypto_AlgorithmFamilyType* CsmMacGenerateAlgorithmFamilyCustomRef;
			Crypto_AlgorithmFamilyType* CsmMacGenerateAlgorithmSecondaryFamilyCustomRef;
			Crypto_AlgorithmModeType CsmMacGenerateAlgorithmMode;
			Crypto_AlgorithmModeType* CsmMacGenerateAlgorithmModeCustomRef;
			uint32 CsmMacGenerateAlgorithmKeyLength;
			uint32 CsmMacGenerateDataMaxLength;
			uint32 CsmMacGenerateResultLength;
		};
	};
	struct CsmMacVerify
	{
		struct CsmMacVerifyConfig
		{
			Crypto_AlgorithmFamilyType CsmMacVerifyAlgorithmFamily;
			Crypto_AlgorithmFamilyType CsmMacVerifyAlgorithmSecondaryFamily;
			Crypto_AlgorithmFamilyType* CsmMacVerifyAlgorithmFamilyCustomRef;
			Crypto_AlgorithmFamilyType* CsmMacVerifyAlgorithmSecondaryFamilyCustomRef;
			Crypto_AlgorithmModeType CsmMacVerifyAlgorithmMode;
			Crypto_AlgorithmModeType* CsmMacVerifyAlgorithmModeCustomRef;
			uint32 CsmMacVerifyAlgorithmKeyLength;
			uint32 CsmMacVerifyDataMaxLength;
			uint32 CsmMacVerifyCompareLength;
		};
	};
	struct CsmRandomGenerate
	{
		struct CsmRandomGenerateConfig
		{
			Crypto_AlgorithmFamilyType CsmRandomGenerateAlgorithmFamily;
			Crypto_AlgorithmFamilyType CsmRandomGenerateAlgorithmSecondaryFamily;
			Crypto_AlgorithmFamilyType* CsmRandomGenerateAlgorithmFamilyCustomRef;
			Crypto_AlgorithmFamilyType* CsmRandomGenerateAlgorithmSecondaryFamilyCustomRef;
			Crypto_AlgorithmModeType CsmRandomGenerateAlgorithmMode;
			Crypto_AlgorithmModeType* CsmRandomGenerateAlgorithmModeCustomRef;
			uint32 CsmRandomGenerateResultLength;
		};
	};
	struct CsmSignatureGenerate
	{
		struct CsmSignatureGenerateConfig
		{
			Crypto_AlgorithmFamilyType CsmSignatureGenerateAlgorithmFamily;
			Crypto_AlgorithmFamilyType CsmSignatureGenerateAlgorithmSecondaryFamily;
			Crypto_AlgorithmFamilyType* CsmSignatureGenerateAlgorithmFamilyCustomRef;
			Crypto_AlgorithmFamilyType* CsmSignatureGenerateAlgorithmSecondaryFamilyCustomRef;
			Crypto_AlgorithmModeType CsmSignatureGenerateAlgorithmMode;
			Crypto_AlgorithmModeType* CsmSignatureGenerateAlgorithmModeCustomRef;
			uint32 CsmSignatureGenerateDataMaxLength;
			uint32 CsmSignatureGenerateKeyLength;
			uint32 CsmSignatureGenerateResultLength;
		};
	};
	struct CsmSignatureVerify
	{
		struct CsmSignatureVerifyConfig
		{
			Crypto_AlgorithmFamilyType CsmSignatureVerifyAlgorithmFamily;
			Crypto_AlgorithmFamilyType CsmSignatureVerifyAlgorithmSecondaryFamily;
			Crypto_AlgorithmFamilyType* CsmSignatureVerifyAlgorithmFamilyCustomRef;
			Crypto_AlgorithmFamilyType* CsmSignatureVerifyAlgorithmSecondaryFamilyCustomRef;
			Crypto_AlgorithmModeType CsmSignatureVerifyAlgorithmMode;
			Crypto_AlgorithmModeType* CsmSignatureVerifyAlgorithmModeCustomRef;
			uint32 CsmSignatureVerifyDataMaxLength;
			uint32 CsmSignatureVerifyKeyLength;
			uint32 CsmSignatureVerifyCompareLength;
		};
	};
	//Rest TBD

}CsmPrimitives;

/****************************************************************************/


/****************************************************************************/
/*Csm_Jobs Definitions*/

typedef enum
{	JOBID_SEEDGENERATE,
	JOBID_SECLEVEL1_MACGENERATE,
	JOBID_SECLEVEL1_MACVERIFY,
	JOBID_SECLEVEL3_MACGENERATE,
	JOBID_SECLEVEL3_MACVERIFY,
	JOBID_SECLEVEL5_MACGENERATE,
	JOBID_SECLEVEL5_MACVERIFY,
	JOBID_SIGNATUREGENERATE,
	JOBID_SIGNATUREVERIFY,
	MAX_JOBID
}JobIds;

typedef struct CsmJob
{
	uint32 CsmJobId;
	uint32 CsmJobPriority;
	CsmJobInterfaceUsePort_t CsmJobInterfaceUsePort;
	CsmCallback* CsmJobPrimitiveCallbackRef;
	CsmPrimitives* CsmJobPrimitiveRef;
	CsmQueue* CsmJobQueueRef;
	CsmKey* CsmJobKeyRef;
	/*CsmInOutRedirection* CsmInOutRedirectionRef;*/
	Crypto_ProcessingType Crypto_ProcessingMode;
	CsmJobInterfaceUsePort_t CsmJobServiceInterfaceContextUsePort;
}CsmJob;

/****************************************************************************/

typedef struct Csm_ConfigType
{
	CsmGeneral CsmGeneral_;
	CsmJob CsmJobs[9];
	CsmKey CsmKeys[5];
	CsmPrimitives CsmPrimitives_SecLevel1_MacGenerate;
	CsmPrimitives CsmPrimitives_SecLevel1_MacVerify;
	CsmPrimitives CsmPrimitives_SecLevel3_MacGenerate;
	CsmPrimitives CsmPrimitives_SecLevel3_MacVerify;
	CsmPrimitives CsmPrimitives_SecLevel5_MacGenerate;
	CsmPrimitives CsmPrimitives_SecLevel5_MacVerify;
	CsmPrimitives CsmPrimitives_SeedGenerate;
	CsmPrimitives CsmPrimitives_SignatureGenerate;
	CsmPrimitives CsmPrimitives_SignatureVerify;
	CsmQueue CsmQueues[1];
	CsmCallback CsmCallbacks[9];
	//CsmInOutRedirections CsmInOutRedirections_;
	CsmMainFunction CsmMainFunction_;
}Csm_ConfigType;


typedef struct rnt_cfg
{
	Crypto_JobType Jobs[MAX_JOBID];
}rnt_cfg;


extern const Csm_ConfigType Csm_config;
extern rnt_cfg rnt;

#endif
