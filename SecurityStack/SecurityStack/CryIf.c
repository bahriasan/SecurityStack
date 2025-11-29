
#include "CryIf.h"


/*[SWS_CryIf_91000] Definition of API function CryIf_Init*/

void CryIf_Init(
	const CryIf_ConfigType* configPtr
)
{
	//Not Used
}


/*[SWS_CryIf_91003] Definition of API function CryIf_ProcessJob*/
Std_ReturnType CryIf_ProcessJob(
	uint32 channelId,
	Crypto_JobType* job
)
{
	Crypto_ServiceInfoType serviceType;
	uint32 cryIfKeyId, cryIfTargetKeyId;
	serviceType = job->jobPrimitiveInfoRef->primitiveInfo->service;
	cryIfKeyId = job->jobPrimitiveInputOutput.cryIfKeyId;
	cryIfTargetKeyId = job->jobPrimitiveInputOutput.targetCryIfKeyId;

	/*[SWS_CryIf_00133] Set the jobPrimitiveInputOutput’s cryptoKeyId with the key ID of the corresponding crypto driver*/
	if (CRYPTO_KEYSETVALID == serviceType || CRYPTO_KEYSETINVALID == serviceType || CRYPTO_RANDOMSEED == serviceType || CRYPTO_KEYGENERATE == serviceType ||
		CRYPTO_KEYDERIVE == serviceType || CRYPTO_KEYEXCHANGECALCPUBVAL == serviceType || CRYPTO_KEYEXCHANGECALCSECRET == serviceType || CRYPTO_CUSTOM_SERVICE == serviceType)
	{
		if(CRYIF_MAXLIMIT_KEYS > cryIfKeyId && CRYIF_MAXLIMIT_KEYS > cryIfTargetKeyId)
		{
			job->cryptoKeyId = CryIf_config.CryIfKeys[cryIfKeyId].CryIfKeyRef->CryptoKeyId;
			job->targetCryptoKeyId = CryIf_config.CryIfKeys[cryIfTargetKeyId].CryIfKeyRef->CryptoKeyId;
		}
	}


	/*[SWS_CryIf_00142] Set the jobPrimitiveInfo’s cryptoKeyId with the key ID of the corresponding crypto driver*/
	if (CRYPTO_MACGENERATE == serviceType || CRYPTO_MACVERIFY == serviceType || CRYPTO_ENCRYPT == serviceType || CRYPTO_DECRYPT == serviceType ||
		CRYPTO_AEADENCRYPT == serviceType || CRYPTO_AEADDECRYPT == serviceType || CRYPTO_RANDOMGENERATE == serviceType || CRYPTO_SIGNATUREGENERATE == serviceType ||
		CRYPTO_SIGNATUREVERIFY == serviceType)
	{
		if (CRYIF_MAXLIMIT_KEYS > cryIfKeyId)
		{
			job->cryptoKeyId = CryIf_config.CryIfKeys[cryIfKeyId].CryIfKeyRef->CryptoKeyId;
		}
	}

	return Crypto_ProcessJob(CryIf_config.CryIfChannels[channelId].CryptoDriverObjectRef->CryptoDriverObjectId, job);

}