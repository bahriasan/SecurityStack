
#include "CryptoDriver.h"

static fn job_Redirection[1][23] =
{
	{NULL, &MacGenerate, &MacVerify, NULL, NULL, NULL, NULL, &Signature_Generate, &Signature_Verify, NULL, NULL, &Random_Generate, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL}//Object_0 
};

void Crypto_Init(
	const Crypto_ConfigType* configPtr
)
{ 
	//Not Used
}


Std_ReturnType Crypto_ProcessJob(
	uint32 objectId,
	Crypto_JobType* job
)
{
	uint8* key = NULL;
	uint32 keysize = CryptoDriver_config.CryptoKeys[job->cryptoKeyId].CryptoKeyTypeRef->CryptoKeyElementRef->CryptoKeyElementSize;
	uint32 keyId = CryptoDriver_config.CryptoKeys[job->cryptoKeyId].CryptoKeyId;

	switch (keyId)
	{
		case CRYPTO_KEY_MAC_SECLEVEL1:
		case CRYPTO_KEY_MAC_SECLEVEL3:
		case CRYPTO_KEY_MAC_SECLEVEL5:
			key = CryptoDriver_config.CryptoKeys[job->cryptoKeyId].CryptoKeyNvBlockRef->CryptoNvBlockDescriptorRef->AES128KEY;
			break;
		case CRYPTO_KEY_RSA2048PRIVATE:
			key = CryptoDriver_config.CryptoKeys[job->cryptoKeyId].CryptoKeyNvBlockRef->CryptoNvBlockDescriptorRef->RSA2048PRIVKEY;
			break;
		case CRYPTO_KEY_RSA2048PUBLIC:
			key = CryptoDriver_config.CryptoKeys[job->cryptoKeyId].CryptoKeyNvBlockRef->CryptoNvBlockDescriptorRef->RSA2048PUBKEY;
			break;
		default:
			break;
		//Rest TBD
	}
	
	return job_Redirection[objectId][job->jobPrimitiveInfoRef->primitiveInfo->service](job, key, keysize);
}