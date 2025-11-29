
#include "Csm.h"


/*[SWS_Csm_00646] Definition of API function Csm_Init*/
void Csm_Init(
	const Csm_ConfigType* configPtr
)
{
	//[SWS_Crypto_00019]
	//All Jobs should be in Idle State
	for (int i = 0; i != MAX_JOBID; ++i)
	{
		rnt.Jobs[i].jobState = CRYPTO_JOBSTATE_IDLE;
	}

}


/*[SWS_Csm_01543] Definition of API function Csm_RandomGenerate*/
Std_ReturnType Csm_RandomGenerate(
	uint32 jobId,
	uint8* resultPtr,
	uint32* resultLengthPtr
)
{
	//Check if JobId is configured for specified service
	if ( (CRYPTO_ALGOFAM_NOT_SET == Csm_config.CsmJobs[jobId].CsmJobPrimitiveRef->CsmRandomGenerateAlgorithmFamily) ||
		 (CRYPTO_ALGOMODE_NOT_SET == Csm_config.CsmJobs[jobId].CsmJobPrimitiveRef->CsmRandomGenerateAlgorithmMode) )
	{
		return E_NOT_OK;
	}

	rnt.Jobs[jobId].jobId = jobId;

	//Configure jobPrimitiveInputOutput
	rnt.Jobs[jobId].jobPrimitiveInputOutput.outputPtr = resultPtr;
	rnt.Jobs[jobId].jobPrimitiveInputOutput.outputLengthPtr = resultLengthPtr;
	rnt.Jobs[jobId].jobPrimitiveInputOutput.mode = CRYPTO_NO_MODE;
	rnt.Jobs[jobId].jobPrimitiveInputOutput.cryIfKeyId = 0u;	// No Keys needed for RandomGenerate but we send default key to use common interface

	//Call Relevant CryIf Function
	return CryIf_ProcessJob(Csm_config.CsmJobs[jobId].CsmJobQueueRef->CsmChannelRef->CryIfChannelId, &rnt.Jobs[jobId]);
}


/*[SWS_Csm_00982] Definition of API function Csm_MacGenerate*/
Std_ReturnType Csm_MacGenerate(
	uint32 jobId,
	Crypto_OperationModeType mode,
	const uint8* dataPtr,
	uint32 dataLength,
	uint8* macPtr,
	uint32* macLengthPtr
)
{ 
	//Only Start Modes are applicable when idle
	//[SWS_Crypto_00118]
	if (CRYPTO_JOBSTATE_IDLE == rnt.Jobs[jobId].jobState && IS_NOT_START_MODE(mode))
	{
		return E_NOT_OK;
	}

	//Finish is received while update was expected
	//[SWS_Csm_01045]
	if ((CRYPTO_OPERATIONMODE_FINISH == mode) &&
		(CRYPTO_JOBSTATE_ACTIVE == rnt.Jobs[jobId].jobState && CRYPTO_OPERATIONMODE_START == rnt.Jobs[jobId].jobPrimitiveInputOutput.mode))
	{
		return E_NOT_OK;
	}

	//Check if JobId is configured for specified service
	if ( (CRYPTO_ALGOFAM_NOT_SET == Csm_config.CsmJobs[jobId].CsmJobPrimitiveRef->CsmMacGenerateAlgorithmFamily) ||
		(CRYPTO_ALGOMODE_NOT_SET == Csm_config.CsmJobs[jobId].CsmJobPrimitiveRef->CsmMacGenerateAlgorithmMode) )
	{
		return E_NOT_OK;
	}

	rnt.Jobs[jobId].jobId = jobId;
	
	//Configure jobPrimitiveInputOutput
	rnt.Jobs[jobId].jobPrimitiveInputOutput.inputPtr = dataPtr;
	rnt.Jobs[jobId].jobPrimitiveInputOutput.inputLength = dataLength;
	rnt.Jobs[jobId].jobPrimitiveInputOutput.outputPtr = macPtr;
	rnt.Jobs[jobId].jobPrimitiveInputOutput.outputLengthPtr = macLengthPtr;
	rnt.Jobs[jobId].jobPrimitiveInputOutput.mode = mode;
	rnt.Jobs[jobId].jobPrimitiveInputOutput.cryIfKeyId = Csm_config.CsmJobs[jobId].CsmJobKeyRef->CsmKeyRef->CryIfKeyId;

	//Call Relevant CryIf Function
	return CryIf_ProcessJob(Csm_config.CsmJobs[jobId].CsmJobQueueRef->CsmChannelRef->CryIfChannelId, &rnt.Jobs[jobId]);
}


/*[SWS_Csm_01050] Definition of API function Csm_MacVerify*/
Std_ReturnType Csm_MacVerify(
	uint32 jobId,
	Crypto_OperationModeType mode,
	const uint8* dataPtr,
	uint32 dataLength,
	const uint8* macPtr,
	uint32 macLength,
	Crypto_VerifyResultType* verifyPtr
)
{
	//Only Start Modes are applicable when idle
	//[SWS_Crypto_00118]
	if (CRYPTO_JOBSTATE_IDLE == rnt.Jobs[jobId].jobState && IS_NOT_START_MODE(mode))
	{
		return E_NOT_OK;
	}

	//Finish is received while update was expected
	//[SWS_Csm_01045]
	if ((CRYPTO_OPERATIONMODE_FINISH == mode) &&
		(CRYPTO_JOBSTATE_ACTIVE == rnt.Jobs[jobId].jobState && CRYPTO_OPERATIONMODE_START == rnt.Jobs[jobId].jobPrimitiveInputOutput.mode))
	{
		return E_NOT_OK;
	}

	//Check if JobId is configured for specified service
	if ((CRYPTO_ALGOFAM_NOT_SET == Csm_config.CsmJobs[jobId].CsmJobPrimitiveRef->CsmMacVerifyAlgorithmFamily) ||
		(CRYPTO_ALGOMODE_NOT_SET == Csm_config.CsmJobs[jobId].CsmJobPrimitiveRef->CsmMacVerifyAlgorithmMode))
	{
		return E_NOT_OK;
	}

	rnt.Jobs[jobId].jobId = jobId;

	//Configure jobPrimitiveInputOutput
	rnt.Jobs[jobId].jobPrimitiveInputOutput.inputPtr = dataPtr;
	rnt.Jobs[jobId].jobPrimitiveInputOutput.inputLength = dataLength;
	rnt.Jobs[jobId].jobPrimitiveInputOutput.secondaryInputPtr = macPtr;
	rnt.Jobs[jobId].jobPrimitiveInputOutput.secondaryInputLength = macLength;
	rnt.Jobs[jobId].jobPrimitiveInputOutput.verifyPtr = verifyPtr;
	rnt.Jobs[jobId].jobPrimitiveInputOutput.mode = mode;
	rnt.Jobs[jobId].jobPrimitiveInputOutput.cryIfKeyId = Csm_config.CsmJobs[jobId].CsmJobKeyRef->CsmKeyRef->CryIfKeyId;

	//Call Relevant CryIf Function
	return CryIf_ProcessJob(Csm_config.CsmJobs[jobId].CsmJobQueueRef->CsmChannelRef->CryIfChannelId, &rnt.Jobs[jobId]);
}


/*[SWS_Csm_00980] Definition of API function Csm_Hash*/
Std_ReturnType Csm_Hash(
	uint32 jobId,
	Crypto_OperationModeType mode,
	const uint8* dataPtr,
	uint32 dataLength,
	uint8* resultPtr,
	uint32* resultLengthPtr
)
{
	//Call Relevant CryIf Function
}


/*[SWS_Csm_00992] Definition of API function Csm_SignatureGenerate*/
Std_ReturnType Csm_SignatureGenerate(
	uint32 jobId,
	Crypto_OperationModeType mode,
	const uint8* dataPtr,
	uint32 dataLength,
	uint8* signaturePtr,
	uint32* signatureLengthPtr
)
{	
	//Only Start Modes are applicable when idle
	//[SWS_Crypto_00118]
	if (CRYPTO_JOBSTATE_IDLE == rnt.Jobs[jobId].jobState && IS_NOT_START_MODE(mode))
	{
		return E_NOT_OK;
	}

	//Finish is received while update was expected
	//[SWS_Csm_01045]
	if ((CRYPTO_OPERATIONMODE_FINISH == mode) &&
		(CRYPTO_JOBSTATE_ACTIVE == rnt.Jobs[jobId].jobState && CRYPTO_OPERATIONMODE_START == rnt.Jobs[jobId].jobPrimitiveInputOutput.mode))
	{
		return E_NOT_OK;
	}

	//Check if JobId is configured for specified service
	if ((CRYPTO_ALGOFAM_NOT_SET == Csm_config.CsmJobs[jobId].CsmJobPrimitiveRef->CsmSignatureGenerateAlgorithmFamily) ||
		(CRYPTO_ALGOMODE_NOT_SET == Csm_config.CsmJobs[jobId].CsmJobPrimitiveRef->CsmSignatureGenerateAlgorithmMode))
	{
		return E_NOT_OK;
	}

	rnt.Jobs[jobId].jobId = jobId;

	//Configure jobPrimitiveInputOutput
	rnt.Jobs[jobId].jobPrimitiveInputOutput.inputPtr = dataPtr;
	rnt.Jobs[jobId].jobPrimitiveInputOutput.inputLength = dataLength;
	rnt.Jobs[jobId].jobPrimitiveInputOutput.outputPtr = signaturePtr;
	rnt.Jobs[jobId].jobPrimitiveInputOutput.outputLengthPtr = signatureLengthPtr;
	rnt.Jobs[jobId].jobPrimitiveInputOutput.mode = mode;
	rnt.Jobs[jobId].jobPrimitiveInputOutput.cryIfKeyId = Csm_config.CsmJobs[jobId].CsmJobKeyRef->CsmKeyRef->CryIfKeyId;

	//Call Relevant CryIf Function
	return CryIf_ProcessJob(Csm_config.CsmJobs[jobId].CsmJobQueueRef->CsmChannelRef->CryIfChannelId, &rnt.Jobs[jobId]);
}


/*[SWS_Csm_00996] Definition of API function Csm_SignatureVerify*/
Std_ReturnType Csm_SignatureVerify(
	uint32 jobId,
	Crypto_OperationModeType mode,
	const uint8* dataPtr,
	uint32 dataLength,
	const uint8* signaturePtr,
	uint32 signatureLength,
	Crypto_VerifyResultType* verifyPtr
)
{
	//Only Start Modes are applicable when idle
	//[SWS_Crypto_00118]
	if (CRYPTO_JOBSTATE_IDLE == rnt.Jobs[jobId].jobState && IS_NOT_START_MODE(mode))
	{
		return E_NOT_OK;
	}

	//Finish is received while update was expected
	//[SWS_Csm_01045]
	if ((CRYPTO_OPERATIONMODE_FINISH == mode) &&
		(CRYPTO_JOBSTATE_ACTIVE == rnt.Jobs[jobId].jobState && CRYPTO_OPERATIONMODE_START == rnt.Jobs[jobId].jobPrimitiveInputOutput.mode))
	{
		return E_NOT_OK;
	}

	//Check if JobId is configured for specified service
	if ((CRYPTO_ALGOFAM_NOT_SET == Csm_config.CsmJobs[jobId].CsmJobPrimitiveRef->CsmSignatureVerifyAlgorithmFamily) ||
		(CRYPTO_ALGOMODE_NOT_SET == Csm_config.CsmJobs[jobId].CsmJobPrimitiveRef->CsmSignatureVerifyAlgorithmMode))
	{
		return E_NOT_OK;
	}

	rnt.Jobs[jobId].jobId = jobId;

	//Configure jobPrimitiveInputOutput
	rnt.Jobs[jobId].jobPrimitiveInputOutput.inputPtr = dataPtr;
	rnt.Jobs[jobId].jobPrimitiveInputOutput.inputLength = dataLength;
	rnt.Jobs[jobId].jobPrimitiveInputOutput.secondaryInputPtr = signaturePtr;
	rnt.Jobs[jobId].jobPrimitiveInputOutput.secondaryInputLength = signatureLength;
	rnt.Jobs[jobId].jobPrimitiveInputOutput.verifyPtr = verifyPtr;
	rnt.Jobs[jobId].jobPrimitiveInputOutput.mode = mode;
	rnt.Jobs[jobId].jobPrimitiveInputOutput.cryIfKeyId = Csm_config.CsmJobs[jobId].CsmJobKeyRef->CsmKeyRef->CryIfKeyId;

	//Call Relevant CryIf Function
	return CryIf_ProcessJob(Csm_config.CsmJobs[jobId].CsmJobQueueRef->CsmChannelRef->CryIfChannelId, &rnt.Jobs[jobId]);
}