#ifndef CSM_H
#define CSM_H

/*Csm.h*/

#include "Std_Types.h"
#include "Rte_Csm_Type.h"
#include "Crypto_GeneralTypes.h"
#include "Csm_Cfg.h"


#define IS_START_MODE(x)		(CRYPTO_OPERATIONMODE_START & x) == CRYPTO_OPERATIONMODE_START ? 1 : 0
#define IS_NOT_START_MODE(x)	(CRYPTO_OPERATIONMODE_START & x) != CRYPTO_OPERATIONMODE_START ? 1 : 0

/*[SWS_Csm_00646] Definition of API function Csm_Init*/
void Csm_Init(
	const Csm_ConfigType* configPtr
);


/*[SWS_Csm_01543] Definition of API function Csm_RandomGenerate*/
Std_ReturnType Csm_RandomGenerate(
	uint32 jobId,
	uint8* resultPtr,
	uint32* resultLengthPtr
);


/*[SWS_Csm_00982] Definition of API function Csm_MacGenerate*/
Std_ReturnType Csm_MacGenerate(
	uint32 jobId,
	Crypto_OperationModeType mode,
	const uint8* dataPtr,
	uint32 dataLength,
	uint8* macPtr,
	uint32* macLengthPtr
);


/*[SWS_Csm_01050] Definition of API function Csm_MacVerify*/
Std_ReturnType Csm_MacVerify(
	uint32 jobId,
	Crypto_OperationModeType mode,
	const uint8* dataPtr,
	uint32 dataLength,
	const uint8* macPtr,
	uint32 macLength,
	Crypto_VerifyResultType* verifyPtr
);


/*[SWS_Csm_00992] Definition of API function Csm_SignatureGenerate*/
Std_ReturnType Csm_SignatureGenerate(
	uint32 jobId,
	Crypto_OperationModeType mode,
	const uint8* dataPtr,
	uint32 dataLength,
	uint8* signaturePtr,
	uint32* signatureLengthPtr
);

/*[SWS_Csm_00996] Definition of API function Csm_SignatureVerify*/
Std_ReturnType Csm_SignatureVerify(
	uint32 jobId,
	Crypto_OperationModeType mode,
	const uint8* dataPtr,
	uint32 dataLength,
	const uint8* signaturePtr,
	uint32 signatureLength,
	Crypto_VerifyResultType* verifyPtr
);


#endif