#ifndef RTE_CSM_TYPE_H
#define RTE_CSM_TYPE_H

/*Rte_Csm_Type.h*/

#include "Types.h"


/*[SWS_Csm_01029] Definition of ImplementationDataType Crypto_OperationModeType*/
typedef uint8 Crypto_OperationModeType;

#define CRYPTO_NO_MODE							0x01u
#define CRYPTO_OPERATIONMODE_START				(Crypto_OperationModeType)0x01u
#define CRYPTO_OPERATIONMODE_UPDATE				0x02u
#define CRYPTO_OPERATIONMODE_STREAMSTART		0x03u
#define CRYPTO_OPERATIONMODE_FINISH				0x04u
#define CRYPTO_OPERATIONMODE_SINGLECALL			0x07u
#define CRYPTO_OPERATIONMODE_SAVE_CONTEXT		0x08u
#define CRYPTO_OPERATIONMODE_RESTORE_CONTEXT	0x10u


/*[SWS_Csm_01024] Definition of ImplementationDataType Crypto_VerifyResultType*/
typedef uint8 Crypto_VerifyResultType;

#define CRYPTO_E_VER_OK			0x00u
#define CRYPTO_E_VER_NOT_OK		0x01u







#endif
