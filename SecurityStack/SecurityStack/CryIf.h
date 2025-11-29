#ifndef CRYIF_H
#define CRYIF_H

/*CryIf.h*/

#include "Crypto_GeneralTypes.h"
#include "Std_Types.h"
#include "Rte_Csm_Type.h"
#include "CryIf_Cfg.h"

/*[SWS_CryIf_91000] Definition of API function CryIf_Init*/

void CryIf_Init(
	const CryIf_ConfigType* configPtr
);


/*[SWS_CryIf_91003] Definition of API function CryIf_ProcessJob*/
Std_ReturnType CryIf_ProcessJob(
	uint32 channelId,
	Crypto_JobType* job
);




#endif
