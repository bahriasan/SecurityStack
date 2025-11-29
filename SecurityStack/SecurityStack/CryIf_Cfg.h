#ifndef CRYIF_CFG_H
#define CRYIF_CFG_H

/*CryIf_Cfg.h*/

#include "Types.h"
#include "CryptoDriver.h"

typedef enum
{	
	CRYIF_KEY_MAC_SECLEVEL1,
	CRYIF_KEY_MAC_SECLEVEL3,
	CRYIF_KEY_MAC_SECLEVEL5,
	CRYIF_KEY_SIGNATUREGENERATE,
	CRYIF_KEY_SIGNATUREVERIFY,
	CRYIF_MAXLIMIT_KEYS
}CryIf_KeyIds;

#define CRYIF_CHANNEL_0		0x00u

/*[ECUC_CryIf_00009] Definition of EcucParamConfContainerDef CryIfGeneral*/
/*[ECUC_CryIf_00010] Definition of EcucBooleanParamDef CryIfDevErrorDetect*/
/*[ECUC_CryIf_00011] Definition of EcucBooleanParamDef CryIfVersionInfoApi*/
typedef struct CryIf_General
{
	boolean CryIfDevErrorDetect;
	boolean CryIfVersionInfoApi;
}CryIf_General;


/*[ECUC_CryIf_00002] Definition of EcucParamConfContainerDef CryIfChannel*/
/*[ECUC_CryIf_00004] Definition of EcucIntegerParamDef CryIfChannelId*/
/*[ECUC_CryIf_00005] Definition of EcucReferenceDef CryIfDriverObjectRef*/
typedef struct CryIfChannel
{
	uint32 CryIfChannelId;
	CryptoDriverObject* CryptoDriverObjectRef;
}CryIfChannel;


/*[ECUC_CryIf_00003] Definition of EcucParamConfContainerDef CryIfKey*/
/*[ECUC_CryIf_00007] Definition of EcucIntegerParamDef CryIfKeyId*/
/*[ECUC_CryIf_00008] Definition of EcucReferenceDef CryIfKeyRef*/
typedef struct CryIfKey
{
	uint32 CryIfKeyId;
	CryptoKey* CryIfKeyRef;
}CryIfKey;


typedef struct CryIf_ConfigType
{
	CryIf_General CryIf_General_;
	CryIfChannel CryIfChannels[1];
	CryIfKey CryIfKeys[5];
}CryIf_ConfigType;


extern CryIf_ConfigType CryIf_config;

#endif
