
#include "CryIf_Cfg.h"

CryIf_ConfigType CryIf_config = 
{
	{ TRUE, TRUE },
	{ { CRYIF_CHANNEL_0, &(CryptoDriver_config.CryptoDriverObjects[0]) } },
	{ { CRYIF_KEY_MAC_SECLEVEL1 , &(CryptoDriver_config.CryptoKeys[0]) },
	  { CRYIF_KEY_MAC_SECLEVEL3 , &(CryptoDriver_config.CryptoKeys[1]) },
	  { CRYIF_KEY_MAC_SECLEVEL5 , &(CryptoDriver_config.CryptoKeys[2]) },
	  { CRYIF_KEY_SIGNATUREGENERATE , &(CryptoDriver_config.CryptoKeys[3]) },
	  { CRYIF_KEY_SIGNATUREVERIFY , &(CryptoDriver_config.CryptoKeys[4]) } }
};