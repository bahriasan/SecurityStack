#ifndef CRYPTODRIVER_H
#define CRYPTODRIVER_H

/*CryptoDriver.h*/

#include "CryptoDriver_Cfg.h"
#include "CryptoWrapper.h"

#define CRYPTO_CHANNEL_0		0x00u

void Crypto_Init(
	const Crypto_ConfigType* configPtr
);

Std_ReturnType Crypto_ProcessJob(
	uint32 objectId,
	Crypto_JobType* job
);

typedef Std_ReturnType(*fn)(Crypto_JobType*, uint8*, size_t keyLength);





#endif
