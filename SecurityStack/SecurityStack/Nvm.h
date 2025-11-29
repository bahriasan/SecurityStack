#ifndef NVM_H
#define NVM_H

/*Nvm.h*/

#include "Std_Types.h"

typedef struct NvMBlockDescriptor
{
	uint8 AES128KEY[16];		//128 Bit Key
	uint8 RSA2048PRIVKEY[1192];	//RSA-2048Private Key	
	uint8 RSA2048PUBKEY[288];	//RSA-2048 Public Key	
}NvMBlockDescriptor;

extern NvMBlockDescriptor NVM_Block0;
extern NvMBlockDescriptor NVM_Block1;
extern NvMBlockDescriptor NVM_Block2;
extern NvMBlockDescriptor NVM_Block3;
extern NvMBlockDescriptor NVM_Block4;

#endif
