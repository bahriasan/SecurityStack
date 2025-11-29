#ifndef UDS_H
#define UDS_H

//Includes the UDS specific definitions

/*
Sub-function Not Supported (12 hex)
Incorrect Message Length/Invalid Format (13 hex)
Request Sequence Error (24 hex)
Request Out Of Range [31 hex]
Invalid Key [0x35]
Exceeded Number Of Attempts [0x36]
Required Time Delay Not Expired [0x37]
*/
typedef enum
{
	ERROR_NO = 0x01,
	INTERR_SEEDGENERATE,
	INTERR_KEYVERIFY,
	INTERR_MACGENERATE,
	INTERR_REQUEST_CHALLENGE,
	INTERR_VERIFY_POWN,
	INTERR_SIGNGENERATE,
	GENERALREJECT = 0x10,
	NOTSUPPORTEDFUNCTION = 0x11,
	NOTSUPPORTEDSUBFUNCTION = 0x12,
	INVALIDFORMAT = 0x13,
	CONDITIONSNOTCORRECT = 0x22,
	REQUESTSEQERROR = 0x24,
	REQUESTOUTOFRANGE = 0x31,
	SECURITYACCESSDENIED = 0x33,
	INVALIDKEY = 0x35,
	EXCEEDEDNOOFATTEMPTS = 0x36,
	TIMEDELAYNOTEXPIRED = 0x37
}errorType;


typedef enum
{
	SECURITY_ACCESS = 0x27,
	AUTHENTICATION = 0x29,
	ROUTINE_CONTROL = 0x31
}UDSservice;

typedef enum
{
	REQUEST_SEED,
	VERIFY_KEY,
	MAC_GENERATE,
	REQUEST_CHALLENGE,
	VERIFY_POWN,
	SIGN_GENERATE
}UDSsubService;

typedef enum
{
	SECLEVEL_1,
	SECLEVEL_3,
	SECLEVEL_5
}secLevel;



#endif
