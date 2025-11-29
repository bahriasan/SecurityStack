# SecurityStack

Implements and Enables using Security Services(SecurityAccess and Authentication) by CSM/CryIf/CryptoDriver AUTOSAR Modules and OpenSSL as Crypto Driver
SecurityAccess: Has 3 security Levels, SecurityLevel-1/3/5. All are secured with AES128 symmetric crypto. Access is enabled with Challenge Response
Authentication: Provides RSA2048 Challenge-Response Asymmetric Cryptography. Signature is 256 Byte long.

Sample Cases:
SecAccess-1:
SecurityStack 0x02 0x27 0x01
SecurityStack 0x02 0x31 0x01
SecurityStack 0x10 0x12 0x27 0x02 MAC

SecAccess-3:
SecurityStack 0x02 0x27 0x03
SecurityStack 0x02 0x31 0x03
SecurityStack 0x10 0x12 0x27 0x04 MAC

SecAccess-5:
SecurityStack 0x02 0x27 0x05
SecurityStack 0x02 0x31 0x05
SecurityStack 0x10 0x12 0x27 0x06 MAC

Authentication:
SecurityStack 0x02 0x29 0x05
SecurityStack 0x02 0x31 0x06
SecurityStack 0x11 0x02 0x29 0x06 SIGNATURE



TO DO:

1. AUTOSAR Requirement Tracking List will be added for Csm/CryIf/CryptoDriver
2. KeyManagement Services to be added
