
// The following ifdef block is the standard way of creating macros which make exporting 
// from a DLL simpler. All files within this DLL are compiled with the CRYPTLIB_EXPORTS
// symbol defined on the command line. this symbol should not be defined on any project
// that uses this DLL. This way any other project whose source files include this file see 
// CRYPTLIB_API functions as being imported from a DLL, wheras this DLL sees symbols
// defined with this macro as being exported.
#ifdef CRYPTLIB_EXPORTS
#define CRYPTLIB_API __declspec(dllexport)
#else
#define CRYPTLIB_API __declspec(dllimport)
#endif

//CRYPTLIB_API bool					InitCryptLib();
CRYPTLIB_API bool						GenerateRSAKey();
CRYPTLIB_API bool						ImportRSAKey(unsigned char*, unsigned long);
CRYPTLIB_API unsigned long	ExportRSAKey(unsigned char*, unsigned long, bool);
CRYPTLIB_API unsigned long	EncodeRSAPacket(unsigned char*, unsigned long, unsigned char*, unsigned long);
CRYPTLIB_API unsigned long	DecodeRSAPacket(unsigned char*, unsigned long, unsigned char*, unsigned long);
CRYPTLIB_API void						EncodeMythicRC4Packet(unsigned char*, unsigned char*, bool);
CRYPTLIB_API void						DecodeMythicRC4Packet(unsigned char*, unsigned char*);