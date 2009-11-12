// CryptLib.cpp : Defines the entry point for the DLL application.
//

#include "stdafx.h"
#include "CryptLib.h"

//#define MP_8BIT
#include <mycrypt.h>

////////////////////////////////////////////////////////////////////////////////////////////////////////////
//Global variables used through the DLL
////////////////////////////////////////////////////////////////////////////////////////////////////////////

#define			MAX_EXPORTEDKEY_LENGTH 1024
#define			RSA_KEY_BITS		   1536
//#define			RSA_KEY_BITS		   257

prng_state		prng; 
rsa_key			rsaKey;

////////////////////////////////////////////////////////////////////////////////////////////////////////////
bool InitCryptLib();

BOOL APIENTRY DllMain( HANDLE hModule, 
                       DWORD  ul_reason_for_call, 
                       LPVOID lpReserved
					 )
{
    switch (ul_reason_for_call)
	{
		case DLL_PROCESS_ATTACH: 
			if(!InitCryptLib()) return FALSE; 
		case DLL_THREAD_ATTACH: break;
		case DLL_THREAD_DETACH: break;
		case DLL_PROCESS_DETACH: break;
    }
    return TRUE;
}


////////////////////////////////////////////////////////////////////////////////////////////////////////////

bool InitCryptLib()
{
	if(register_prng(&sprng_desc) ==-1)
		return false;

	return true;
}

CRYPTLIB_API bool GenerateRSAKey()
{
	FILE *fp;
	if((fp = fopen("rsakey.dat","rb"))!=NULL)
	{
		fseek(fp,0L,SEEK_END);
		unsigned long exportedKeyLength = ftell(fp);
		rewind(fp);
		unsigned char *exportedKey = new unsigned char[exportedKeyLength];
		if(fread(exportedKey,exportedKeyLength,1,fp) > 0)
		{
			if(rsa_import(exportedKey,exportedKeyLength,&rsaKey) == CRYPT_OK)
			{
				delete[] exportedKey;
				return true;
			}
			delete[] exportedKey;
		}
	}

	//printf("No valid RSA key found, generating!\n");

	int error;
	if((error=rsa_make_key(&prng, find_prng( "sprng"), RSA_KEY_BITS/8, 65537, &rsaKey)) == CRYPT_OK)
	{
		unsigned long exportedKeyLength = RSA_KEY_BITS;
		unsigned char *exportedKey = new unsigned char[exportedKeyLength];
		if((error=rsa_export(exportedKey, &exportedKeyLength, PK_PRIVATE_OPTIMIZED, &rsaKey)) != CRYPT_OK) 
		{
			printf("rsa_export() error: %s\n", error_to_string(error));
			delete[] exportedKey;
			return false;
		}
		FILE *fp;
		if((fp = fopen("rsakey.dat","wb"))!=NULL)
		{
			fwrite(exportedKey,exportedKeyLength,1,fp);
			fclose(fp);
		}
		delete[] exportedKey;
		return true;
	}
	else
	{
		printf("rsa_make_key() error: %s\n", error_to_string(error));
	}
	return false;
}


CRYPTLIB_API bool ImportRSAKey(unsigned char *externalKey, unsigned long keyLen)
{
	if(rsa_import(externalKey,keyLen,&rsaKey) != CRYPT_OK)
		return false;
	return true;
}

CRYPTLIB_API unsigned long ExportRSAKey(unsigned char *keyBuffer, unsigned long keyBufferSize, bool withPrivate)
{
	if(rsa_export(keyBuffer, &keyBufferSize, withPrivate?PK_PRIVATE_OPTIMIZED:PK_PUBLIC, &rsaKey) != CRYPT_OK) 
		return 0;
	return keyBufferSize;
}

#define BLOCKLEN RSA_KEY_BITS / 8 / 3 - 1

CRYPTLIB_API unsigned long EncodeMythicRSAPacket(unsigned char *inMessage, unsigned long inMessageLen, unsigned char *outMessage, unsigned long outMessageLen)
{
	//printf("Encrypting: inLen=%ul outLen=%ul\n",inMessageLen, outMessageLen);
	if(inMessage==NULL) return 0;
	if(inMessageLen==0) return 0;
	if(outMessage==NULL) return 0;
	if(outMessageLen==0) return 0;

	unsigned long curInPtr = 2; //Input starts at byte 3
	unsigned long curOutPtr = 2; //Output starts at byte 3 too

	unsigned long blockLen = BLOCKLEN;
	unsigned char paddedBlock[200];

	int error = 0;
	while(curInPtr < inMessageLen)
	{
		blockLen = BLOCKLEN;
		if(curInPtr+blockLen > inMessageLen)
			blockLen = inMessageLen - curInPtr;
		
		//Pad a block of data
		unsigned long paddedBlockLen = 200;
		printf("Padding data... blockLen=%d curInPtr=%d\n",blockLen,curInPtr);
		if((error=rsa_pad(&inMessage[curInPtr], blockLen, paddedBlock, &paddedBlockLen, find_prng("sprng"), &prng)) != CRYPT_OK)
		{
			printf("rsa_pad() error: %s\n", error_to_string(error)); 
			return 0;
		}
		curInPtr += blockLen;
		printf("Padding finished... paddedBlockLen=%d curInPtr=%d\n",paddedBlockLen,curInPtr); 

		unsigned long cryptedBlockLen = outMessageLen - curOutPtr - 2;
		printf("Crypting block... cryptedBlockLen=%d curOutPtr=%d\n",cryptedBlockLen,curOutPtr);
		if((error=rsa_exptmod(paddedBlock,paddedBlockLen,&outMessage[curOutPtr+2],&cryptedBlockLen,PK_PUBLIC,&rsaKey))!=CRYPT_OK)
		{
			printf("rsa_exptmod() error: %s\n", error_to_string(error)); 
			return 0;
		}
		outMessage[curOutPtr] = (unsigned char)((cryptedBlockLen>>8)&0xFF);
		outMessage[curOutPtr+1] = (unsigned char)(cryptedBlockLen&0xFF);
		curOutPtr += cryptedBlockLen + 2;
		printf("Crypting finished.. cryptedBlockLen=%d curOutPtr=%d\n",cryptedBlockLen,curOutPtr);
	}
	outMessage[0]=(unsigned char)(curOutPtr>>8);
	outMessage[1]=(unsigned char)(curOutPtr&0x0FF);
	return curOutPtr;
}

/*
void Dump(mp_int *tmp)
{
	for (int i=0; i<tmp->used; i+=16) {				
		char hex[500]="";
		char text[500]="";

		sprintf(text,"%04X: ",i);
		lstrcat(hex,text);
		
		for(int j=0; j<16; j++) 
		{
			if (j + i < tmp->used) 
			{
				sprintf(text," %02X",tmp->dp[j+i]);
				lstrcat(hex,text);
			}
			else
			{
				break;
			}
		}
		printf("%s\n",hex);
	}
}
*/

CRYPTLIB_API unsigned long DecodeMythicRSAPacket(unsigned char *inMessage, unsigned long inMessageLen, unsigned char *outMessage, unsigned long outMessageLen)
{
	DWORD tick = GetTickCount();
	printf("Dencrypting: inLen=%ul outLen=%ul\n",inMessageLen, outMessageLen);
	if(inMessage==NULL) return 0;
	if(inMessageLen==0) return 0;
	if(outMessage==NULL) return 0;
	if(outMessageLen==0) return 0;

	unsigned long curInPtr = 2;
	unsigned long curOutPtr = 2;

	unsigned char decryptedBlock[500];
	unsigned char depaddedBlock[500];

	while(curInPtr < inMessageLen)
	{
		//printf("Reading blockLength... curInPtr=%d\n",curInPtr);
		if(curInPtr+2 > inMessageLen)
			return 0;
		unsigned long curBlockLen = (inMessage[curInPtr]<<8)+inMessage[curInPtr+1];
		curInPtr+=2;
		//printf("BlockLength... curInPtr=%d blockLen=%d\n",curInPtr,curBlockLen);
		if(curBlockLen>0)
		{
			unsigned long decryptedBlockLen = 500;
			/*
			mp_int tmp;
			if(mp_init_multi(&tmp, NULL) != MP_OKAY)
				return 0;
			if(mp_read_unsigned_bin(&tmp, &inMessage[curInPtr], (int)curBlockLen) != MP_OKAY)
				return 0;
 
			Dump(&tmp);
			*/
			//printf("Decrypting block...\n");
			if(rsa_exptmod(&inMessage[curInPtr],curBlockLen,decryptedBlock,&decryptedBlockLen,PK_PRIVATE,&rsaKey)!=CRYPT_OK)
				return 0;
			//printf("Decrypting finished... decryptedBlockLen=%d\n",decryptedBlockLen);

			unsigned long depaddedBlockLen = 500;
			
			//printf("Depadding block ... depaddedBlockLen=%d\n",depaddedBlockLen);
			if(rsa_depad(decryptedBlock, decryptedBlockLen, depaddedBlock, &depaddedBlockLen) != CRYPT_OK)
				return 0;
			//printf("Depadding finished ... curOutPtr=%d depaddedBlockLen=%d\n",curOutPtr, depaddedBlockLen);
			if(curOutPtr+depaddedBlockLen > outMessageLen)
				return 0;

			memcpy(&outMessage[curOutPtr],depaddedBlock,depaddedBlockLen);
			curOutPtr+=depaddedBlockLen;
			//printf("Decrypting block finished ... curOutPtr=%d\n",curOutPtr);
		}
		curInPtr+=curBlockLen;
	}
	outMessage[0]=(unsigned char)(curOutPtr>>8);
	outMessage[1]=(unsigned char)(curOutPtr&0x0FF);
	tick = GetTickCount()-tick;
	printf("Ticks=%d",tick);
	return curOutPtr;
}

CRYPTLIB_API void EncodeMythicRC4Packet(unsigned char *buf, unsigned char *sbox, bool udpPacket)
{
	if(buf==NULL) return;
	if(sbox==NULL) return;
	unsigned __int8 tmpsbox[256];
	CopyMemory(tmpsbox,sbox,256);
	unsigned __int8 i = 0;
	unsigned __int8 j = 0;
	unsigned __int16 len = (buf[0]<<8)|buf[1];
	len+=1; // +1 byte for packet code
	if(udpPacket)
		len+=2; //+2 byte for packet-count
	
	int k;
	for(k=(len/2)+2;k<len+2;k++)
	{
		i++;
		unsigned __int8 tmp = tmpsbox[i];
		j += tmp;
		tmpsbox[i]=tmpsbox[j];
		tmpsbox[j]=tmp;
		unsigned __int8 xorKey = tmpsbox[(unsigned __int8)(tmpsbox[i]+tmpsbox[j])];
		j+=buf[k];
		buf[k]^= xorKey;
	}
	for(k=2;k<(len/2)+2;k++)
	{
		i++;
		unsigned __int8 tmp = tmpsbox[i];
		j += tmp;
		tmpsbox[i]=tmpsbox[j];
		tmpsbox[j]=tmp;
		unsigned __int8 xorKey = tmpsbox[(unsigned __int8)(tmpsbox[i]+tmpsbox[j])];
		j+=buf[k];
		buf[k]^= xorKey;
	}
}

CRYPTLIB_API void DecodeMythicRC4Packet(unsigned char *buf, unsigned char *sbox)
{
	if(buf==NULL) return;
	if(sbox==NULL) return;
	unsigned __int8 tmpsbox[256];
	CopyMemory(tmpsbox,sbox,256);
	unsigned __int8 i = 0;
	unsigned __int8 j = 0;
	unsigned __int16 len = (buf[0]<<8)|buf[1] + 10; //+10 byte for packet#,session,param,code,checksum
	int k;
	for(k=(len/2)+2;k<len+2;k++)
	{
		i++;
		unsigned __int8 tmp = tmpsbox[i];
		j += tmp;
		tmpsbox[i]=tmpsbox[j];
		tmpsbox[j]=tmp;
		unsigned __int8 xorKey = tmpsbox[(unsigned __int8)(tmpsbox[i]+tmpsbox[j])];
		buf[k]^= xorKey;
		j+=buf[k];
	}
	for(k=2;k<(len/2)+2;k++)
	{
		i++;
		unsigned __int8 tmp = tmpsbox[i];
		j += tmp;
		tmpsbox[i]=tmpsbox[j];
		tmpsbox[j]=tmp;
		unsigned __int8 xorKey = tmpsbox[(unsigned __int8)(tmpsbox[i]+tmpsbox[j])];
		buf[k]^= xorKey;
		j+=buf[k];
	}
}
