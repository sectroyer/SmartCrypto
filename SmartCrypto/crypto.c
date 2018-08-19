#include <openssl/sha.h>
#include "keys.h"
#include <memory.h>
#include <stdio.h>
#include <stdlib.h>
#include "aes.h"
#include <openssl/bn.h>
#include <arpa/inet.h>

void bufToHex(unsigned char * buf, char *out, int len,int doBig)
{
	char tmpBuf[0x10];
	if(doBig)
		sprintf(out,"%02X",buf[0]);
	else
		sprintf(out,"%02x",buf[0]);
	for(int i=1; i< len ; i++)
	{
		if(doBig)
			sprintf(tmpBuf,"%02X",buf[i]);
		else
			sprintf(tmpBuf,"%02x",buf[i]);
		strcat(out,tmpBuf);
	}
}
unsigned char* HexToBuf(char *hex)
{
	int hexLen = strlen(hex);
	unsigned char *bytearray = malloc(hexLen+10);
	for (int i = 0; i < (hexLen / 2); i++)
	{
		sscanf(hex + 2*i, "%02x", (unsigned int*)&bytearray[i]);
		//printf("bytearray %02x\n", bytearray[i]);
	}
	return bytearray;
}
void printBuffer(char *label, unsigned char *buf, int bufSize)
{
    printf("%s: ", label);
    for(int i =0; i< bufSize; i++)
    {
        printf("%02x",buf[i]);
    }
	puts("");
}
int EncryptParameterDataWithAES(unsigned char *pIn, unsigned char *pOut)
{
	unsigned int num;
	unsigned char iv[0x10];
	for (num = 0u; num < 128u; num += 16u)
	{
		memset(iv, 0, 16);
    	AES_128_CBC_Enc(pIn + num, pOut + num, wbKey, iv, 16);
	}
	return 0;
}
int DecryptParameterDataWithAES(unsigned char *pIn, unsigned char *pOut)
{
	unsigned int num;
	unsigned char iv[0x10];
	for (num = 0u; num < 128u; num += 16u)
	{
		memset(iv, 0, 16);
    	AES_128_CBC_Dec(pIn + num, pOut + num, wbKey, iv, 16);
	}
	return 0;
}
void applySamyGOKeyTransform(unsigned char *pIn, unsigned char *pOut)
{
	AES_128_Transform(3,transKey,pIn,pOut);
}

int generateServerHello(char *userId, char *pin, unsigned char *pOut)
{
	int dataLen;
	unsigned char data[256];
	unsigned char iv[0x10];
	unsigned char hash[SHA_DIGEST_LENGTH];
	unsigned char swapped[256];
	unsigned char encrypted[256];
	char dataText[2048];
	char tmpText[1024];
	char cmd[1024];
	char hashText[256];
	FILE *fp;
	
	SHA1((unsigned char*)pin, strlen((char*)pin), hash);
	bufToHex(hash,(char*)hashText, 16,0);
	printf("AES key: %s\n",hashText);
	
	memset(iv, 0, 16);
	AES_128_CBC_Enc(publicKey, encrypted, hash, iv, 128);
	bufToHex(encrypted,(char*)hashText, 128,0);
	printf("AES encrypted: %s\n",hashText);
	EncryptParameterDataWithAES(encrypted,swapped);
	bufToHex(swapped,(char*)hashText, 128,0);
	printf("AES swapped: %s\n",hashText);

	dataLen=0;	
	memset(data,0,sizeof(data));
	data[3]=strlen(userId);
	dataLen+=4;
	strcpy((char*)data+dataLen,userId);
	dataLen+=strlen(userId);
	memcpy(data+dataLen,swapped,128);
	dataLen+=128;
	bufToHex(data,dataText, dataLen,1);
	printf("data buffer: %s\n",dataText);


	SHA1(data, dataLen, hash);
	bufToHex(hash,(char*)hashText, SHA_DIGEST_LENGTH,0);
	printf("hash: %s\n",hashText);
	printf("ServerHello: 01020000000000000000%02lX%s0000000000\n",132+strlen(userId),dataText);

	return 0;
}
#define GX_SIZE 0x80
#define USER_ID_POS 15
int parseClientHello(char *clientHello, char *hashText, char *aesKeyText, char* gUserId)
{
	unsigned char *dataBytes=HexToBuf(clientHello);
	unsigned char *hash=HexToBuf(hashText),hash2[SHA_DIGEST_LENGTH], hash3[SHA_DIGEST_LENGTH],dest_hash[SHA_DIGEST_LENGTH];
	unsigned char *aesKey=HexToBuf(aesKeyText), SKPrime[SHA_DIGEST_LENGTH+1], SKPrimeHash[SHA_DIGEST_LENGTH];
	unsigned char *dest, *userId,pEncWBGx[GX_SIZE], pEncGx[GX_SIZE], *finalBuffer;
	unsigned char iv[0x10],pGx[GX_SIZE],secretBytes[256], secretLen,thirdHashBuf[512];
	unsigned int *l,firstLen,userIdLen,thirdLen,destLen, flagPos,finalPos;
	printf("\nhash: ");
	for(int i =0; i< strlen(hashText)/2; i++)
	{
		printf("%02x",hash[i]);
	}
	printf("\nAES key: ");
	for(int i =0; i< strlen(aesKeyText)/2; i++)
	{
		printf("%02x",aesKey[i]);
	}
	l=(unsigned int*)&dataBytes[7];
	firstLen = htonl(*l);
	l=(unsigned int*)&dataBytes[11];
	userIdLen = htonl(*l);

	destLen = userIdLen + 132 + SHA_DIGEST_LENGTH;
	dest=malloc(destLen);
	thirdLen = userIdLen + 132;
	memcpy(dest,dataBytes+11,thirdLen);
	memcpy(dest+thirdLen,hash,SHA_DIGEST_LENGTH);
	
	printf("\ndest: ");
	for(int i =0; i< destLen; i++)
	{
		printf("%02x",dest[i]);
	}

	userId=malloc(userIdLen+1);
	memcpy(userId,dataBytes+USER_ID_POS,userIdLen);
	userId[userIdLen]=0;
	printf("\nuserId: %s\n",userId);

	memcpy(pEncWBGx,dataBytes+USER_ID_POS+userIdLen,GX_SIZE);
	printf("\npEncWBGx: ");
	for(int i =0; i< GX_SIZE; i++)
	{
		printf("%02x",pEncWBGx[i]);
	}

	DecryptParameterDataWithAES(pEncWBGx,pEncGx);
	
	printf("\npEncGx: ");
	for(int i =0; i< GX_SIZE; i++)
	{
		printf("%02x",pEncGx[i]);
	}

	memset(iv, 0, 16);
	AES_128_CBC_Dec(pEncGx, pGx, aesKey, iv, GX_SIZE);
	
	printf("\npGx: ");
	for(int i =0; i< GX_SIZE; i++)
	{
		printf("%02x",pGx[i]);
	}
	puts("");

    BIGNUM *bn_prime, *bn_pGx, *bn_publicKey, *bn_privateKey, *bn_secret;
    BN_CTX *ctx; /* used internally by the bignum lib */

    ctx = BN_CTX_new();
	bn_secret = BN_new();
	bn_prime = BN_bin2bn(prime,sizeof(prime),NULL);
	bn_pGx= BN_bin2bn(pGx,GX_SIZE,NULL);
	bn_publicKey = BN_bin2bn(publicKey,GX_SIZE,NULL);
	bn_privateKey = BN_bin2bn(privateKey,GX_SIZE,NULL);
	BN_mod_exp(bn_secret, bn_pGx, bn_privateKey, bn_prime,ctx);
	//printf("Secret: %s\n",BN_bn2hex(bn_secret));
	secretLen=BN_bn2bin(bn_secret,secretBytes);
	printBuffer("secret",secretBytes,secretLen);
	
	memcpy(hash2,dataBytes+USER_ID_POS+userIdLen+GX_SIZE,SHA_DIGEST_LENGTH);
	printBuffer("hash2",hash2,SHA_DIGEST_LENGTH);
	
	memcpy(thirdHashBuf, userId,strlen((char*)userId));
	memcpy(thirdHashBuf+strlen((char*)userId), secretBytes, secretLen);
	printBuffer("secret2",thirdHashBuf,secretLen+strlen((char*)userId));
	
	SHA1(thirdHashBuf,  secretLen+strlen((char*)userId), hash3);
	printBuffer("hash3",hash3,SHA_DIGEST_LENGTH);
	if(memcmp(hash2,hash3,SHA_DIGEST_LENGTH))
	{
		puts("Pin error!!!");
		return -1;
	}
	puts("Pin OK :)\n");

	flagPos = strlen((char*)userId) + USER_ID_POS + GX_SIZE + SHA_DIGEST_LENGTH;
	if(dataBytes[flagPos])
	{
		puts("First flag error!!!");
		return -1;
	}
	l=(unsigned int*)&dataBytes[flagPos+1];
	if(htonl(*l))
	{
		puts("Second flag error!!!");
		return -1;
	}
	SHA1(dest, destLen, dest_hash);
	printBuffer("dest_hash",dest_hash,SHA_DIGEST_LENGTH);
	
	finalBuffer = malloc(userIdLen+ strlen((char*)userId)+ 384);
	finalPos=0;
	strcpy((char*)&finalBuffer[finalPos],(char*)userId);
	finalPos+=strlen((char*)userId);
	strcpy((char*)&finalBuffer[finalPos],(char*)gUserId);
	finalPos+=strlen((char*)gUserId);
	memcpy(&finalBuffer[finalPos],pGx,sizeof(pGx));
	finalPos+=sizeof(pGx);
	memcpy(&finalBuffer[finalPos],publicKey,sizeof(publicKey));
	finalPos+=sizeof(publicKey);
	memcpy(&finalBuffer[finalPos],secretBytes,secretLen);
	finalPos+=secretLen;

	SHA1(finalBuffer, finalPos, SKPrime);
	SKPrime[SHA_DIGEST_LENGTH]=0;
	printBuffer("SKPrime",SKPrime,SHA_DIGEST_LENGTH);
	
	SHA1(SKPrime, SHA_DIGEST_LENGTH+1, SKPrimeHash);
	printBuffer("SKPrimeHash",SKPrimeHash,SHA_DIGEST_LENGTH);
	applySamyGOKeyTransform(SKPrimeHash,SKPrimeHash);
	printBuffer("ctx",SKPrimeHash,16);
	return 0;
}
