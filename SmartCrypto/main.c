#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crypto.h"

int main(int argc, char *argv[])
{
	int ret,i;
	unsigned char input[256];
	unsigned char output[256];
	unsigned char output2[256];
	memset(input,0,256);
	memset(output,0,256);
	memset(output2,0x41,256);
	if(argc < 2)
	{
		puts("Not enough arguments!!!");
		exit(-1);
	}
	if(!strcmp(argv[1], "generateServerHello"))
	{
		if(argc < 4)
		{
			puts("Not enough arguments for generateServerHello!!!");
			puts("Usage: generateServerHello userId pin");
			exit(-1);
		}
		generateServerHello((unsigned char*)argv[2],(unsigned char*) argv[3], output);
	}
	if(!strcmp(argv[1], "parseClientHello"))
	{
		if(argc < 5)
		{
			puts("Not enough arguments for parseClientHello!!!");
			puts("Usage: parseClientHello clientHello hash aes_key userId");
			exit(-1);
		}
		parseClientHello(argv[2], argv[3], argv[4], argv[5]);
	}

	puts("");
	return 0;
}
