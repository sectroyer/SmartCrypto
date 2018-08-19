int generateServerHello(unsigned char *userId, unsigned char *pin, unsigned char *pOut);
int parseClientHello(char *clientHello, char *hashText, char *aesKeyText, char *userId);
