#include "RC4HMACMD5.h"

int main(void) {
	const unsigned char* key = "\x22\x66\x57\xA0\x62\xEE\xA9\xD7\x13\x76\x02\x16\x81\xAE\x2A\xBA";
	unsigned char* encdata = (unsigned char*)malloc(52);
	memcpy_s(encdata, 52, "\x5c\x13\x4c\x89\x52\x60\x44\xdd\xba\x3a\x0a\x37\x64\xd9\xc3\x12" \
		"\x7d\xe7\xcb\x3a\x94\x09\x6a\x5b\x72\x19\x5e\x6c\xae\x4e\x96\x04" \
		"\x2f\xfc\xbf\x26\x64\xb1\xf6\xd6\x1b\x3b\x2d\x73\x57\xfe\x32\x24" \
		"\x8f\x87\x43\xdf", 52);

	decrypt(key, 0x00000001, encdata, 52);
	
	printf("Checksum: ");
	for (int i = 0; i < HMAC_MD5_LENGTH; ++i) printf("%02X ", encdata[i]);
	printf("\nConfounder: ");
	for (int i = HMAC_MD5_LENGTH; i < HMAC_MD5_LENGTH + CONFOUNDER_LENGTH; ++i) printf("%02X ", encdata[i]);
	printf("\nData: ");
	for (int i = HMAC_MD5_LENGTH + CONFOUNDER_LENGTH; i < 52; ++i) printf("%c", encdata[i]);
	printf("\n");

	system("pause");
	free(encdata);
	return 0;
}