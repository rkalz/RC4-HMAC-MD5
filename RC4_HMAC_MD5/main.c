#include "RC4_HMAC_MD5.h"

int main(void) {
	/*const int len = 37;
	const unsigned char* key = "hellothere";
	const unsigned char* encdata = encrypt(key, 1, "generalkenobi", strlen("generalkenobi"));
	int result = decrypt(key, 1, encdata, len);*/

	const int len = 52;
	const unsigned char* key = "\x22\x66\x57\xA0\x62\xEE\xA9\xD7\x13\x76\x02\x16\x81\xAE\x2A\xBA";
	unsigned char* encdata = (unsigned char*)malloc(len);
	memcpy_s(encdata, len, "\x5c\x13\x4c\x89\x52\x60\x44\xdd\xba\x3a\x0a\x37\x64\xd9\xc3\x12" \
		"\x7d\xe7\xcb\x3a\x94\x09\x6a\x5b\x72\x19\x5e\x6c\xae\x4e\x96\x04" \
		"\x2f\xfc\xbf\x26\x64\xb1\xf6\xd6\x1b\x3b\x2d\x73\x57\xfe\x32\x24" \
		"\x8f\x87\x43\xdf", len);

	int result = decrypt(key, 1, encdata, 52);

	if (result) {
		printf("Checksum: ");
		for (int i = 0; i < HMAC_MD5_LENGTH; ++i) printf("%02X ", encdata[i]);
		printf("\nConfounder: ");
		for (int i = HMAC_MD5_LENGTH; i < HMAC_MD5_LENGTH + CONFOUNDER_LENGTH; ++i) printf("%02X ", encdata[i]);
		printf("\nData: ");
		for (int i = HMAC_MD5_LENGTH + CONFOUNDER_LENGTH; i < len; ++i) printf("%c", encdata[i]);
		printf("\n");
	} else printf("Checksum failed!\n");

	system("pause");
	free(encdata);
	return 0;
}