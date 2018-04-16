#include "RC4HMACMD5.h"

int main(void) {
	unsigned char* key = StringToKey("61D61194FF2A9CDACF5B63083A16F8D1");

	unsigned char* cipher = "\x07\x9e\x4e\xdc\x6c\x4c\x45\x65\x02\x2c\x76\x12\x3b\xdd\xdd\xdf" \
		"\xf2\xb9\x78\x0f\xa3\x96\xfd\x98\x3c\xab\xf1\x8a\xf9\x1b\x76\xed" \
		"\x9a\x0e\x1e\xc7\x6c\x87\x8c\x5f\x8b\xf1\x17\x04\xfd\x17\x03\xb0" \
		"\xe9\x2d\x97\xc6";
	struct EDATA edata = byte_array_to_EDATA(cipher);

	unsigned char* result = decrypt(key, 1, 0x01000000, &edata);
	printf("%s\n", result);

	system("pause");
	return 0;
}