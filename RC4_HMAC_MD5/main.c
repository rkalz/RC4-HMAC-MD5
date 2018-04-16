#include "RC4HMACMD5.h"

int main(void) {
	unsigned char* key;
	StringToKey("foo", &key);

	struct EDATA edata = encrypt(key, 1, 0x01000000, "bar");
	int result =         decrypt(key, 1, 0x01000000, &edata);
	if (result) printf("%s\n", edata.Data);

	unsigned char* bytes = EDATA_to_byte_array(edata);
	struct EDATA match = byte_array_to_EDATA(bytes);

	system("pause");
	return 0;
}