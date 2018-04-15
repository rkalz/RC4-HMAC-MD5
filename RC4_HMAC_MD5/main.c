#include "RC4HMACMD5.h"

int main(void) {
	unsigned char* key;
	StringToKey("foo", &key);

	struct EDATA edata = encrypt(key, 1, 0x01000000, "bar");
	int result =         decrypt(key, 1, 0x01000000, &edata);
	if (result) printf("%s\n", edata.Data);

	system("pause");
	return 0;
}