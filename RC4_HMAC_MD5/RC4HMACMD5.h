#ifndef RC4HMACMD5_H
#define RC4HMACMD5_H

#include "stdlib.h"
#include "string.h"

#include <openssl\hmac.h>
#include <openssl\md4.h>
#include <openssl\md5.h>
#include <openssl\rand.h>
#include <openssl\rc4.h>

#define HMAC_MD5_LENGTH 16

typedef unsigned char OCTET;
typedef unsigned int DWORD;
typedef struct EDATA {
	OCTET Checksum[16];
	OCTET Confounder[8];
	OCTET* Data;
} EDATA;

// Converts UTF8 to UTF16 Little Endian
// utf8: Input string, utf16le: Output string
void UTF8ToUTF16LE(const char* utf8, unsigned char** utf16le) {
	int len = strlen(utf8);
	*utf16le = (unsigned char*)calloc(2 * len, sizeof(unsigned char));
	for (int i = 0; i < 2 * len; i += 2) {
		(*utf16le)[i] = utf8[i / 2];
	}
}

// Converts UTF8 input TO UTF16LE, sets key to MD4 hash
// string: Input string, key: Output key
void StringToKey(const char* string, unsigned char** key) {
	unsigned char* unicode;
	UTF8ToUTF16LE(string, &unicode);
	*key = MD4((unsigned char*)unicode, 2 * strlen(string), NULL);
	free(unicode);
}

// Checksum used by algorithm
// K: Input key, T: Message Type (4 byte LE), data: Input data
unsigned char* Checksum(const unsigned char* K, uint32_t T, const char* data) {
	unsigned char* ksign = HMAC(EVP_md5(), K, MD4_DIGEST_LENGTH, (unsigned char*)"signaturekey", strlen("signaturekey"), NULL, NULL);
	
	unsigned char* concat = (unsigned char*)calloc(strlen(data) + 4, sizeof(unsigned char));
	strcat_s(concat, sizeof(concat), &T);
	strcat_s(concat, sizeof(concat), data);
	unsigned char* tmp = MD5(concat, strlen(data) + 4, NULL);
	free(concat);

	return HMAC(EVP_md5(), ksign, HMAC_MD5_LENGTH, tmp, strlen(data) + 4, NULL, NULL);
}


// Encryption
// K: Input Key, export: Key length > 5 bytes, T: Message Type (4 byte LE), data: Input Data
// returns an EDATA Struct
struct EDATA encrypt(const unsigned char* K, int export, uint32_t T, const char* data) {
	OCTET L40[14] = "fortybits";
	struct EDATA edata = (EDATA) { 0, 0, 0 };

	unsigned char* K1 = (unsigned char*)calloc(HMAC_MD5_LENGTH, sizeof(unsigned char));
	if (export) {
		*((DWORD *)(L40 + 10)) = T; // appends T to L40
		memcpy_s(K1, HMAC_MD5_LENGTH, HMAC(EVP_md5(), K, MD4_DIGEST_LENGTH, L40, 14, NULL, NULL), HMAC_MD5_LENGTH);
	}
	else {
		memcpy_s(K1, HMAC_MD5_LENGTH, HMAC(EVP_md5(), K, MD4_DIGEST_LENGTH, &T, 4, NULL, NULL), HMAC_MD5_LENGTH);
	}
	unsigned char* K2 = (unsigned char*)calloc(HMAC_MD5_LENGTH, sizeof(unsigned char));
	memcpy_s(K2, HMAC_MD5_LENGTH, K1, HMAC_MD5_LENGTH);
	if (export) memset(K1 + 7, 0xAB, 9);
	
	RAND_bytes(edata.Confounder, 8);
	edata.Data = (OCTET*)calloc(strlen(data)+1, sizeof(OCTET));
	strcpy_s(edata.Data, strlen(data)+1, data);
	// Checksum looks at concat of confounder and data
	unsigned char* concat = (unsigned char*)calloc(9 + strlen(edata.Data), sizeof(unsigned char));
	memcpy_s(concat, 9 + strlen(edata.Data), edata.Confounder, 8);
	strcpy_s(concat + 8, strlen(edata.Data) + 1, edata.Data);
	memcpy_s(edata.Checksum, HMAC_MD5_LENGTH, HMAC(EVP_md5(), K2, HMAC_MD5_LENGTH, concat, 9 + strlen(edata.Data), NULL, NULL), HMAC_MD5_LENGTH);
	
	unsigned char* K3 = HMAC(EVP_md5(), K1, HMAC_MD5_LENGTH, edata.Checksum, HMAC_MD5_LENGTH, NULL, NULL);
	RC4(K3, 8, edata.Confounder, edata.Confounder);
	RC4(K3, strlen(data), edata.Data, edata.Data);

	free(K1);
	K1 = NULL;
	free(K2);
	K2 = NULL;
	free(concat);
	concat = NULL;
	return edata;
}

// Decryption
// K: Input key, export: Key length > 5 bytes, T: Message Type (4 byte LE), edata: Input encrypted data
int decrypt(const unsigned char* K, int export, uint32_t T, struct EDATA* edata) {
	OCTET L40[14] = "fortybits";

	unsigned char* K1 = (unsigned char*)calloc(HMAC_MD5_LENGTH, sizeof(unsigned char));
	if (export) {
		*((DWORD *)(L40 + 10)) = T;
		memcpy_s(K1, HMAC_MD5_LENGTH, HMAC(EVP_md5(), K, MD4_DIGEST_LENGTH, L40, 14, NULL, NULL), HMAC_MD5_LENGTH);
	}
	else {
		memcpy_s(K1, HMAC_MD5_LENGTH, HMAC(EVP_md5(), K, MD4_DIGEST_LENGTH, &T, 4, NULL, NULL), HMAC_MD5_LENGTH);
	}
	unsigned char* K2 = (unsigned char*)calloc(HMAC_MD5_LENGTH, sizeof(unsigned char));
	memcpy_s(K2, HMAC_MD5_LENGTH, K1, HMAC_MD5_LENGTH);
	if (export) memset(K1 + 7, 0xAB, 9);

	unsigned char* K3 = HMAC(EVP_md5(), K1, HMAC_MD5_LENGTH, edata->Checksum, HMAC_MD5_LENGTH, NULL, NULL);
	RC4(K3, 8, edata->Confounder, edata->Confounder);
	RC4(K3, strlen(edata->Data), edata->Data, edata->Data);

	unsigned char* concat = (unsigned char*)calloc(9 + strlen(edata->Data), sizeof(unsigned char));
	memcpy_s(concat, 9 + strlen(edata->Data), edata->Confounder, 8);
	strcpy_s(concat + 8, strlen(edata->Data) + 1, edata->Data);
	unsigned char* checksum = (unsigned char*)calloc(HMAC_MD5_LENGTH, sizeof(unsigned char));
	memcpy_s(checksum, HMAC_MD5_LENGTH, HMAC(EVP_md5(), K2, HMAC_MD5_LENGTH, concat, 9 + strlen(edata->Data), NULL, NULL), HMAC_MD5_LENGTH);

	free(K1);
	K1 = NULL;
	free(K2);
	K2 = NULL;
	free(concat);
	concat = NULL;

	for (int i = 0; i < HMAC_MD5_LENGTH; ++i) {
		if (checksum[i] != edata->Checksum[i]) {
			printf("ERROR: CHECKSUM FAILED!\n");
			free(checksum);
			checksum = NULL;
			return 0;
		}
	}

	free(checksum);
	checksum = NULL;
	return 1;
}


#endif