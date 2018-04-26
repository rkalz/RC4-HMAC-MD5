#ifndef RC4_HMAC_MD5_H
#define RC4_HMAC_MD5_H

#include <stdlib.h>
#include <string.h>

#include <openssl\hmac.h>
#include <openssl\md5.h>
#include <openssl\rand.h>
#include <openssl\rc4.h>

#define KEY_LENGTH 16
#define HMAC_MD5_LENGTH 16
#define CONFOUNDER_LENGTH 8

// Encryption
// K - Key used for encryption
// T - 4 byte little endian based on message type (see specification)
// data - data to be encrypted
// data_len - length of data (exclude null terminator if using const char*)
//
// Output is allocated on the heap
// Length of output is data_len + 24
unsigned char* encrypt(const unsigned char* K, const uint32_t T, const unsigned char* data, const int data_len) {
	unsigned char* edata = (unsigned char*)malloc(HMAC_MD5_LENGTH + CONFOUNDER_LENGTH + data_len);

	// Generate K1 (same as K2)
	unsigned char K1[HMAC_MD5_LENGTH];
	HMAC(EVP_md5(), K, KEY_LENGTH, &T, 4, K1, NULL);

	// Generate confounder, copy data to output, generate checksum
	RAND_bytes(edata + HMAC_MD5_LENGTH, CONFOUNDER_LENGTH);
	memcpy_s(edata + HMAC_MD5_LENGTH + CONFOUNDER_LENGTH, data_len, data, data_len);
	unsigned char checksum[HMAC_MD5_LENGTH];
	HMAC(EVP_md5(), K1, KEY_LENGTH, edata + HMAC_MD5_LENGTH, CONFOUNDER_LENGTH + data_len, checksum, NULL);

	// Generate K3
	unsigned char K3[HMAC_MD5_LENGTH];
	HMAC(EVP_md5(), K1, KEY_LENGTH, checksum, HMAC_MD5_LENGTH, K3, NULL);

	// Generate RC4 key, perform on confounder and data
	RC4_KEY rc4_key;
	RC4_set_key(&rc4_key, HMAC_MD5_LENGTH, K3);
	RC4(&rc4_key, CONFOUNDER_LENGTH, edata + HMAC_MD5_LENGTH, edata + HMAC_MD5_LENGTH);
	RC4(&rc4_key, data_len, edata + HMAC_MD5_LENGTH + CONFOUNDER_LENGTH, edata + HMAC_MD5_LENGTH + CONFOUNDER_LENGTH);

	// Copy checksum to edata
	memcpy_s(edata, HMAC_MD5_LENGTH, checksum, HMAC_MD5_LENGTH);

	return edata;
}

// Encryption
// K - Key used for decryption
// T - 4 byte little endian based on message type (see specification)
// edata - Encrypted data to be decrypted
// edata_len - length of encrypted data
// Returns 1 if checksum passes, otherwise 0
//
// This function manipulates edata, rather than returning new memory
// Data starts at edata + 24
int decrypt(const unsigned char* K, const uint32_t T, unsigned char* edata, const int edata_len) {
	int data_len = edata_len - HMAC_MD5_LENGTH - CONFOUNDER_LENGTH;
	
	// Generate K1 (same as K2 without EXP) and K3
	unsigned char K1[HMAC_MD5_LENGTH];
	HMAC(EVP_md5(), K, KEY_LENGTH, &T, 4, K1, NULL); 
	unsigned char K3[HMAC_MD5_LENGTH];
	HMAC(EVP_md5(), K1, HMAC_MD5_LENGTH, edata, HMAC_MD5_LENGTH, K3, NULL); 

	// Decrypt edata
	RC4_KEY rc4_key;
	RC4_set_key(&rc4_key, HMAC_MD5_LENGTH, K3);
	RC4(&rc4_key, CONFOUNDER_LENGTH, edata + HMAC_MD5_LENGTH, edata + HMAC_MD5_LENGTH);  
	RC4(&rc4_key, data_len, edata + HMAC_MD5_LENGTH + CONFOUNDER_LENGTH, edata + HMAC_MD5_LENGTH + CONFOUNDER_LENGTH); 

	// Verify with checksum
	unsigned char checksum[HMAC_MD5_LENGTH];
	HMAC(EVP_md5(), K1, HMAC_MD5_LENGTH, edata + HMAC_MD5_LENGTH, edata_len - HMAC_MD5_LENGTH, checksum, NULL);
	if (memcmp(checksum, edata, HMAC_MD5_LENGTH)) return 0;

	return 1;
}

#endif