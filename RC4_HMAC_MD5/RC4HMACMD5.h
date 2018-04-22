#ifndef RC4HMACMD5_H
#define RC4HMACMD5_H

#include "stdlib.h"
#include "string.h"

#include <openssl\hmac.h>
#include <openssl\md5.h>
#include <openssl\rand.h>
#include <openssl\rc4.h>

#define KEY_LENGTH 16
#define HMAC_MD5_LENGTH 16
#define CONFOUNDER_LENGTH 8

void decrypt(const unsigned char* K, const uint32_t T, unsigned char* edata, const int edata_len) {

	int data_len = edata_len - HMAC_MD5_LENGTH - CONFOUNDER_LENGTH;
	
	// Initialize K1 (same as K2 without EXP) and K3)
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
	if (memcmp(checksum, edata, HMAC_MD5_LENGTH)) printf("Checksum failed!\n");
}

#endif