# RC4-HMAC-MD5
C implementation of RC4-HMAC-MD5 authentication used by Kerberos

## Dependencies
The implementation uses OpenSSL's libcrypto library. 

## Usage
### Adding to Your Project
The implementation is located entirely in RC4_HMAC_MD5/RC4_HMAC_MD5.h. 

Remember to compile with `-lcrypto` if using GCC or Clang.

### Encryption
```c
const unsigned char* key = "0123456789ABCDEF";                        // Assumes keys are length 16
const char* data = "data";
const unsigned char* encdata = encrypt(key, 1, data, strlen(data));   // Exclude null terminator if using const char*
```

### Decryption
```c
const int enclen = HMAC_MD5_LENGTH + CONFOUNDER_LENGTH + strlen(data);
int result = decrypt(key, 1, encdata, enclen);
```
