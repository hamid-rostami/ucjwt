#ifndef _JWT_H_
#define _JWT_H_

#include <stdlib.h>
#include <stdbool.h>

/* HS256 base64 encoded length */
#define   HS256_B64_LEN   44

typedef enum {
  JWTDecode_Verified = 0,      // Everything is fine
  JWTDecode_NotVerified = -1, // Signture verification failed
  JWTDecode_BadToken = -2,     // Bad JWT Token
  JWTDecode_NoBufSpace = -3    // No input buffer space to copy decoded payload
} JWTDecode;

char*
jwt_encode(char *data, size_t data_size,
           char *key, size_t key_size);

JWTDecode
jwt_decode(char *token, size_t token_size,
           char *key, size_t key_size,
           char *data, size_t data_len);

#endif
