#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "hmac-sha256.h"
#include "base64.h"
#include "jwt.h"

int main(void)
{
  char *data1 = "{\"uname\":\"user\"}";
  char data2[100];
  char *key = "secretkey";
  char token[120];
  JWTDecode decode_result;
  int r;

  r = jwt_encode(data1, strlen(data1),
                key, strlen(key),
                token, sizeof(token));
  if (r <= 0) {
    printf("Encode error\n");
    return 1;
  }

  printf("Original data: %s\n", data1);
  printf("jwt_encode: %d bytes, %s\n", r, token);
  printf("----\n");

  decode_result = jwt_decode(token, strlen(token),
                              key, strlen(key),
                              data2, sizeof(data2),
                              false);
  printf("Retrived data without check sign: %s\n", data2);
  printf("----\n");

  decode_result = jwt_decode(token, strlen(token),
                              key, strlen(key),
                              data2, sizeof(data2),
                              true);
  printf("jwt_decode: %d %s\n", decode_result,
                                decode_result == JWTDecode_OK ? "(Verified)" : "" );
  printf("Retrived data: %s\n", data2);
  printf("----\n");

  /* Corrept sign */
  *(token + strlen(token) - 5) = '\0';
  printf("correpted token: %s\n", token);

  decode_result = jwt_decode(token, strlen(token),
                              key, strlen(key),
                              data2, sizeof(data2),
                              true);
  printf("jwt_decode: %d %s\n", decode_result,
                                decode_result == JWTDecode_OK ? "(Verified)" : "" );
  printf("Retrived data: %s\n", data2);

  return 0;
}
