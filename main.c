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
  char *token;
  JWTDecode decode_result;

  token = jwt_encode(data1, strlen(data1),
             key, strlen(key));
  printf("Original data: %s\n", data1);
  printf("jwt_encode: %s\n", token);

  decode_result = jwt_decode(token, strlen(token),
                              key, strlen(key),
                              data2, sizeof(data2));
  printf("jwt_decode: %d %s\n", decode_result,
                                decode_result == JWTDecode_Verified ? "(Verified)" : "" );
  printf("Retrived data: %s\n", data2);
  return 0;
}