#include <stdio.h>
#include <string.h>
#include <error.h>

#include "jwt.h"

#include "hmac-sha256.h"
#include "base64.h"

/* default header: {"alg":"HS256","typ":"JWT"} */
const char jwt_header_b64[] = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
#define   JWT_HDR_B64_LEN   sizeof(jwt_header_b64) - 1

/* Generate b64 encoded HS256 string,
 * Caller is responsible for freeing the returned buffer. Returned buffer is
 * null terminated to make it easier to use as a C string.
 */
unsigned char*
jwt_hs256_gen(char *key, size_t key_len,
              char* msg, size_t msg_len)
{
  unsigned char* bytes = malloc(32);
  unsigned char *b64;
  size_t b64_len;

  // Calculate HS256 bytes
  hmac_sha256(bytes, key, key_len*8, msg, msg_len*8);
  b64 = base64_encode((const unsigned char*)bytes, 32, &b64_len);
  free(bytes);
  return b64;
}

char*
jwt_encode(char *payload, size_t payload_size,
           char *key, size_t key_size)
{
  unsigned char *payload_b64;
  char *token;
  unsigned char *hs256_b64;
  size_t payload_b64_len;
  size_t token_len;
  uint32_t hs256_msg_len;


  payload_b64 = base64_encode((const unsigned char*)payload,
                              payload_size,
                              &payload_b64_len);

  // 2 for two dots and 44 for hs256 base64 output
  // hs256 output is always 32 bytes == 44 byte of base64 string
  // Plus 1 more space for NULL terminator
  token_len = payload_b64_len + JWT_HDR_B64_LEN + 2 + 44 + 1;
  token = malloc(token_len); 
  *(token + token_len - 1) = '\0';   // Insert NULL at last position
  // Header (base64)
  memcpy(token, jwt_header_b64, JWT_HDR_B64_LEN);
  // Dot
  *(token + JWT_HDR_B64_LEN) = '.';
  // Payload (base64)
  memcpy(token + JWT_HDR_B64_LEN + 1, payload_b64, payload_b64_len);
  // Calculate HS256
  hs256_msg_len = JWT_HDR_B64_LEN + 1 + payload_b64_len;
  hs256_b64 = jwt_hs256_gen(key, key_size, token, hs256_msg_len);

  *(token + JWT_HDR_B64_LEN + 1 + payload_b64_len) = '.';
  memcpy(token+JWT_HDR_B64_LEN+1+payload_b64_len+1, hs256_b64, 44);

  free(payload_b64);
  free(hs256_b64);

  return token;
}

JWTDecode
jwt_decode(char *token, size_t token_size,
           char *key, size_t key_size,
           char *data, size_t data_len,
           bool check_sign)
{
  char *dot1_p;       // Point to first dor in token
  char *dot2_p;       // Point to secod dot
  char *payload_b64;  // Message payload (b64_encoded)
  unsigned char *payload;      // Message payload (decoded)
  char *msg_sign;     // Message sign (HS256)
  unsigned char *sign;         // Calculated sign from message header and payload
  size_t header_b64_len;
  size_t payload_b64_len;
  size_t payload_len;
  size_t msg_sign_len;
  char *end = data + data_len - 1;  // Point to last character of token
  int ret = JWTDecode_OK;

  dot1_p = strchr(token, '.');
  if (dot1_p == NULL || dot1_p == end) {
    ret = JWTDecode_BadToken;
    goto error;
  }

  dot2_p = strchr(dot1_p + 1, '.');
  if (dot2_p == NULL || dot2_p == end) {
    ret = JWTDecode_BadToken;
    goto error;
  }

  header_b64_len = dot1_p - token;

  payload_b64 = dot1_p + 1;
  payload_b64_len = dot2_p - (dot1_p + 1);

  msg_sign = dot2_p + 1;
  msg_sign_len = (token + token_size - 1) - dot2_p;

  payload = base64_decode((const unsigned char*)payload_b64,
                          payload_b64_len,
                          &payload_len);
  if (payload_len >= data_len) {
    // Don't copy data, just terminate data pointer with NULL
    // Compare with >= because wee need one more space for NULL terminator
    if (data != NULL)
      *data = '\0';
  } else if (data != NULL){
    memcpy(data, payload, payload_len);
    *(data + payload_len) = '\0';
  }
  free(payload);

  if (!check_sign) {
    if (data == NULL)
      return JWTDecode_NoBufSpace;
    else
      return JWTDecode_OK;
  }

  /* Check message sign length */
  if (msg_sign_len != HS256_B64_LEN)
    return JWTDecode_NotVerified;

  sign = jwt_hs256_gen(key,
                       key_size,
                       token,
                       header_b64_len + payload_b64_len + 1);   // +1 for separating dot

  if (strncmp((char*)sign, msg_sign, msg_sign_len) != 0)
    ret = JWTDecode_NotVerified;

  free(sign);
  return ret;

error:
  if (data != NULL)
    *data = '\0';
  return ret;
}
