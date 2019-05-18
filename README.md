# JWT implemention for Microcontroller
Encode and decode JWT tokens. Lightweight and no need to external library,
suitable for using in microcontrollers.

At this moment, only `HS256` algorithm supported.

# Sample usage

## Encode
```c
char *data = "{\"uname\":\"user\"}";
char *key = "secretkey";
char *token;

token = jwt_encode(data, strlen(data), key, strlen(key));
/* your codes ... */
free(token)
```

## Decode
```c
char data[100];
JWTDecode decode_result;
char *key = "secretkey";

decode_result = jwt_decode(token, strlen(token),
                           key, strlen(key),
                           data, sizeof(data));
```

`decode_result` is a typedef in `jwt.h` file:

```c
typedef enum {
  JWTDecode_Verified = 0,      // Everything is fine
  JWTDecode_NotVerified = -1,  // Signture verification failed
  JWTDecode_BadToken = -2,     // Bad JWT Token
  JWTDecode_NoBufSpace = -3    // No input buffer space to copy decoded payload
} JWTDecode;
```

`jwt_decode` output explaination:

* JWTDecode_Verified:
Token signture verified successfully and data copied to given buffer.

* JWTDecode_NotVerified:
Token signture is wrong, but data copied to given buffer.

* JWTDecode_BadToken:
Given token is not in JWT format.

* JWTDecode_NoBufSpace:
Not implemented yet!
