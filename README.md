# JWT implemention for Microcontroller
Encode and decode JWT tokens. Lightweight and no need to external library, suitable for using in microcontrollers.

# Sample usage

##Encode
```c
char *data = "{\"uname\":\"user\"}";
char *key = "secretkey";
char *token;

token = jwt_encode(data1, strlen(data1), key, strlen(key));
```

##Decode
```c
char data[100];
JWTDecode decode_result;
char *key = "secretkey";

decode_result = jwt_decode(token, strlen(token),
                           key, strlen(key),
                           data, sizeof(data));
```
