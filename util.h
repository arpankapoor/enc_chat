#ifndef _MY_UTIL_H_
#define _MY_UTIL_H_
#include <string>
#include "polarssl/aes.h"

void
read_key(const char *arg_key, unsigned char *key,
		size_t keysize, size_t *keylen);

int
encrypt_and_send(unsigned char *key, size_t keylen,
		int fd, const char *msg, size_t msglen);

int
recv_and_decrypt(unsigned char *key, size_t keylen, int fd, std::string& msg);

#endif
