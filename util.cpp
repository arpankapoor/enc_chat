#include <cstdio>
#include <cstring>
#include <string>
#include <iostream>
#include "polarssl/aes.h"
#include "polarssl/net.h"
#include "util.h"
using namespace std;

/* Read the key for AES */
void
read_key(const char *arg_key, unsigned char *key,
		size_t keysize, size_t *keylen)
{
	FILE *fkey;
	if ((fkey = fopen(arg_key, "rb")) != NULL) {
		*keylen = fread(key, 1, keysize, fkey);
		fclose(fkey);
	} else {
		if (memcmp(arg_key, "hex:", 4) == 0) {
			int n;
			char *p = (char *)&arg_key[4];
			*keylen = 0;

			while (sscanf(p, "%02X", &n) > 0 &&
					*keylen < keysize) {
				key[(*keylen)++] = (unsigned char) n;
				p += 2;
			}
		} else {
			*keylen = strlen(arg_key);

			if (*keylen > keysize)
				*keylen = keysize;

			memcpy(key, arg_key, *keylen);
		}
	}

	*keylen = 8 * (*keylen);
}

/*
 * Encrypt given message and send to the server
 * @return number of bytes sent
 *	(may be more than the message lenth due to padding)
 */
int
encrypt_and_send(unsigned char *key, size_t keylen,
		int fd, const char *msg, size_t msglen)
{
	aes_context ctx;
	size_t sent = 0;
	int n;

	msglen++;

	aes_init(&ctx);
	aes_setkey_enc(&ctx, key, keylen);
	while (sent < msglen) {
		unsigned char in[16], out[16];

		memset(in, 0, 16);		/* Pad with zeroes */
		memset(out, 0, 16);		/* Pad with zeroes */
		memcpy(in, msg + sent,
			(msglen - sent) > 16 ? 16 : (msglen - sent));

		aes_crypt_ecb(&ctx, AES_ENCRYPT, in, out);

		n = net_send(&fd, out, 16);
		if (n == -1)
			break;

		sent += n;
	}

	aes_free(&ctx);
	return sent;
}

/*
 * Receive a NULL-terminated encrypted message
 * @return number of bytes read
 */
int
recv_and_decrypt(unsigned char *key, size_t keylen, int fd, string& msg)
{
	aes_context ctx;
	int n, total = 0;
	bool eom = true;	/* End of message */
	unsigned char in[16], out[16];

	aes_init(&ctx);
	aes_setkey_dec(&ctx, key, keylen);

	msg.clear();
	/* Every message should be null-terminated */
	while (eom) {
		memset(in, 0, 16);		/* Pad with zeroes */
		memset(out, 0, 16);		/* Pad with zeroes */
		n = net_recv(&fd, in, 16);
		if (n <= 0)
			break;

		total += n;
		aes_crypt_ecb(&ctx, AES_DECRYPT, in, out);
		for (int i = 0; i < 16; i++) {
			/* This packet marks the end of message */
			if (out[i] == 0) {
				eom = false;
				break;
			}
			msg += out[i];
		}
	}

	aes_free(&ctx);
	return total;
}
