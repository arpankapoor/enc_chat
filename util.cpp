#include <cstdio>
#include <cstring>
#include <string>
#include <iostream>
#include <polarssl/aes.h>
#include <polarssl/net.h>
#include "util.h"
using namespace std;

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
	aes_setkey_enc(&ctx, key, 8*keylen);	/* Convert keylen to bits */
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
	aes_setkey_dec(&ctx, key, 8*keylen);	/* Convert keylen to bits */

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
