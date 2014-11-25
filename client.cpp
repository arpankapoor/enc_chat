#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sys/select.h>
#include <sys/socket.h>
#include <netdb.h>
#include <iostream>
#include <string>
#include "polarssl/aes.h"
#include "polarssl/ctr_drbg.h"
#include "polarssl/dhm.h"
#include "polarssl/entropy.h"
#include "polarssl/net.h"
#include "polarssl/sha1.h"
#include "util.h"
using namespace std;

/*
 * Send & receive the DH parameters to establish the key
 * @return 0 on success, -1 on failure
 */
static int
exchange_key(int fd, unsigned char *key, size_t keylen)
{
	size_t buflen = 128;		/* Use 1024-bit P */
	unsigned char buf[buflen];

	entropy_context entropy;
	ctr_drbg_context ctr_drbg;
	dhm_context dhm;

	/* Diffie-Hellman init */
	dhm_init(&dhm);

	/* Seeding the random number generator */
	entropy_init(&entropy);
	if (ctr_drbg_init(&ctr_drbg, entropy_func,
				&entropy, NULL, 0) != 0) {
		fprintf(stderr, "ERROR: ctr_drbg_init\n");
		return -1;
	}

	/* Set DHM modulus and generator */
	if (mpi_read_string(&dhm.P, 16,
			POLARSSL_DHM_RFC2409_MODP_1024_P) != 0
		|| mpi_read_string(&dhm.G, 16,
			POLARSSL_DHM_RFC2409_MODP_1024_G) != 0) {
		fprintf(stderr, "ERROR: mpi_read_string\n");
		return -1;
	}

	memset(buf, 0, sizeof(buf));

	dhm.len = mpi_size(&dhm.P);
	/* Get server's public parameters */
	if (net_recv(&fd, buf, buflen) != (int)buflen) {
		fprintf(stderr, "ERROR: recv\n");
		return -1;
	}

	if (dhm_read_public(&dhm, buf, dhm.len) != 0) {
		fprintf(stderr, "ERROR: dhm_read_public\n");
		return -1;
	}

	memset(buf, 0, sizeof(buf));

	/* Setup the DH parameters & send to the server */
	if (dhm_make_public(&dhm, (int)mpi_size(&dhm.P), buf, buflen,
				ctr_drbg_random, &ctr_drbg) != 0) {
		fprintf(stderr, "ERROR: dhm_make_public\n");
		return -1;
	}

	if (net_send(&fd, buf, buflen) != (int)buflen) {
		fprintf(stderr, "ERROR: send\n");
		return -1;
	}

	if (dhm_calc_secret(&dhm, buf, &buflen,
			ctr_drbg_random, &ctr_drbg) != 0) {
		fprintf(stderr, "ERROR: dhm_calc_secret\n");
		return -1;
	}

	/* Copy the required keylength */
	memcpy(key, buf, keylen);

	dhm_free(&dhm);
	ctr_drbg_free(&ctr_drbg);
	entropy_free(&entropy);

	return 0;
}

/*
 * Send username and password to the server.
 * Server sends a NULL packet is authentication failed
 * @return 0 if authentication info is corrent, -1 otherwise
 */
static int
authenticate(unsigned char *key, size_t keylen, int fd,
		const char *usr, size_t usrlen,
		const char *pwd, size_t pwdlen)
{
	const int hplen = 20;		/* Hashed password length */
	int rd;
	char tmp[10];
	unsigned char hpwd[hplen];	/* Hashed password */
	string msg, hpwd_str;

	exchange_key(fd, key, keylen);

	/* Send username */
	encrypt_and_send(key, keylen, fd, usr, usrlen);

	/* Send hashed password as a string */
	sha1((unsigned char *)pwd, pwdlen, hpwd);
	for (int i = 0; i < hplen; i++) {
		snprintf(tmp, 10, "%02X", hpwd[i]);
		hpwd_str += tmp;
	}
	encrypt_and_send(key, keylen, fd, hpwd_str.c_str(), hpwd_str.length());

	rd = recv_and_decrypt(key, keylen, fd, msg);
	return rd == 0 ? -1 : 0;
}

int
main(int argc, char *argv[])
{
	int port, fd, fdmax, msglen;
	int ret = EXIT_FAILURE;
	const size_t keylen = 32;
	size_t pwdlen;
	char *arg_host, *arg_port, *arg_usr, *arg_pwd;
	unsigned char key[keylen];
	fd_set master, read_fds;
	string msg;

	if (argc != 5) {
		fprintf(stderr,
			"Usage: %s <host> <port> <username> <password>\n",
			argv[0]);
		fprintf(stderr,
			"example: %s localhost 3490 abcd abcd\n",
			argv[0]);
		goto exit;
	} else {
		arg_host = argv[1];
		arg_port = argv[2];
		arg_usr = argv[3];
		arg_pwd = argv[4];
		pwdlen = strlen(arg_pwd);
	}

	port = atoi(arg_port);

	/* Connect to the server */
	if (net_connect(&fd, arg_host, port) != 0) {
		fprintf(stderr, "ERROR: connect\n");
		goto exit;
	}

	/* Send username */
	if (authenticate(key, keylen, fd, arg_usr,
			strlen(arg_usr), arg_pwd, pwdlen) == -1) {
		fprintf(stderr, "ERROR: Incorrect credentials\n");
		goto exit;
	}

	/* Clean the command clean */
	memset(arg_pwd, 0, strlen(arg_pwd));

	FD_ZERO(&master);
	FD_ZERO(&read_fds);

	FD_SET(fileno(stdin), &master);
	fdmax = fileno(stdin);

	FD_SET(fd, &master);
	if (fd > fdmax)
		fdmax = fd;

	for (;;) {
		read_fds = master;
		if (select(fdmax+1, &read_fds, NULL, NULL, NULL) == -1) {
			perror("select");
			goto exit;
		}

		/* Incoming... */
		if (FD_ISSET(fd, &read_fds)) {
			msglen = recv_and_decrypt(key, keylen, fd, msg);
			if (msglen == 0) {
				printf("Server closed.\n");
				goto exit;
			} else {
				cout << msg << endl;
			}
		}

		if (FD_ISSET(fileno(stdin), &read_fds)) {
			msg.clear();
			getline(cin, msg);
			encrypt_and_send(key, keylen, fd,
					msg.c_str(), msg.length());
		}
	}

	ret = EXIT_SUCCESS;
exit:
	net_close(fd);
	return ret;
}
