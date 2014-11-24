#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sys/select.h>
#include <sys/socket.h>
#include <netdb.h>
#include <iostream>
#include <string>
#include "polarssl/aes.h"
#include "polarssl/net.h"
#include "polarssl/sha1.h"
#include "util.h"
using namespace std;

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
	size_t keylen, pwdlen;
	char *arg_host, *arg_port, *arg_key, *arg_usr, *arg_pwd;
	unsigned char key[64];
	fd_set master, read_fds;
	string msg;

	if (argc != 6) {
		fprintf(stderr,
			"Usage: %s <host> <port> <key> <username> <password>\n",
			argv[0]);
		fprintf(stderr,
			"example: %s localhost 3490 hex:0123456789ABCDEF0123456789ABCDEF abcd abcd\n",
			argv[0]);
		goto exit;
	} else {
		arg_host = argv[1];
		arg_port = argv[2];
		arg_key = argv[3];
		arg_usr = argv[4];
		arg_pwd = argv[5];
		pwdlen = strlen(arg_pwd);
	}

	port = atoi(arg_port);

	/* Read key */
	read_key(arg_key, key, sizeof(key), &keylen);

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
	memset(arg_key, 0, strlen(arg_key));
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
