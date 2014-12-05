#include <cstdio>
#include <cstdlib>
#include <sys/socket.h>
#include <sys/select.h>
#include <netdb.h>
#include <algorithm>
#include <fstream>
#include <iostream>
#include <map>
#include <polarssl/aes.h>
#include <polarssl/ctr_drbg.h>
#include <polarssl/dhm.h>
#include <polarssl/entropy.h>
#include <polarssl/error.h>
#include <polarssl/net.h>
#include "util.h"
using namespace std;

/* Username => Password */
map <string, string> usr_pwd;

/* Populate the usr_pwd map */
static int
pwd_init(const char *pwd_file)
{
	int count = 0;
	string line;
	ifstream fpwd(pwd_file);
	if (fpwd.fail())
		return -1;

	/*
	 * Each line is of the form
	 * USERNAME:PASSWORD
	 */
	while (getline(fpwd, line)) {
		auto it = find(line.begin(), line.end(), ':');
		if (it == line.end())
			continue;

		string username(line.begin(), it);
		string password(it + 1, line.end());

		usr_pwd[username] = password;
		count++;
	}

	fpwd.close();
	return count == 0 ? -1 : 0;
}

/*
 * Receive the username and password from the client.
 * Also save the username.
 * @return true if credentials are correct
 */
static bool
authenticate(unsigned char *key, size_t keylen, int fd, string& username)
{
	string pwd;

	/* Username will be terminated by zeroes */
	recv_and_decrypt(key, keylen, fd, username);
	recv_and_decrypt(key, keylen, fd, pwd);

	/* Find this user's password */
	auto it = usr_pwd.find(username);

	/* User doesn't exist */
	if (it == usr_pwd.end())
		return false;
	else
		return it->second == pwd;
}

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

	dhm.len = mpi_size(&dhm.P);

	/* Setup the DH parameters & send to the client */
	if (dhm_make_public(&dhm, (int)mpi_size(&dhm.P), buf, buflen,
				ctr_drbg_random, &ctr_drbg) != 0) {
		fprintf(stderr, "ERROR: dhm_make_public\n");
		return -1;
	}

	if (net_send(&fd, buf, buflen) != (int)buflen) {
		fprintf(stderr, "ERROR: send\n");
		return -1;
	}

	memset(buf, 0, sizeof(buf));

	/* Get client's public parameters */
	if (net_recv(&fd, buf, buflen) != (int)buflen) {
		fprintf(stderr, "ERROR: recv\n");
		return -1;
	}

	if (dhm_read_public(&dhm, buf, dhm.len) != 0) {
		fprintf(stderr, "ERROR: dhm_read_public\n");
		return -1;
	}

	memset(buf, 0, sizeof(buf));

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
 * 1) Accept an incoming connection from a client
 * 2) Exchange AES-256 keys with the client
 * 3) Receive the username and password of the client
 * 4) Close the connection if any error occurs
 */
static int
accept_and_auth(int listener, string& username,
		unsigned char *key, size_t keylen)
{
	int newfd = -1;
	int ret = -1;
	char host[NI_MAXHOST], service[NI_MAXSERV];

	struct sockaddr_storage client_addr;
	socklen_t addr_len = sizeof(client_addr);

	if (net_accept(listener, &newfd, NULL) != 0) {
		fprintf(stderr, "ERROR: accept\n");
	} else {
		memset(key, 0, keylen);
		if (exchange_key(newfd, key, keylen) != 0) {
			fprintf(stderr, "Key exchange failed\n");
			goto err;
		}

		if (getpeername(newfd, (struct sockaddr *)&client_addr,
				&addr_len) != 0) {
			perror("getpeername");
			goto err;
		}

		if (getnameinfo((struct sockaddr *)&client_addr, addr_len,
				host, NI_MAXHOST, service, NI_MAXSERV,
				NI_NUMERICSERV) != 0) {
			perror("getnameinfo");
			goto err;
		}

		if (authenticate(key, keylen, newfd, username)) {
			ret = 0;		/* Success */
			cout << username << ", joining." << endl;
		} else {
			fprintf(stderr, "Invalid login attempt from %s:%s\n",
					host, service);
		}
	}

err:
	if (ret == -1) {
		net_close(newfd);
		newfd = -1;
	} else {
		encrypt_and_send(key, keylen, newfd, "HI", 2);
	}

	return newfd;
}

int
main(int argc, char *argv[])
{
	int port, newfd, fdmax, fd, msglen;
	int listener = -1;
	int ret = EXIT_FAILURE;
	char *arg_port, *arg_pwd_file;
	const size_t keylen = 32;	/* 256 bits */
	unsigned char key[keylen];
	unsigned char *nkey;

	fd_set master, read_fds;
	string username, msg;
	vector <int> trash;

	/* File descriptor => key, username */
	map <int, pair <unsigned char *, string> > fd_usr;

	if (argc != 3) {
		fprintf(stderr,
			"Usage: %s <port> <password FILE>\n",
			argv[0]);

		fprintf(stderr,
			"example: %s 3490 shadow\n",
			argv[0]);
		goto exit;
	} else {
		arg_port = argv[1];
		arg_pwd_file = argv[2];
	}

	port = atoi(arg_port);

	/* Initialize the password map */
	if (pwd_init(arg_pwd_file) == -1) {
		fprintf(stderr, "Invalid password file\n");
		goto exit;
	}

	/* Start the server */
	if (net_bind(&listener, NULL, port) != 0) {
		fprintf(stderr, "ERROR: bind\n");
		goto exit;
	}

	/* Clear master and temp sets */
	FD_ZERO(&master);
	FD_ZERO(&read_fds);

	/* Add listener to master set */
	FD_SET(listener, &master);

	/* Keep track of the highest numbered file descriptor */
	fdmax = listener;

	for (;;) {
		read_fds = master;	/* copy it */
		if (select(fdmax+1, &read_fds, NULL, NULL, NULL) == -1) {
			perror("select");
			goto exit;
		}

		if (FD_ISSET(listener, &read_fds)) {	/* New connection */
			newfd = accept_and_auth(listener, username, key, keylen);
			if (newfd != -1) {
				/* Add to master set */
				FD_SET(newfd, &master);
				if (newfd > fdmax)
					fdmax = newfd;

				nkey = (unsigned char *)calloc(1, keylen);
				if (nkey == NULL) {
					fprintf(stderr, "Memory error\n");
					goto exit;
				}

				memcpy(nkey, key, keylen);

				msg = username + ", joining.";

				/* Send to ALL */
				for (auto x: fd_usr) {
					int fdnew = x.first;
					unsigned char *nnkey = x.second.first;

					encrypt_and_send(nnkey, keylen, fdnew,
							msg.c_str(), msg.size());
				}

				/* Add to the map */
				fd_usr[newfd] = make_pair(nkey, username);
			}
		}

		/* Handle data from a client */
		for (auto it: fd_usr) {
			fd = it.first;
			nkey = it.second.first;
			username = it.second.second;
			if (!FD_ISSET(fd, &read_fds))
				continue;

			msglen = recv_and_decrypt(nkey, keylen, fd, msg);
			if (msglen == 0) {
				/* Connection closed */
				msg = username + ", quitting.";

				net_close(fd);
				FD_CLR(fd, &master);
				/* Clear the map value */
				trash.push_back(fd);
			} else {
				msg = username + ": " + msg;
			}

			cout << msg << endl;

			/* Send to ALL */
			for (auto x: fd_usr) {
				int fdnew = x.first;
				unsigned char *nnkey = x.second.first;
				if (fdnew == fd)
					continue;
				if (find(trash.begin(), trash.end(),
						fdnew) != trash.end())
					continue;

				encrypt_and_send(nnkey, keylen, fdnew,
						msg.c_str(), msg.size());
			}
		}

		for (auto x: trash) {
			free(fd_usr[x].first);
			fd_usr.erase(x);
		}
		trash.clear();
	}

	ret = EXIT_SUCCESS;
exit:
	if (listener != -1)
		net_close(listener);

	return ret;
}
