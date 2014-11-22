#include <cstdio>
#include <cstdlib>
#include <sys/socket.h>
#include <sys/select.h>
#include <netdb.h>
#include <algorithm>
#include <fstream>
#include <iostream>
#include <map>
#include "polarssl/aes.h"
#include "polarssl/net.h"
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

static int
accept_and_auth(unsigned char *key, size_t keylen, int listener, string& username)
{
	int newfd = -1, ret = -1;
	char host[NI_MAXHOST], service[NI_MAXSERV];
	struct sockaddr_storage client_addr;
	socklen_t addr_len = sizeof(client_addr);

	if (net_accept(listener, &newfd, NULL) != 0) {
		fprintf(stderr, "ERROR: accept\n");
	} else {
		getpeername(newfd, (struct sockaddr *)&client_addr, &addr_len);
		getnameinfo((struct sockaddr *)&client_addr, addr_len, host,
			NI_MAXHOST, service, NI_MAXSERV,NI_NUMERICSERV);

		if (authenticate(key, keylen, newfd, username)) {
			ret = 0;		/* Success */
			cout << username << ", joining." << endl;
		} else {
			fprintf(stderr, "Invalid login attempt from %s:%s\n",
					host, service);
		}
	}

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
	int port, listener, newfd, fdmax, fd, msglen;
	int ret = EXIT_FAILURE;
	size_t keylen;
	char *arg_port, *arg_key, *arg_pwd_file;
	unsigned char key[64];
	fd_set master, read_fds;
	string username, msg;
	vector <int> trash;

	/* File descriptor => Username */
	map <int, string> fd_usr;

	if (argc != 4) {
		fprintf(stderr,
			"Usage: %s <port> <key> <password FILE>\n",
			argv[0]);

		fprintf(stderr,
			"example: %s 3490 hex:0123456789ABCDEF0123456789ABCDEF shadow\n",
			argv[0]);
		goto exit;
	} else {
		arg_port = argv[1];
		arg_key = argv[2];
		arg_pwd_file = argv[3];
	}

	port = atoi(arg_port);

	/* Read secret key */
	read_key(arg_key, key, sizeof(key), &keylen);

	/* Clean the command line */
	memset(arg_key, 0, strlen(arg_key));

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
			newfd = accept_and_auth(key, keylen, listener, username);
			if (newfd != -1) {
				/* Add to master set */
				FD_SET(newfd, &master);
				if (newfd > fdmax)
					fdmax = newfd;

				/* Add to the map */
				fd_usr[newfd] = username;
			}
		}

		/* Handle data from a client */
		for (auto it: fd_usr) {
			fd = it.first;
			username = it.second;
			if (!FD_ISSET(fd, &read_fds))
				continue;

			msglen = recv_and_decrypt(key, keylen, fd, msg);
			if (msglen == 0) {
				/* Connection closed */
				cout << username << ", quitting.";
				cout << endl;

				net_close(fd);
				FD_CLR(fd, &master);
				/* Clear the map value */
				trash.push_back(fd);
			} else {
				msg = username + ": " + msg;
				cout << msg << endl;

				/* Send to ALL */
				for (auto x: fd_usr) {
					int fdnew = x.first;
					if (fdnew == fd)
						continue;
					if (find(trash.begin(), trash.end(),
							fdnew) != trash.end())
						continue;

					encrypt_and_send(key, keylen, fdnew,
							msg.c_str(), msg.size());
				}
			}
		}

		for (auto x: trash)
			fd_usr.erase(x);
		trash.clear();
	}

	ret = EXIT_SUCCESS;
exit:
	net_close(listener);
	return ret;
}
