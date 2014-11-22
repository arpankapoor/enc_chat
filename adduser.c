#include <stdio.h>
#include <string.h>
#include "polarssl/sha1.h"

int main(int argc, char *argv[])
{
	int ret = 1;
	FILE *fpwd = NULL;
	unsigned char output[20];

	if (argc != 4) {
		fprintf(stderr,
			"Usage: %s <password FILE> <username> <password>\n",
			argv[0]);
		goto exit;
	}

	if ((fpwd = fopen(argv[1], "a")) == NULL) {
		fprintf(stderr, "ERROR: Cannot open %s\n", argv[1]);
		goto exit;
	}

	sha1((unsigned char *)argv[3], strlen(argv[3]), output);
	fprintf(fpwd, "%s:", argv[2]);
	for (int i = 0; i < 20; i++)
		fprintf(fpwd, "%02X", output[i]);
	fprintf(fpwd, "\n");

	ret = 0;
exit:
	if (fpwd)
		fclose(fpwd);
	return ret;
}
