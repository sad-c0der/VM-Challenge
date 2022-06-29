#include "../tigress/3.3.2/tigress.h"
#include <stdio.h>
#include <stdlib.h>

unsigned long long secret_key(unsigned long long n);

int main (int argc, char** argv) {

	char* endl;

	if (argc < 2) {
		printf("./vm_chal <secret>\n");
		return -1;
	}

	unsigned long long password = strtoull(argv[1], &endl, 16);

	if (secret_key(password)) {
		printf("FLAG(0x%llx)\n", secret_key(password));
	}

	return 0;
}

unsigned long long 
secret_key(unsigned long long n) {
	unsigned long long key = 0xFFFFFFFFFFFFFFFF;
	unsigned long long secret = 0xFFFFFFFFFFFF;
	if ((n ^ secret) == key) {
		return key;
	}

	return -1;
}
