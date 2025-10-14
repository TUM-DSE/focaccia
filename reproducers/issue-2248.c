#include <stdio.h>
#include <stdint.h>

size_t callme(size_t _1, size_t _2, size_t a, size_t b, size_t c);

int main() {
    int64_t ret = callme(0, 0, 0, 1, 2);

	int var = 0;

	if (ret < 0)
		var = 0;
	else
		var = 5;

	return var;
}

