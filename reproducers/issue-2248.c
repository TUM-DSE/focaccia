#include <stdio.h>

unsigned long long callme(unsigned long long _1, unsigned long long _2, unsigned long long a, unsigned long long b, unsigned long long c);

int main() {
    unsigned long long ret = callme(0, 0, 0, 1, 2);
	printf("%lld\n", ret);
    return 0;
}

