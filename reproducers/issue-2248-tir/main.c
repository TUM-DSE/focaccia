#include <stdio.h>
#include <stdint.h>

int64_t callme(size_t _1, size_t _2, int64_t a, int64_t b, int64_t c);

int main() {
    int64_t ret = callme(0, 0, 0, 1, 2);
    printf("%ld\n", ret);
    return 0;
}
