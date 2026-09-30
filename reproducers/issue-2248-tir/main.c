#include <stddef.h>
#include <stdint.h>

int64_t callme(size_t _1, size_t _2, int64_t a, int64_t b, int64_t c);

int main(void) {
    return callme(0, 0, 0, 1, 2) == -1 ? 0 : 1;
}
