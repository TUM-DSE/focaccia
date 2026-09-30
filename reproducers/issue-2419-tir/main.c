#include <stdint.h>

uint64_t issue2419(const uint64_t *base);

int main(void)
{
    /* -8 and the historically misdecoded +504 are both mapped and distinct. */
    struct {
        uint64_t target;
        unsigned char gap[504];
        uint64_t canary;
    } volatile values = {
        .target = UINT64_C(0x11111111deadbeef),
        .canary = UINT64_C(0x22222222cafebabe),
    };

    return issue2419((const uint64_t *)((const unsigned char *)&values + 8))
        == values.target ? 0 : 1;
}
