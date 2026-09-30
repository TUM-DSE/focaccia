#include <stdint.h>

uint32_t issue364(int8_t *memory);

int main(void)
{
    int8_t values[3] = { 0, -1, 3 };

    /* Canonical #364 operands: destination, source -1, memory 3. */
    values[0] = (int8_t)issue364(&values[2]);
    return values[0] == 3 && values[1] == -1 && values[2] == 3 ? 0 : 1;
}
