#include <stdint.h>
#include <stdio.h>
#include <string.h>

uint8_t i_R8[8] = { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };
uint8_t i_MM0[8] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
uint8_t o_R8[8];

void __attribute__ ((noinline)) show_state() {
    printf("R8: ");
    for (int i = 0; i < 8; i++) {
        printf("%02x ", o_R8[i]);
    }
    printf("\n");
}

void __attribute__ ((noinline)) run() {
    __asm__ (
        ".intel_syntax noprefix\n"
        "mov r8, qword ptr [rip + i_R8]\n"
        "movq mm0, qword ptr [rip + i_MM0]\n"
        ".byte 0x4f, 0x0f, 0x7e, 0xc0\n"
        "mov qword ptr [rip + o_R8], r8\n"
        ".att_syntax\n"
    );
}

int main(int argc, char **argv) {
    run();
    show_state();
    return 0;
}
