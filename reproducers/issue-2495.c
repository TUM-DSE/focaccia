char i_R8[8] = { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };
char i_MM0[8] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
char o_R8[8];

int main(int argc, char **argv) {
    __asm__ (
        ".intel_syntax noprefix\n"
        "mov r8, qword ptr [rip + i_R8]\n"
        "movq mm0, qword ptr [rip + i_MM0]\n"
        ".byte 0x4f, 0x0f, 0x7e, 0xc0\n"
        "mov qword ptr [rip + o_R8], r8\n"
        ".att_syntax\n"
    );
    return 0;
}
