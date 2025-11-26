int main(int argc, char **argv) {
    __asm__ (
        ".intel_syntax noprefix\n"
        ".byte 0x40, 0x9f\n"
        ".att_syntax\n"
    );
    return 0;
}
