int main() {
    long long result;
    long long data = 0x11111111deadbeef;
    
    
    asm volatile(
        "mov x1, %[data_addr]\n\t"
        "ldapur x0, [x1, #-8]\n\t"
        "mov %[result], x0\n\t"
        : [result] "=r" (result)
        : [data_addr] "r" (&data + 1)
        : "x0", "x1", "memory"
    );
    
    return 0;
}
