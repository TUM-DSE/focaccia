#define _GNU_SOURCE
#include <errno.h>
#include <inttypes.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Independent pre-execution configuration observation, not a guest oracle. */
int main(int argc, char **argv) {
    if (argc != 3 || strcmp(argv[1], "--cpu") != 0) {
        fprintf(stderr, "usage: focaccia-native-hardware-profile --cpu CPU\n");
        return 2;
    }
    char *end = NULL;
    errno = 0;
    long cpu = strtol(argv[2], &end, 10);
    if (errno || !end || end == argv[2] || *end || cpu < 0 || cpu >= CPU_SETSIZE) {
        fprintf(stderr, "invalid CPU index\n");
        return 2;
    }
    cpu_set_t affinity;
    CPU_ZERO(&affinity);
    CPU_SET(cpu, &affinity);
    if (sched_setaffinity(0, sizeof(affinity), &affinity) || sched_getcpu() != cpu) {
        perror("cannot establish hardware-profile CPU affinity");
        return 1;
    }
#if defined(__aarch64__)
    uint64_t dczid;
    __asm__ volatile("mrs %0, dczid_el0" : "=r"(dczid));
    if (sched_getcpu() != cpu) {
        fprintf(stderr, "hardware-profile CPU changed\n");
        return 1;
    }
    printf("{\"schema\":1,\"architecture\":\"aarch64\",\"cpu\":%ld,"
           "\"dczid_el0\":%" PRIu64 "}\n", cpu, dczid);
    return 0;
#else
    fprintf(stderr, "hardware-profile helper requires native AArch64\n");
    return 2;
#endif
}
