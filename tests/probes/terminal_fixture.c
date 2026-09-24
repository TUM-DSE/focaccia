/* Observation fixtures only: no oracle or whole-program support claim. */
#include <signal.h>
#include <unistd.h>

int main(void) {
#ifdef FATAL_SIGNAL
    raise(SIGTERM);
    _exit(99); /* Reaching this means the fatal signal was suppressed. */
#else
    _exit(EXIT_CODE);
#endif
}
