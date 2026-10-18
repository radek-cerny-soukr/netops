#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {
    int serving = argc == 1 || (argc == 2 && strcmp(argv[1], "serve") == 0);
    if (serving) {
        sigset_t signals;
        if (sigemptyset(&signals) != 0 || sigaddset(&signals, SIGTERM) != 0 ||
            sigprocmask(SIG_BLOCK, &signals, NULL) != 0) {
            fputs("netops: Cannot preserve startup stop signal\n", stderr);
            return 127;
        }
    }
    char **args = calloc((size_t)argc + 3, sizeof(*args));
    if (args == NULL) {
        fputs("netops: Cannot start command\n", stderr);
        return 127;
    }
    args[0] = "/usr/local/bin/python";
    args[1] = "/usr/local/bin/netops";
    if (argc == 1) {
        args[2] = "serve";
    } else {
        for (int i = 1; i < argc; i++) args[i + 1] = argv[i];
    }
    execv(args[0], args);
    fputs("netops: Cannot execute command\n", stderr);
    free(args);
    return 127;
}
