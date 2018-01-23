#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>

void sighandler(int i) {
    if (i == SIGINT) 
        exit(0);
}

int main() {
    int *j[1024];
    for (int i = 0; i < 1024; i++) {
        if (i == 0)
            sleep(30);
        j[i] = (int*)malloc(sizeof(int));
        printf("res %d\n", *j[i]);
    }
    //free(j);
    signal(SIGINT, sighandler);
    for (;;) {}
    return 0;
}
