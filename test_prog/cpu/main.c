#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <signal.h>
#include <unistd.h>

pthread_t threads[4];

void sighandler(int i) {
    if (i == SIGINT) {
        for (int i = 0; i < 4; i++) {
            pthread_join(threads[i], NULL);
        }
        exit(0);
    }
}

void* thread_func(void *arg) {
    for (int i = 0; i < 60; i++) {
        printf("%d\n", (int)(arg));
        sleep(1);
    }
}

int main() {
    signal(SIGINT, sighandler);
    for (int i = 0; i < 4; i++) {
        pthread_create(&threads[i], NULL, thread_func, (void *)i);
    }
    for (;;) {}
    return 0;
}
