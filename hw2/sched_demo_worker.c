#include <pthread.h>
#include "sched_demo.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

void time_wait(double seconds)
{
    struct timespec start, now;
    clock_gettime(CLOCK_MONOTONIC, &start);

    double elapsed = 0.0;
    do {
        clock_gettime(CLOCK_MONOTONIC, &now);
        elapsed = now.tv_sec - start.tv_sec + (now.tv_nsec - start.tv_nsec) / 1e9;
    } while (elapsed < seconds);
}

void *thread_func(void *arg)
{
    /* 1. wait until all threads are ready */
    thread_info_t *thread_info = (thread_info_t *)arg;
    pthread_barrier_wait(thread_info->barrier);

    /* 2. do the task */
    for (int i=0;i<3;i++) {
        printf("Thread %d is starting\n", thread_info->thread_id);
        /* busy for <time_wait> seconds */
        time_wait(thread_info->busy_time);
    }

    return NULL;
}