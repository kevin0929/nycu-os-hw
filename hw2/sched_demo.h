#ifndef SCHED_DEMO_H
#define SCHED_DEMO_H

#include <pthread.h>

// create a struct to store the thread information
typedef struct {
    int thread_id;
    int policy;
    int priority;
    double busy_time;
    pthread_barrier_t *barrier;
} thread_info_t;

void *thread_func(void *arg);

#endif