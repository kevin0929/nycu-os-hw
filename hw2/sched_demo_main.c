#define _GNU_SOURCE
#include <pthread.h>
#include <sched.h>
#include "sched_demo.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>


int main(int argc, char *argv[]) {
    int num_threads = 0;
    double busy_time = 0.0;
    char *str_policies = NULL, *str_priorities = NULL;

    int opt;
    while ((opt = getopt(argc, argv, "n:t:s:p:")) != -1) {
        switch (opt) {
            case 'n':
                num_threads = atoi(optarg);
                break;
            case 't':
                busy_time = atof(optarg);
                break;
            case 's':
                str_policies = strdup(optarg);
                break;
            case 'p':
                str_priorities = strdup(optarg);
                break;
        }
    }

    int policies[num_threads], priorities[num_threads];

    /*
        because the strtok only can have one status, we can't use it to parse two string at the same time
        1. deal with the policy string
        2. deal with the priority string
    */
    char *policy_tok = strtok(str_policies, ",");
    for (int i=0;i<num_threads;i++) {
        policies[i] = strcmp(policy_tok, "FIFO") == 0 ? SCHED_FIFO : SCHED_OTHER;
        policy_tok = strtok(NULL, ",");
    }

    char *priority_tok = strtok(str_priorities, ",");
    for (int i=0;i<num_threads;i++) {
        priorities[i] = atoi(priority_tok);
        priority_tok = strtok(NULL, ",");
    }


    /* 2. Create <num_threads> worker threads */

    // create threads
    pthread_t threads[num_threads];
    thread_info_t thread_info[num_threads];
    pthread_attr_t attr[num_threads];
    pthread_barrier_t barrier;

    /* 3. set cpu affinity */
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(0, &cpuset);
    sched_setaffinity(0, sizeof(cpuset), &cpuset);
    
    pthread_barrier_init(&barrier, NULL, num_threads);

    for (int i=0;i<num_threads;i++) {
        /* 4. set the attributes to each thread */
        pthread_attr_init(&attr[i]);
        
        if (policies[i] == SCHED_FIFO) {
            struct sched_param param;
            param.sched_priority = priorities[i];
            pthread_attr_setschedpolicy(&attr[i], SCHED_FIFO);
            pthread_attr_setschedparam(&attr[i], &param);
            pthread_attr_setinheritsched(&attr[i], PTHREAD_EXPLICIT_SCHED); // important
        }
        else {
            pthread_attr_setschedpolicy(&attr[i], SCHED_OTHER);
        }

        // generate thread information
        thread_info[i] = (thread_info_t){
            .thread_id = i,
            .policy = policies[i],
            .priority = priorities[i],
            .busy_time = busy_time,
            .barrier = &barrier
        };


        /* 5. start all thread at once  */
        pthread_create(&threads[i], &attr[i], thread_func, &thread_info[i]);

        pthread_attr_destroy(&attr[i]);
    }

    /* 6. wait for all threads to finish */
    for (int i=0;i<num_threads;i++) {
        pthread_join(threads[i], NULL);
    }

    pthread_barrier_destroy(&barrier);
}