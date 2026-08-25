#ifndef AEGIS_EVENTS_H
#define AEGIS_EVENTS_H

#include <linux/types.h>

#define AEGIS_COMM_LEN 16
#define AEGIS_PATH_LEN 256

enum aegis_event_type {
    AEGIS_PROCESS_EXEC = 1,
    AEGIS_PROCESS_EXIT = 2,
};

/*
 * Fixed-size records deliberately keep kernel work bounded. User space enriches
 * paths, hashes, container identity, and command-line data after ring-buffer read.
 */
struct aegis_process_event {
    __u64 monotonic_ns;
    __u64 process_start_ns;
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 event_type;
    char comm[AEGIS_COMM_LEN];
    char filename[AEGIS_PATH_LEN];
};

#endif
