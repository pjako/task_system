#define TASK_SYSTEM_IMPL
#include "task_system.h"

ts_fiberEntry(fiberEntry) {
    uint32_t* intData = (uint32_t*)data;
    *intData += 1;
}
ts_fiberEntry(fiberEntryMainThread) {
    ts_continueOnThread(1); // 1 is always the mainthread
    uint32_t* intData = (uint32_t*)data;
    *intData += 1;
}

int main(int args, char* argv[]) {
    (void)(args);
    (void)(argv);
    ts_setup((ts_Desc) {0});

    uint32_t numbers[5] = {1,2,3,4,5};

    ts_Job jobs[5] =  {
        { .data = (uintptr_t) (numbers + 0), .fn = fiberEntry},
        { .data = (uintptr_t) (numbers + 1), .fn = fiberEntry},
        { .data = (uintptr_t) (numbers + 2), .fn = fiberEntry},
        { .data = (uintptr_t) (numbers + 3), .fn = fiberEntry},
        { .data = (uintptr_t) (numbers + 4), .fn = fiberEntryMainThread, .threadIndex = 1},
    };
    ts_counter counter = ts_runjobs(jobs, 5);
    ts_waitForCounterAndFree(counter);
    ts_cleanup();
    return 0;
}