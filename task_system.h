#ifndef _TASK_SYSTEM_H_
#define _TASK_SYSTEM_H_
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define TS_API extern

typedef void (ts_fiberEntryFn) (uintptr_t data);
#define ts_fiberEntry(NAME) void NAME(uintptr_t data)

typedef void (ts_threadMainFn) (void* data, uint32_t threadIndex);
#define ts_threadEntry(NAME) void NAME(void* data, uint32_t threadIndex)

typedef void* (ts_alloc) (uint64_t size, void* ctx);
typedef void (ts_free) (void* ptr, void* ctx);

typedef struct ts_CustomThreadDesc { ts_threadMainFn* fn; void* customData; uint32_t stackSize; } ts_CustomThreadDesc;

/*
    The ts_Desc struct contains configuration values for the job system

    The default configuration is:


*/
typedef struct ts_Desc {
    uint32_t workerThreadCount;
    uint32_t jobCount;
    uint32_t fiberCount;
    uint64_t fiberStackSize;
    ts_CustomThreadDesc customThreads[12];
    ts_alloc* alloc;
    ts_free* free;
    void* allocCtx;
} ts_Desc;

/*
    ts_setup
*/
TS_API void ts_setup(ts_Desc desc);
TS_API void ts_cleanup(void);

typedef struct ts_Job {
    ts_fiberEntryFn* fn;
    uintptr_t data;
    uint32_t threadIndex;
} ts_Job;

typedef struct ts_counter {
    uint32_t id;
} ts_counter;

TS_API ts_counter ts_runjobs(ts_Job* jobs, uint32_t jobCount);
TS_API void ts_runJobsAndAutoFreeCounter(ts_Job* jobs, uint32_t jobCount);
TS_API void ts_waitForCounterAndFree(ts_counter counterId);

typedef struct ts__Context ts__Context;

/*
    ts_setContext

    Sets the context of the jobsystem
    usefull when using it with DLLs

*/
TS_API void ts_setContext(ts__Context* ctx);

/*
    ts_getContext

    returns the current internal context of the jobsystem
*/
TS_API ts__Context* ts_getContext(void);

/*
    ts_continueOnThread

    Puts the current fiber to sleep till it gets picked up by the suggsted thread.
    The fiber is now pinned to this thread.
    If the threadIndex matches the thread that currently runs it, it will just continue without any interruption.

    Special cases:

    threadIndex == 0
    In this case any thread can pickup this fiber and run it

    threadIndex == 1
    This is always the mainthread where ts_setup() was initially called
*/
TS_API void ts_continueOnThread(uint32_t threadIndex);

/*
    ts_shouldQuit

    Should be called by custom threads regularly to know when they should shutdown
*/
TS_API bool ts_shouldQuit(void);

/*
    ts_coreCount

    Returns the currents system cpu core count
*/
TS_API uint32_t ts_coreCount(void);

#ifdef __cplusplus
}
#endif

#ifdef TASK_SYSTEM_IMPL

#ifndef ts__setZero
#include <string.h>
#define ts__setZero(PTR, SIZE) memset((PTR), 0x0, (SIZE))
#endif // ts__setZero

#ifndef TS_ASSERT
#include <assert.h>
#define TS_ASSERT(A) assert(A)
#endif // TS_ASSERT

#define TS_UNUSED(V) (void)(V)

#define ts_null ((void*)0)
#define TS_INTERN static
typedef uint32_t ts_id;

/* threads */

#ifdef _MSC_VER
    #include <windows.h>
    #define sleepInMs(MS) Sleep(MS)
    typedef HANDLE threadHandle;

    #define ts__threadEntry(NAME) unsigned long WINAPI NAME(void* data)
    typedef DWORD (ts__threadMainFn) (void* data);

    threadHandle createThread(ts__threadMainFn* main, void* data, uint64_t stackSize) {
        threadHandle handle = CreateThread(ts_null, stackSize, c89thrd_start_win32, data, 0, ts_null);
        assert(handle != 0);
        return handle;
    } // if (WaitForSingleObject((HANDLE)thr, INFINITE) == WAIT_FAILED) {

    bool threadJoin(threadHandle handle) {
        return !WaitForSingleObject(handle, INFINITE) == WAIT_FAILED);
    }
#else
    #include <time.h>
    #define sleepInMs(MS) nanosleep(&(struct timespec) { (time_t) MS / 1000, (long) ((MS % 1000) * 1000000) }, &(struct timespec) {0})
    #include <pthread.h>
    #define ts__threadEntry(NAME) void* NAME(void* data)
    typedef void* (ts__threadMainFn) (void* data);
    typedef pthread_t threadHandle;

    threadHandle createThread(ts__threadMainFn* main, void* data, uint64_t stackSize) {
        threadHandle handle;
        
        pthread_attr_t attr;
        int r = pthread_attr_init(&attr);
        assert(r == 0 && "pthread_attr_init failed");
        r = pthread_attr_setstacksize(&attr, stackSize);
        assert(r == 0 && "pthread_attr_setstacksize failed");
        r = pthread_create(&handle, &attr, main, data);
        assert(r == 0 && "pthread_create failed");
        return handle;
    }

    bool threadJoin(threadHandle handle) {
        void* out = 0;
        return !pthread_join(handle, &out);
    }
#endif

/* atomic */

#ifdef _MSC_VER
    #include <intrin.h>
    typedef uint32_t volatile ts_a32;
    typedef uint64_t volatile ts_a64;
    #define ts__atomicCompareExchange64(DESTPTR, COMPERAND, EXCHANGE) _InterlockedCompareExchange64(DESTPTR, EXCHANGE, *(COMPERAND))
    #define ts__atomicCompareExchange32(DESTPTR, COMPERAND, EXCHANGE) _InterlockedCompareExchange32(DESTPTR, EXCHANGE, *(COMPERAND))
    #define ts__atomicLoad32Aq(VALPTR) InterlockedOr32(VALPTR, 0)
    #define ts__atomicLoad64Aq(VALPTR) InterlockedOr64(VALPTR, 0)
#else
    #include <stdatomic.h>
    typedef _Atomic(uint32_t) ts_a32;
    typedef _Atomic(uint64_t) ts_a64;
    #define ts__atomicCompareExchange64(DESTPTR, COMPERAND, EXCHANGE) atomic_compare_exchange_weak(DESTPTR, COMPERAND, EXCHANGE)
    #define ts__atomicCompareExchange32(DESTPTR, COMPERAND, EXCHANGE) ts__atomicCompareExchange64(DESTPTR, COMPERAND, EXCHANGE)
    #define ts__atomicLoad64Aq(VALPTR)  atomic_load_explicit(VALPTR, memory_order_acquire)
    #define ts__atomicLoad32Aq(VALPTR)  atomic_load_explicit(VALPTR, memory_order_acquire)
#endif

/* yield */

#if defined(__arm__) || defined(__arm64__)
void yieldCpu(void) {
#ifdef _MSC_VER
    __yield();
#else
    __asm__ __volatile__("yield");
#endif
}
#elif defined(__amd64__) || defined(__WIN64__)
#include <xmmintrin.h>
void yieldCpu(void) {
    _mm_pause();
}
#else
void yieldCpu(void) {
    sleepInMs(0);
}
#endif

/* core count */

#ifdef _MSC_VER
uint32_t ts_coreCount(void) {
    SYSTEM_INFO sysinfo;
    GetSystemInfo(&sysinfo);
    return sysinfo.dwNumberOfProcessors;
}
#elif defined(__APPLE__)
#include <sys/sysctl.h>
uint32_t ts_coreCount(void) {
    int ctlarg[2], ncpu;
    size_t len;

    ctlarg[0] = CTL_HW;
    ctlarg[1] = HW_NCPU;
    len = sizeof(ncpu);
    if (sysctl(ctlarg, 2, &ncpu, &len, 0, 0) == 0) {
		return (uint32_t) ncpu;
    }

    return 1;
}
#else
#include <sys/syscall.h>
uint32_t ts_coreCount(void) {
    return sysconf(_SC_NPROCESSORS_ONLN);
}
#endif

/* TLS */

typedef struct ts__tls { void* ptr; } ts__tls;
/* thread local storage */
#ifdef _MSC_VER
ts__tls ts__tlsCreate() {
    DWORD tls_id = TlsAlloc();
    sx_assertf(tls_id != TLS_OUT_OF_INDEXES, "Failed to create tls!");
    return (ts__tls) {(uintptr_t)tls_id};
}

void ts__tlsDestroy(ts__tls* tls) {
    TlsFree((DWORD)(uintptr_t)tls->ptr);
}

void ts__tlsSet(ts__tls* tls, void* data) {
    TlsSetValue((DWORD)(uintptr_t)tls->ptr, data);
}

void* ts__tlsGet(ts__tls* tls) {
    return TlsGetValue((DWORD)(uintptr_t)tls->ptr);
}
#else
ts__tls ts__tlsCreate() {
    pthread_key_t key;
    int r = pthread_key_create(&key, ts_null);
    TS_ASSERT(r == 0 && "pthread_key_create failed");
    return (ts__tls) {(void*)key};
}

void ts__tlsDestroy(ts__tls* tls) {
    pthread_key_t key = (pthread_key_t)(uintptr_t)tls->ptr;
    int r = pthread_key_delete(key);
    TS_ASSERT(r == 0 && "pthread_key_delete failed");
    tls->ptr = ts_null;
}

void ts__tlsSet(ts__tls* tls, void* data) {
    pthread_key_t key = (pthread_key_t)(uintptr_t)tls->ptr;
    int r = pthread_setspecific(key, data);
    TS_ASSERT(r == 0 && "pthread_setspcific failed");
}

void* ts__tlsGet(ts__tls* tls) {
    pthread_key_t key = (pthread_key_t)(uintptr_t)tls->ptr;
    return pthread_getspecific(key);
}
#endif

typedef struct ts__FiberContext ts__FiberContext;
// Coroutine body function type.
// 'value' will be the value passed to the initial call to ts__yield() that starts the coroutine.
typedef uintptr_t ts__fiberEntryFn(ts__FiberContext* coro, uintptr_t value);

// Initialize a coroutine into a memory buffer.
// If 'buffer' is NULL, it will malloc() one for you. You are responsible to call free(tina.buffer) when you are done with it.
// 'body' is the function that will run inside of the coroutine, and 'user_data' will be stored in tina.user_data.
// The initialized coroutine is not started. You must call ts__yield() to do that.
static ts__FiberContext* ts__initFiber(void* buffer, size_t size, ts__fiberEntryFn* entry);

// Yield execution into another coroutine, or yield back to the caller by yielding to itself (the tina value passed to the body function).
// NOTE: The implementation is not fully symmetric and for simplicity just swaps a continuation stored in the coroutine.
// In other words: Coroutines can yield to other coroutines, but don't yield to a coroutine that hasn't yielded back to it's caller yet.
// Treat them as non-reentrant or you'll get continuations and coroutines scrambled in a way that's probably more confusing than helpful.
static uintptr_t ts__yield(ts__FiberContext* coro, uintptr_t value);

#ifdef __EMSCRIPTEN__
#error "Emscipten support is not implemented yet"
#include <emscripten/fiber.h>

#else

/* TINA Fibers START */
typedef struct ts__FiberContext {
    ts_fiberEntryFn* fn;
	// User defined name. (optional)
	const char* name;
	// Pointer to the coroutine's memory buffer. (readonly)
	void* buffer;
	// Size of the buffer. (readonly)
	size_t size;
	// Has the coroutine's body function exited? (readonly)
	bool completed;
	
	// Private implementation details.
	void* _sp;
	uint32_t _magic;
} ts__FiberContext;


// Magic number to help assert for memory corruption errors.
#define TS_FIBER_MAGIC_NUMBER 0x54494E41ul

// Symbols for the assembly functions.
// These are either defined as inline assembly (GCC/Clang) of binary blobs (MSVC).
extern const uint64_t ts__swapFiber[];
extern const uint64_t ts__initFiberStack[];

ts__FiberContext* ts__initFiber(void* buffer, size_t size, ts__fiberEntryFn* entry) {
	TS_ASSERT(size >= 64*1024 && "Tina Warning: Small stacks tend to not work on modern OSes. (Feel free to disable this if you have your reasons)");
	//if(buffer == ts_null) buffer = malloc(size);
    TS_ASSERT(buffer);
    TS_ASSERT(size > 0);
    TS_ASSERT(entry);
	// TODO check alignment?
	ts__FiberContext* coro = (ts__FiberContext*)buffer;
	coro->completed = false;
	coro->buffer = buffer;
	coro->size = size;
	coro->_magic = TS_FIBER_MAGIC_NUMBER;

	typedef ts__FiberContext* init_func(ts__FiberContext* coro, ts__fiberEntryFn* entry, void** sp_loc, void* sp);
	init_func* init = ((init_func*)(void*)ts__initFiberStack);
	return init(coro, entry, &coro->_sp, (uint8_t*)buffer + size);
}

void ts__fiberContext(ts__FiberContext* coro, ts__fiberEntryFn* body) {
	// Yield back to the ts__initFiberStack() call, and return the coroutine.
	uintptr_t value = ts__yield(coro, (uintptr_t)coro);
	// Call the body function with the first value.
	value = body(coro, value);
	// body() has exited, and the coroutine is completed.
	coro->completed = true;
	// Yield the final return value back to the calling thread.
	ts__yield(coro, value);
	
	TS_ASSERT(false && "Tina Error: You cannot resume a coroutine after it has finished.");
}

uintptr_t ts__yield(ts__FiberContext* coro, uintptr_t value){
	TS_ASSERT(coro->_magic == TS_FIBER_MAGIC_NUMBER && "Tina Error: Coroutine has likely had a stack overflow. Bad magic number detected.");
	
	typedef uintptr_t swap_func(ts__FiberContext* coro, uintptr_t value, void** sp);
	swap_func* swap = ((swap_func*)(void*)ts__swapFiber);
	// TODO swap no longer needs the coro pointer.
	// Could save a couple instructions? Meh. Too much testing effort.
	return swap(ts_null, value, &coro->_sp);
}

#if __APPLE__
	#define TS_SYMBOL(sym) "_"#sym
#else
	#define TS_SYMBOL(sym) #sym
#endif
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wpedantic"
#if __ARM_EABI__ && __GNUC__
	// TODO: Is this an appropriate macro check for a 32 bit ARM ABI?
	// TODO: Only tested on RPi3.
	
	// Since the 32 bit ARM version is by far the shortest, I'll document this one.
	// The other variations are basically the same structurally.
	
	// ts__initFiberStack() sets up the stack and initial execution of the coroutine.
	asm("ts__initFiberStack:");
	// First things first, save the registers protected by the ABI
	asm("  push {r4-r11, lr}");
	asm("  vpush {q4-q7}");
	// Now store the stack pointer in the couroutine.
	// ts__fiberContext() will call ts__yield() to restore the stack and registers later.
	asm("  str sp, [r2]");
	// Align the stack top to 16 bytes as requested by the ABI and set it to the stack pointer.
	asm("  and r3, r3, #~0xF");
	asm("  mov sp, r3");
	// Finally, tail call into ts__fiberContext.
	// By setting the caller to null, debuggers will show ts__fiberContext() as a base stack frame.
	asm("  mov lr, #0");
	asm("  b ts__fiberContext");
	
	// https://static.docs.arm.com/ihi0042/g/aapcs32.pdf
	// ts__swapFiber() is responsible for swapping out the registers and stack pointer.
	asm("ts__swapFiber:");
	// Like above, save the ABI protected registers and save the stack pointer.
	asm("  push {r4-r11, lr}");
	asm("  vpush {q4-q7}");
	asm("  mov r3, sp");
	// Restore the stack pointer for the new coroutine.
	asm("  ldr sp, [r2]");
	// And save the previous stack pointer into the coroutine object.
	asm("  str r3, [r2]");
	// Restore the new coroutine's protected registers.
	asm("  vpop {q4-q7}");
	asm("  pop {r4-r11, lr}");
	// Move the 'value' parameter to the return value register.
	asm("  mov r0, r1");
	// And perform a normal return instruction.
	// This will return from ts__yield() in the new coroutine.
	asm("  bx lr");
#elif __amd64__ && (__unix__ || __APPLE__)
	#define ARG0 "rdi"
	#define ARG1 "rsi"
	#define ARG2 "rdx"
	#define ARG3 "rcx"
	#define RET "rax"
	
	asm(".intel_syntax noprefix");
	
	asm(TS_SYMBOL(ts__initFiberStack:));
	asm("  push rbp");
	asm("  push rbx");
	asm("  push r12");
	asm("  push r13");
	asm("  push r14");
	asm("  push r15");
	asm("  mov [" ARG2 "], rsp");
	asm("  and " ARG3 ", ~0xF");
	asm("  mov rsp, " ARG3);
	asm("  push 0");
	asm("  jmp " TS_SYMBOL(ts__fiberContext));
	
	// https://software.intel.com/sites/default/files/article/402129/mpx-linux64-abi.pdf
	asm(TS_SYMBOL(ts__swapFiber:));
	asm("  push rbp");
	asm("  push rbx");
	asm("  push r12");
	asm("  push r13");
	asm("  push r14");
	asm("  push r15");
	asm("  mov rax, rsp");
	asm("  mov rsp, [" ARG2 "]");
	asm("  mov [" ARG2 "], rax");
	asm("  pop r15");
	asm("  pop r14");
	asm("  pop r13");
	asm("  pop r12");
	asm("  pop rbx");
	asm("  pop rbp");
	asm("  mov " RET ", " ARG1);
	asm("  ret");
	
	asm(".att_syntax");
#elif __WIN64__ || defined(_WIN64)
	// MSVC doesn't allow inline assembly, assemble to binary blob then.
	
	#if __GNUC__
		#define TINA_SECTION_ATTRIBUTE __attribute__((section(".text#")))
	#elif _MSC_VER
		#pragma section("tina", execute)
		#define TINA_SECTION_ATTRIBUTE __declspec(allocate("tina"))
	#else
		#error Unknown/untested compiler for Win64. 
	#endif
	
	// Assembled and dumped from win64-init.S
	TINA_SECTION_ATTRIBUTE
	const uint64_t ts__initFiberStack[] = {
		0x5541544157565355, 0x2534ff6557415641,
		0x2534ff6500000008, 0x2534ff6500000010,
		0xa0ec814800001478, 0x9024b4290f000000,
		0x8024bc290f000000, 0x2444290f44000000,
		0x4460244c290f4470, 0x290f44502454290f,
		0x2464290f4440245c, 0x4420246c290f4430,
		0x290f44102474290f, 0xe18349208949243c,
		0x0c894865cc894cf0, 0x8948650000147825,
		0x4c6500000010250c, 0x6a00000008250c89,
		0xb8489020ec834800, (uint64_t)ts__fiberContext,
		0x909090909090e0ff, 0x9090909090909090,
	};

	// Assembled and dumped from win64-swap.S
	TINA_SECTION_ATTRIBUTE
	const uint64_t ts__swapFiber[] = {
		0x5541544157565355, 0x2534ff6557415641,
		0x2534ff6500000008, 0x2534ff6500000010,
		0xa0ec814800001478, 0x9024b4290f000000,
		0x8024bc290f000000, 0x2444290f44000000,
		0x4460244c290f4470, 0x290f44502454290f,
		0x2464290f4440245c, 0x4420246c290f4430,
		0x290f44102474290f, 0x208b49e08948243c,
		0x9024b4280f008949, 0x8024bc280f000000,
		0x2444280f44000000, 0x4460244c280f4470,
		0x280f44502454280f, 0x2464280f4440245c,
		0x4420246c280f4430, 0x280f44102474280f,
		0x0000a0c48148243c, 0x00147825048f6500,
		0x00001025048f6500, 0x00000825048f6500,
		0x415d415e415f4100, 0xd089485d5b5e5f5c,
		0x90909090909090c3, 0x9090909090909090,
	};
#elif __aarch64__ && __GNUC__
	asm(TS_SYMBOL(ts__initFiberStack:));
	asm("  sub sp, sp, 0xA0");
	asm("  stp x19, x20, [sp, 0x00]");
	asm("  stp x21, x22, [sp, 0x10]");
	asm("  stp x23, x24, [sp, 0x20]");
	asm("  stp x25, x26, [sp, 0x30]");
	asm("  stp x27, x28, [sp, 0x40]");
	asm("  stp x29, x30, [sp, 0x50]");
	asm("  stp d8 , d9 , [sp, 0x60]");
	asm("  stp d10, d11, [sp, 0x70]");
	asm("  stp d12, d13, [sp, 0x80]");
	asm("  stp d14, d15, [sp, 0x90]");
	asm("  mov x4, sp");
	asm("  str x4, [x2]");
	asm("  and x3, x3, #~0xF");
	asm("  mov sp, x3");
	asm("  mov lr, #0");
	asm("  b " TS_SYMBOL(ts__fiberContext));

	asm(TS_SYMBOL(ts__swapFiber:));
	asm("  sub sp, sp, 0xA0");
	asm("  stp x19, x20, [sp, 0x00]");
	asm("  stp x21, x22, [sp, 0x10]");
	asm("  stp x23, x24, [sp, 0x20]");
	asm("  stp x25, x26, [sp, 0x30]");
	asm("  stp x27, x28, [sp, 0x40]");
	asm("  stp x29, x30, [sp, 0x50]");
	asm("  stp d8 , d9 , [sp, 0x60]");
	asm("  stp d10, d11, [sp, 0x70]");
	asm("  stp d12, d13, [sp, 0x80]");
	asm("  stp d14, d15, [sp, 0x90]");
	asm("  mov x3, sp");
	asm("  ldr x4, [x2]");
	asm("  mov sp, x4");
	asm("  str x3, [x2]");
	asm("  ldp x19, x20, [sp, 0x00]");
	asm("  ldp x21, x22, [sp, 0x10]");
	asm("  ldp x23, x24, [sp, 0x20]");
	asm("  ldp x25, x26, [sp, 0x30]");
	asm("  ldp x27, x28, [sp, 0x40]");
	asm("  ldp x29, x30, [sp, 0x50]");
	asm("  ldp d8 , d9 , [sp, 0x60]");
	asm("  ldp d10, d11, [sp, 0x70]");
	asm("  ldp d12, d13, [sp, 0x80]");
	asm("  ldp d14, d15, [sp, 0x90]");
	asm("  add sp, sp, 0xA0");
	asm("  mov x0, x1");
	asm("  ret");
#endif
#pragma clang diagnostic pop
#endif
/* TINA Fibers END */


/* MPMC Queue */

typedef struct ts_IndexQueue {
    ts_a64 out;
    ts_a64 in;
    ts_a32* indicies;
    uint32_t size;
} ts_IndexQueue;

#define ts__queueRingEntry(queue, index) (queue->indicies + (index & (queue->size - 1)))
static ts_id ts__invalidIndex = 0xFFFFFFFF;

bool ts__queuePush(ts_IndexQueue* queue, uint32_t index) {
    assert(queue);
    assert(index <= (ts__invalidIndex - 1));
    index += 1;
    // 0 ist reseved to track fee entries so we increase indicies by one on add and decrease again it on pull
    uint64_t in;

    for (;;) {
        ts_a64 out = ts__atomicLoad64Aq(&queue->out);
        in = ts__atomicLoad64Aq(&queue->in);
        uint64_t inNext = in + 1;
        
        // we want to make sure that the queue is not full
        if (inNext == out) {
            assert(false && "Queue is full!");
            return false;
        }

        if (ts__atomicCompareExchange64(&queue->in, &in, inNext)) {
            break;
        }
    }
    ts_a32* task = ts__queueRingEntry(queue, in);

    uint32_t expected = 0;
    while (!ts__atomicCompareExchange32(task, &expected, index)) {
        // this entry still waits to get set to zero on the other end of the queue
        // wait till it is done
    }
    return true;
}

ts_id ts__queuePull(ts_IndexQueue* queue) {
    assert(queue);
    uint64_t out;
    for (;;) {
        // load in first
        ts_a64 in = ts__atomicLoad64Aq(&queue->in);
        out = ts__atomicLoad64Aq(&queue->out);
        uint64_t outNext = out + 1;
        if (in <= out) {
            // return invalid if there is no index
            return ts__invalidIndex;
        }
        if (ts__atomicCompareExchange64(&queue->out, &out, outNext)) {
            break;
        }
    }
    ts_a32* task = ts__queueRingEntry(queue, out);
    ts_id index;
    for (;;) {
        index = ts__atomicLoad32Aq(task);
        if (index == 0) {
            // When the programs starts to loop in this place forever another thread that is one or more "loops" ahead on the queues ring buffer
            // already took this entry
            // To avoid this from happening you should increase the queue size
            continue;
        }
        if (ts__atomicCompareExchange32(task, &index, 0)) {
            break;
        }
        // this queue entry is still beeing added so we wait till its done
        // this is a lock mechanic in this otherwise lockless implementation
    }
    return index - 1; // 0 - 1 == ts__invalidIndex (its a defined behaviour for unsigned ints)
}

/* Job Context */
typedef struct ts__Fiber {
    ts__FiberContext* fiberCtx;
    void* fiberBuffer;
    uint32_t counterIndex;
    uint32_t ownCounterIndex;
    uint32_t threadIndex;
} ts__Fiber;

typedef struct ts__ThreadData {
    ts_threadMainFn* customFn;
    void* customData;
    uint32_t threadIndex;
    ts__Fiber* fiber;
    bool isCustom;
} ts__ThreadData;

typedef struct ts__Count {
    ts_a32 count;
} ts__Count;

typedef struct ts__Job {
    ts_fiberEntryFn* entry;
    uintptr_t data;
    uint32_t dependentCounterIndex;
    uint32_t threadIndex;
} ts__Job;

typedef struct ts__Context {
    struct {
        uint64_t fiberStackSize;
    } config;

    struct {
        threadHandle* store;
        uint32_t count;
    } threadHandles;

    struct {
        ts__ThreadData* store;
        uint32_t count;
    } threadData;

    ts__tls threadLocalStorage;

    struct {
        ts__Job* store;
        uint32_t count;
    } jobs;

    struct {
        ts__Fiber* store;
        uint32_t count;
    } fibers;

    struct {
        ts__Count* store;
        uint32_t count;
    } counters;

    ts_IndexQueue freeCounter;
    ts_IndexQueue freeFibers;
    ts_IndexQueue freeJobs;
    ts_IndexQueue openJobs;
    ts_IndexQueue sleepingFibers;

    ts_alloc* alloc;
    ts_free* free;
    void* allocCtx;

    ts_a32 shouldQuit;
} ts__Context;
static ts__Context* ts__context;

uintptr_t ts__fiberEntry(ts__FiberContext* coro, uintptr_t value) {
    TS_ASSERT(coro);
    TS_ASSERT(coro->fn);
    coro->fn(value);
    return 0;
}

bool ts__runFiber(ts__ThreadData* threadData, uint32_t fiberIndex, ts__Fiber* fiber, uintptr_t userData) {
    TS_ASSERT(fiber);
    threadData->fiber = fiber;
    ts__yield(fiber->fiberCtx, userData);
    threadData->fiber = ts_null;
    if (fiber->fiberCtx->completed) {
        if (fiber->counterIndex != ts__invalidIndex) {
            ts__Count* counterObj = ts__context->counters.store + fiber->counterIndex;
            uint32_t count;
            for (;;) {
                count = ts__atomicLoad32Aq(&counterObj->count);

                if (ts__atomicCompareExchange32(&counterObj->count, &count, count - 1)) {
                    break;
                }
            }
            if (count == 0) {
                ts__queuePush(&ts__context->freeCounter, fiber->counterIndex);
            }
        }
        ts__queuePush(&ts__context->freeFibers, fiberIndex);
    } else {
        ts__queuePush(&ts__context->sleepingFibers, fiberIndex);
    }
    return true;
}

bool ts__executeNextJob(ts__ThreadData* threadData) {
    ts_id sleepingIndex = ts__queuePull(&ts__context->sleepingFibers);
    if (sleepingIndex != ts__invalidIndex) {
        ts__Fiber* fiber = ts__context->fibers.store + sleepingIndex;
        uint32_t count = 0;
        if (fiber->ownCounterIndex != ts__invalidIndex) {
            count = ts__atomicLoad32Aq(&ts__context->counters.store[fiber->ownCounterIndex].count);
        }
        if (count > 0 || (fiber->threadIndex != 0 && fiber->threadIndex != threadData->threadIndex)) {
            // this job has to run on another thread, put it back to the queue
            ts__queuePush(&ts__context->sleepingFibers, sleepingIndex);
            return true;
        }
        return ts__runFiber(threadData, sleepingIndex, fiber, 0);
    }
    ts_id newJobIndex = ts__queuePull(&ts__context->openJobs);
    if (newJobIndex == ts__invalidIndex) {
        // no jobs left
        return false;
    }
    // execute new job
    ts__Job* job = ts__context->jobs.store + newJobIndex;
    if (job->threadIndex != 0 && job->threadIndex != threadData->threadIndex) {
        // this job has to run on another thread, put it back to the queue
        ts__queuePush(&ts__context->openJobs, newJobIndex);
        return true;
    }
    uintptr_t userData = job->data;
    ts_fiberEntryFn* entryFn = job->entry;
    ts_id counter = job->dependentCounterIndex;
    ts__queuePush(&ts__context->freeJobs, newJobIndex);

    ts_id fiberIndex = ts__queuePull(&ts__context->freeFibers);
    TS_ASSERT(fiberIndex != ts__invalidIndex);
    ts__Fiber* fiber = ts__context->fibers.store + fiberIndex;
    fiber->ownCounterIndex = ts__invalidIndex;
    fiber->fiberCtx = ts__initFiber(fiber->fiberBuffer, ts__context->config.fiberStackSize, ts__fiberEntry);
    fiber->fiberCtx->fn = entryFn;
    fiber->counterIndex = counter;
    return ts__runFiber(threadData, fiberIndex, fiber, userData);
}

void ts__workerLoop(ts__ThreadData* threadData) {
    while (!ts_shouldQuit()) {
        if (!ts__executeNextJob(threadData)) {
            yieldCpu();
        }
    }
}

ts__threadEntry(ts__threadEntryPoint) {
    ts__ThreadData* threadData = data;
    ts__tlsSet(&ts__context->threadLocalStorage, threadData);
    if (!threadData->isCustom) {
        ts__workerLoop(threadData);
    } else {
        threadData->customFn(threadData->customData, threadData->threadIndex);
    }

    return 0;
}

ts_counter ts__runjobs(ts_Job* jobs, uint32_t jobCount, uint32_t counterCount) {
    TS_ASSERT(jobs);
    TS_ASSERT(jobCount);
    ts_counter counterId = {ts__queuePull(&ts__context->freeCounter)};
    TS_ASSERT(counterId.id != ts__invalidIndex);
    ts__context->counters.store[counterId.id].count = counterCount;
    for (uint32_t i = 0; i < jobCount; i++) {
        ts_id jobId = ts__queuePull(&ts__context->freeJobs);
        TS_ASSERT(jobId != ts__invalidIndex);
        ts__Job* job = ts__context->jobs.store + jobId;
        job->dependentCounterIndex = counterId.id;
        job->entry = jobs[i].fn;
        job->data = jobs[i].data;
        job->threadIndex = jobs[i].threadIndex;
        ts__queuePush(&ts__context->openJobs, jobId);
    }
    return counterId;
}
ts_counter ts_runjobs(ts_Job* jobs, uint32_t jobCount) {
    return ts__runjobs(jobs, jobCount, jobCount + 1);
}

void ts_runJobsAndAutoFreeCounter(ts_Job* jobs, uint32_t jobCount) {
    ts__runjobs(jobs, jobCount, jobCount);
}

void ts_waitForCounterAndFree(ts_counter counterId) {
    ts__Count* countObj = ts__context->counters.store + counterId.id;
    ts_a32 count = ts__atomicLoad32Aq(&countObj->count);
    if (count == 0) {
        return;
    }
    ts__ThreadData* threadData = ts__tlsGet(&ts__context->threadLocalStorage);
    TS_ASSERT(threadData && "Wait for counter can only called from ts worker or custom threads");
    if (threadData->fiber) {
        threadData->fiber->ownCounterIndex = counterId.id;
        ts__yield(threadData->fiber->fiberCtx, 0);
        return;
    }
    for(;;) {
        bool runJob = ts__executeNextJob(threadData);

        ts_a32 count = ts__atomicLoad32Aq(&countObj->count);
        if (count == 1) {
            ts__queuePush(&ts__context->freeCounter, counterId.id);
            break;
        }
        if (!runJob) {
            yieldCpu();
        }
    }
}

void ts_continueOnThread(uint32_t threadIndex) {
    TS_ASSERT(ts__context);
    ts__ThreadData* data = ts__tlsGet(&ts__context->threadLocalStorage);
    TS_ASSERT(data && "Running in a foren thread");
    TS_ASSERT(data->fiber && "ts_continueOnThread should be only called within a fiber");
    if (data->threadIndex == threadIndex) {
        // we are on the same thread so we just continue
        return;
    }
    data->fiber->threadIndex = threadIndex;
    ts__yield(data->fiber->fiberCtx, 0);
}

#include <stdlib.h>
static void* ts__alloc(uint64_t size, void* ctx) {
    TS_UNUSED(ctx);
    return malloc(size);
}

static void ts__free(void* ptr, void* ctx) {
    free(ptr);
    TS_UNUSED(ctx);
}

#define ts__setArrayZero(ARR, COUNT) ts__setZero(ARR, sizeof((ARR)[0]) * COUNT)
#define ts__nextPowerOfTwoU32(VAL) assert(VAL > 0); VAL--;  VAL |= VAL >> 1; VAL |= VAL >> 2; VAL |= VAL >> 4; VAL |= VAL >> 8; VAL |= VAL >> 16; VAL += 1
static void ts__initQueue(ts_IndexQueue* queue, uint32_t size, uint32_t endIndex, ts_alloc* alloc, void* allocCtx) {
    assert(alloc);
    ts__nextPowerOfTwoU32(size);
    queue->in = 0;
    queue->out = 0;
    queue->size = size;
    queue->indicies = alloc(size * sizeof(queue->indicies[0]), allocCtx);
    uint32_t idx = 0;
    for (; idx < endIndex; idx++) {
        queue->indicies[idx] = idx + 1;
    }
    queue->in = idx;
    uint32_t zeroSize = (queue->size - idx);
    ts__setArrayZero(queue->indicies + idx, zeroSize);
}

#define ts_countOf(ARR) (sizeof(desc.customThreads) / sizeof(desc.customThreads[0]))
#define ts__allocArray(CTX, ARR, COUNT) ARR.store = CTX->alloc(sizeof(ARR.store[0]) * (COUNT), CTX->allocCtx); ARR.count = (COUNT)
#define ts__allocArrayZero(CTX, ARR, COUNT) ts__allocArray(CTX, ARR, (COUNT)); ts__setZero(ARR.store, sizeof(ARR.store[0]) * (COUNT))
#define ts__allocIndexQueue(CTX, QUEUE, SIZE) QUEUE.indicies = CTX->alloc(sizeof(QUEUE.indicies[0]) * (SIZE), CTX->allocCtx); \
        ts__setZero(QUEUE.indicies, sizeof(QUEUE.indicies[0]) * (SIZE)); QUEUE.size = (SIZE)
void ts_setup(ts_Desc desc) {
    if (!desc.alloc || !desc.free) {
        desc.alloc = ts__alloc;
        desc.free = ts__free;
        desc.allocCtx = ts_null;
    }
    ts__context = desc.alloc(sizeof(ts__Context), desc.allocCtx);
    ts__setZero(ts__context, sizeof(ts__Context));
    ts__context->alloc = desc.alloc;
    ts__context->free = desc.free;
    ts__context->allocCtx = desc.allocCtx;

    ts__context->threadLocalStorage = ts__tlsCreate();

    uint32_t customThreadCount = 0;
    while (desc.customThreads[customThreadCount].fn != ts_null && ts_countOf(desc.customThreads) > customThreadCount) customThreadCount += 1;
    
    uint32_t threadWorkersTotal = (desc.workerThreadCount == 0 ? (ts_coreCount() - 1) : desc.workerThreadCount);

    uint32_t threadsTotal = threadWorkersTotal + customThreadCount;
    ts__allocArray(ts__context, ts__context->threadData, threadsTotal + 1);
    ts__allocArray(ts__context, ts__context->threadHandles, threadsTotal);

    uint32_t jobsTotal = desc.jobCount == 0 ? 1000 : desc.jobCount;
    ts__allocArray(ts__context, ts__context->jobs, jobsTotal);

    uint32_t fibersTotal = desc.fiberCount == 0 ? (jobsTotal / 3) : desc.fiberCount;
    ts__allocArray(ts__context, ts__context->fibers, fibersTotal);

    ts__context->config.fiberStackSize = desc.fiberStackSize > 0 ? desc.fiberStackSize : (1024 * 1024);

    for (uint32_t idx = 0; idx < ts__context->fibers.count; idx++) {
        // init fiber
        ts__Fiber* fiber = ts__context->fibers.store + idx;
        fiber->counterIndex = ts__invalidIndex;
        // TODO: optionally for debugging virtual alloc memory and catch stack overflows with a protected page at the end
        fiber->fiberBuffer = malloc(ts__context->config.fiberStackSize);
    }

    uint32_t countersTotal = jobsTotal;
    ts__allocArrayZero(ts__context, ts__context->counters, countersTotal);
    ts__initQueue(&ts__context->freeCounter,    countersTotal * 2, countersTotal, ts__context->alloc, ts__context->allocCtx);
    ts__initQueue(&ts__context->freeFibers,     fibersTotal   * 2, fibersTotal,   ts__context->alloc, ts__context->allocCtx);
    ts__initQueue(&ts__context->freeJobs,       jobsTotal     * 2, jobsTotal,     ts__context->alloc, ts__context->allocCtx);
    ts__initQueue(&ts__context->openJobs,       jobsTotal     * 2, 0,             ts__context->alloc, ts__context->allocCtx);
    ts__initQueue(&ts__context->sleepingFibers, fibersTotal   * 2, 0,             ts__context->alloc, ts__context->allocCtx);

    uint32_t threadIdx = 0;

    ts__ThreadData* mainThreadData = ts__context->threadData.store;
    ts__setZero(mainThreadData, sizeof(ts__ThreadData) * ts__context->threadData.count);
    mainThreadData->threadIndex = 1;
    ts__tlsSet(&ts__context->threadLocalStorage, mainThreadData);

    // init workers
    for (; threadIdx < threadWorkersTotal; threadIdx++) {
        ts__ThreadData* data = ts__context->threadData.store + (threadIdx + 1);
        data->isCustom = false;
        data->threadIndex = (threadIdx + 2);
        ts__context->threadHandles.store[threadIdx] = createThread(ts__threadEntryPoint, data, 1024 * 1024);
    }
    for (; threadIdx < threadsTotal; threadIdx++) {
        ts_CustomThreadDesc* threadDesc = desc.customThreads + (threadIdx - threadWorkersTotal);
        ts__ThreadData* data = ts__context->threadData.store + (threadIdx + 1);
        data->customFn = threadDesc->fn;
        data->customData = threadDesc->customData;
        data->isCustom = true;
        data->threadIndex = (threadIdx + 2);
        ts__context->threadHandles.store[threadIdx] = createThread(ts__threadEntryPoint, &data, threadDesc->stackSize == 0 ? 1024 * 1024 : threadDesc->stackSize);
    }
}

void ts_cleanup(void) {
    assert(ts__context);
    uint32_t desiredQuitVal = 0;
    if (!ts__atomicCompareExchange32(&ts__context->shouldQuit, &desiredQuitVal, 1)) {
        assert(false && "quitting already done before");
        return;
    }

    for (uint32_t threadIdx = 0; threadIdx < ts__context->threadHandles.count; threadIdx++) {
        threadJoin(ts__context->threadHandles.store[threadIdx]);
    }
    ts__tlsDestroy(&ts__context->threadLocalStorage);
    ts__context->free(ts__context->freeCounter.indicies, ts__context->allocCtx);
    ts__context->free(ts__context->freeFibers.indicies, ts__context->allocCtx);
    ts__context->free(ts__context->freeJobs.indicies, ts__context->allocCtx);
    ts__context->free(ts__context->openJobs.indicies, ts__context->allocCtx);
    ts__context->free(ts__context->sleepingFibers.indicies, ts__context->allocCtx);

    ts__context->free(ts__context->threadData.store, ts__context->allocCtx);
    ts__context->free(ts__context->threadHandles.store, ts__context->allocCtx);
    ts__context->free(ts__context->jobs.store, ts__context->allocCtx);
    ts__context->free(ts__context->fibers.store, ts__context->allocCtx);

    ts__context->free(ts__context, ts__context->allocCtx);

    ts__context = ts_null;
}


void ts_setContext(ts__Context* ctx) {
    assert(!ts__context);
    ts__context = ctx;
}
ts__Context* ts_getContext(void) {
    assert(ts__context);
    return ts__context;
}

bool ts_shouldQuit(void) {
    return ts__atomicLoad32Aq(&ts__context->shouldQuit) != 0;
}

#endif // TASK_SYSTEM_IMPL
#endif // _TASK_SYSTEM_H_