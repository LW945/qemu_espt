#ifndef QEMU_ESPT_INT_H
#define QEMU_ESPT_INT_H

#include "qemu/osdep.h"
#include "qemu/main-loop.h"
#include "cpu.h"
#include "exec/exec-all.h"
#include "exec/memory.h"
#include "exec/address-spaces.h"
#include "exec/cpu_ldst.h"
#include "exec/cputlb.h"
#include "exec/memory-internal.h"
#include "exec/ram_addr.h"
#include "qemu/queue.h"

#include <sys/ioctl.h>

#define ESPT_MEM_LOG_DIRTY_PAGES	(1UL << 0)
#define ESPT_MEM_READONLY	(1UL << 1)

#define ESPT_SET_ENTRY 0
#define ESPT_FLUSH_ENTRY 1

typedef struct ESPTMemorySlot{
	uint32_t flags;
	hwaddr guest_phys_addr;
	uint64_t memory_size; /* bytes */
	uint64_t userspace_addr; /* start of the userspace allocated memory */
	unsigned long *dirty_bitmap;
	QLIST_ENTRY(ESPTMemorySlot) link;
}ESPTMemorySlot;

typedef struct ESPTState{
	int fd;
	struct MemoryListener memory_listener;
	
	QLIST_HEAD(, ESPTMemorySlot) memory_slot;
	struct ESPTFlushEntryVec{
		target_ulong *addr_list;
		int capacity;
		int size;
	}espt_entry;
}ESPTState;

struct ESPTEntry{
	union{
		struct{
			target_ulong gva;
			uintptr_t hva;
			int pid;
		}set_entry;
		struct{
			target_ulong *list;
			int size;
			int pid;
		}flush_entry;
	};
};

struct HelperElem{
	CPUArchState *env;
	target_ulong addr;
	TCGMemOpIdx oi;
	uintptr_t retaddr;
	MemOp op;
	bool code_read;
	bool is_load;
	uint64_t write_val;
};

int espt_ioctl(int type, ...);

int espt_init(void);

int espt_entry_flush_all(void);

void sigsegv_handler(int sig);
#endif

