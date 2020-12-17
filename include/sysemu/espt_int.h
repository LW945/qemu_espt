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
#include "exec/tb-hash.h"
#include "translate-all.h"
#include "qemu/bitmap.h"
#include "qemu/error-report.h"
#include "qemu/qemu-print.h"
#include "qemu/timer.h"
#include "exec/log.h"
#include "sysemu/cpus.h"
#include "sysemu/tcg.h"

#include <sys/ioctl.h>

#define ESPTIO 0xAF

#define ESPT_INIT _IOR(ESPTIO, 0x1, int)
#define ESPT_SET_ENTRY _IOR(ESPTIO, 0x2, struct ESPTEntry)
#define ESPT_FLUSH_ENTRY _IOR(ESPTIO, 0x3, struct ESPTEntry)
#define ESPT_MMIO_ENTRY _IOR(ESPTIO, 0x4, struct ESPTEntry)
#define ESPT_PRINT_ENTRY _IOR(ESPTIO, 0x5, struct ESPTEntry)

typedef struct ESPTMemorySlot{
	hwaddr guest_phys_addr;
	uint64_t memory_size; /* bytes */
	uint64_t userspace_addr; /* start of the userspace allocated memory */
	QLIST_ENTRY(ESPTMemorySlot) link;
}ESPTMemorySlot;

typedef struct ESPTState{
	int fd;
	int pid;
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
		}set_entry;
		struct{
			target_ulong *list;
			int size;
		}flush_entry;
		struct{
			target_ulong gva;
			uint64_t val;
			int add;
		}mmio_entry;
		struct{
			target_ulong gva;
		}print_entry;
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

int espt_entry_flush_addr(target_ulong addr);

int espt_entry_flush_all(void);

void espt_print_all_slot(void);

void espt_entry_list_insert(target_ulong elem);

bool espt_find_gpa_in_slot(hwaddr gpa);

bool handle_espt_page_fault(CPUState *cs, vaddr addr, int size,
                      MMUAccessType access_type, int mmu_idx,
                      uintptr_t retaddr, hwaddr *paddr, hwaddr *iotlb, uintptr_t *addend);
#endif

