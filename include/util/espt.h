#ifndef UTIL_ESPT_H
#define UTIL_ESPT_H
#include "exec/cpu-defs.h"
#include "exec/memop.h"
#include "cpu.h"
#include "tcg.h"

#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <string.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>

#define NETLINK_TEST    30
#define MSG_LEN            125
#define MAX_PLOAD        125

#define MY_TLB_INVALID_MASK    (1 << 0)
/* Set if TLB entry references a clean RAM page.  The iotlb entry will
   contain the page physical address.  */
#define MY_TLB_NOTDIRTY        (1 << 1)
/* Set if TLB entry is an IO callback.  */
#define MY_TLB_MMIO            (1 << 2)
/* Set if TLB entry contains a watchpoint.  */
#define MY_TLB_WATCHPOINT      (1 << 3)
/* Set if TLB entry requires byte swap.  */
#define MY_TLB_BSWAP           (1 << 4)
/* Set if TLB entry writes ignored.  */
#define MY_TLB_DISCARD_WRITE   (1 << 5)

struct PagetableListener{
	target_ulong addr;
	QSLIST_ENTRY(PagetableListener) entry;
};

struct GvaUpdatedList{
	unsigned long addr;
	QLIST_ENTRY(GvaUpdatedList) entry;
};

struct MyElemPack{
	CPUArchState *env;
	target_ulong addr;
	TCGMemOpIdx oi;
	uintptr_t retaddr;
	MemOp op;
	bool code_read;
};

struct MyNetlinkPack{
	int type;
	int pid;
	int gva_list_len;
	unsigned long gva;	
	unsigned long hva;
	unsigned long *gva_list;
};

typedef QLIST_HEAD(, PagetableListener) PagetableListenerHead;
typedef QLIST_HEAD(, GvaUpdatedList) GvaUpdatedListHead;

void my_load_helper_handler(int sig, siginfo_t *info, void *ucontext);
void my_store_helper_handler(int sig, siginfo_t *info, void *ucontext);
void netlink_init(int *skfd, struct sockaddr_nl *saddr, struct sockaddr_nl *daddr);
void netlink_send(int skfd, struct sockaddr_nl saddr, struct sockaddr_nl daddr, struct MyNetlinkPack msg);
void netlink_recv(int skfd, struct sockaddr_nl daddr, struct nlmsghdr *nlh_rev);

/*bool * get_is_gva_updated(void); //bool is_gva_updated
GvaUpdatedListHead * get_gva_updated_list(void); //GvaUpdatedListHead *gva_updated_list
int * get_len_gva_list(void);	//int len_gva_list*/

void my_espt_update(unsigned long * list);

#endif
